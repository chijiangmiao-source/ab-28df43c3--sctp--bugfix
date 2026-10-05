// Package audit 实现星载控制中继弱链路控制消息的逐包裁决引擎:
// 单关联、单个有序流, 仅审查 DATA 与 FORWARD-TSN, 依据 TSN 与 B/E 标志
// 维护累计 TSN、缓存分片、跳过范围与已交付消息, 并对每个包给出冻结裁决。
//
// 一个 SCTP 数据报可在同一公共头后携带多个块(弱链路捕获常把同一关联、同一
// 有序流的连续 DATA, 或 DATA 后紧随的 FORWARD-TSN 装入一个数据报)。裁决以
// 原始数据报为单位: 数据报内的全部允许块按线序在同一个裁决中审查; 任一块
// 违规则整个数据报冻结拒绝, 首块已产生的关联、缓存与累计 TSN 一律不落库。
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"sctpaudit/sctp"
)

// 裁决结论。
const (
	DecisionAccepted  = "accepted"  // FORWARD-TSN 已应用
	DecisionBuffered  = "buffered"  // DATA 分片已缓存, 等待补齐
	DecisionDelivered = "delivered" // DATA 使完整消息交付
	DecisionDuplicate = "duplicate" // 字节完全相同的重传, 状态不变
	DecisionStale     = "stale"     // 已被累计确认或跨越的旧片, 状态不变
	DecisionRejected  = "rejected"  // 冻结拒绝, 状态不变
)

// 数据报内单个块的处理结果(用于在整包裁决中展示逐块线序)。
const (
	outcomeDelivered = "delivered"
	outcomeBuffered  = "buffered"
	outcomeStale     = "stale"
	outcomeDuplicate = "duplicate"
	outcomeAccepted  = "accepted"
)

// Range 是一个闭区间 TSN 范围。
type Range struct {
	Start uint32 `json:"start"`
	End   uint32 `json:"end"`
}

// Frag 是缓存中的一个 DATA 分片。
type Frag struct {
	TSN  uint32 `json:"tsn"`
	SSN  uint16 `json:"ssn"`
	B    bool   `json:"b"`
	E    bool   `json:"e"`
	Data []byte `json:"data"`
}

// SeenRec 记录某个 TSN 首次观测到的指纹, 用于检测同 TSN 不同字节的冲突。
type SeenRec struct {
	SHA256   string `json:"sha256"`
	FirstHex string `json:"firstHex"` // 首个原始字节(用户数据前 16 字节)的十六进制依据
	Index    int    `json:"index"`
}

// Message 是一条已交付的完整消息。
type Message struct {
	Seq    int      `json:"seq"`
	Stream uint16   `json:"stream"`
	SSN    uint16   `json:"ssn"`
	TSNs   []uint32 `json:"tsns"`
	Length int      `json:"length"`
	Hex    string   `json:"hex"`
}

// Evidence 是冻结拒绝时稳定展示的首个原始字节依据。
type Evidence struct {
	TSN              uint32 `json:"tsn"`
	FirstIndex       int    `json:"firstIndex"`
	FirstSHA256      string `json:"firstSha256"`
	FirstBytesHex    string `json:"firstBytesHex"`
	ConflictBytesHex string `json:"conflictBytesHex"`
}

// ChunkInfo 是一个原始数据报裁决中单个块的线序审查记录。
type ChunkInfo struct {
	Ordinal int     `json:"ordinal"`       // 块在数据报内的线序号(从 0 起)
	Type    string  `json:"type"`          // DATA / FORWARD-TSN
	Outcome string  `json:"outcome"`       // delivered/buffered/stale/duplicate/accepted
	TSN     *uint32 `json:"tsn,omitempty"` // DATA 块的 TSN
	SSN     *uint16 `json:"ssn,omitempty"` // DATA 块的流序
	Reason  string  `json:"reason,omitempty"`
}

// Verdict 是单个原始数据报的冻结裁决, 一旦记录不可更改。
type Verdict struct {
	Index         int         `json:"index"`
	SHA256        string      `json:"sha256"`
	Type          string      `json:"type"` // DATA / FORWARD-TSN / DATA+FORWARD-TSN / INVALID
	Decision      string      `json:"decision"`
	Reason        string      `json:"reason,omitempty"`
	TSN           *uint32     `json:"tsn,omitempty"` // 仅单块 DATA 数据报填充
	SSN           *uint16     `json:"ssn,omitempty"`
	CumTSN        uint32      `json:"cumTSN"` // 处理后的累计 TSN
	Chunks        []ChunkInfo `json:"chunks,omitempty"`
	BufferAdded   []uint32    `json:"bufferAdded,omitempty"`
	BufferRemoved []uint32    `json:"bufferRemoved,omitempty"`
	SkippedAdded  []Range     `json:"skippedAdded,omitempty"`
	Delivered     []Message   `json:"delivered,omitempty"`
	Abandoned     []uint16    `json:"abandonedSSN,omitempty"`
	Evidence      *Evidence   `json:"evidence,omitempty"`
}

// Session 是一个审计标识下的全部冻结状态。
type Session struct {
	ID          string             `json:"id"`
	Raw         [][]byte           `json:"raw"`
	Verdicts    []Verdict          `json:"verdicts"`
	Initialized bool               `json:"initialized"`
	SrcPort     uint16             `json:"srcPort"`
	DstPort     uint16             `json:"dstPort"`
	VerTag      uint32             `json:"verTag"`
	Stream      uint16             `json:"stream"`
	CumTSN      uint32             `json:"cumTSN"`
	MaxTSN      uint32             `json:"maxTSN"`
	ExpectedSSN uint16             `json:"expectedSSN"`
	Buffered    map[uint32]*Frag   `json:"buffered"`
	Skipped     []Range            `json:"skipped"`
	Seen        map[uint32]SeenRec `json:"seen"`
	Messages    []Message          `json:"messages"`
}

// NewSession 创建空会话。
func NewSession(id string) *Session {
	return &Session{
		ID:       id,
		Buffered: map[uint32]*Frag{},
		Seen:     map[uint32]SeenRec{},
	}
}

// snapshot 复制全部可变裁决状态, 供整包事务在副本上试执行。
func (s *Session) snapshot() *Session {
	c := *s
	c.Raw = nil
	c.Verdicts = nil
	c.Buffered = make(map[uint32]*Frag, len(s.Buffered))
	for t, f := range s.Buffered {
		fc := *f
		fc.Data = append([]byte(nil), f.Data...)
		c.Buffered[t] = &fc
	}
	c.Skipped = append([]Range(nil), s.Skipped...)
	c.Seen = make(map[uint32]SeenRec, len(s.Seen))
	for t, rec := range s.Seen {
		c.Seen[t] = rec
	}
	c.Messages = make([]Message, len(s.Messages))
	for i, m := range s.Messages {
		c.Messages[i] = m
		c.Messages[i].TSNs = append([]uint32(nil), m.TSNs...)
	}
	return &c
}

// commit 把整包事务在副本上产生的状态写回本会话(裁决记录除外)。
func (s *Session) commit(c *Session) {
	s.Initialized = c.Initialized
	s.SrcPort = c.SrcPort
	s.DstPort = c.DstPort
	s.VerTag = c.VerTag
	s.Stream = c.Stream
	s.CumTSN = c.CumTSN
	s.MaxTSN = c.MaxTSN
	s.ExpectedSSN = c.ExpectedSSN
	s.Buffered = c.Buffered
	s.Skipped = c.Skipped
	s.Seen = c.Seen
	s.Messages = c.Messages
}

func shaOf(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func firstHex(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return hex.EncodeToString(b)
}

// Apply 裁决一个原始数据报, 追加一条冻结裁决。拒绝的数据报不改变任何状态。
func (s *Session) Apply(raw []byte) Verdict {
	v := s.adjudicate(raw)
	s.Verdicts = append(s.Verdicts, v)
	s.Raw = append(s.Raw, raw)
	return v
}

func (s *Session) adjudicate(raw []byte) Verdict {
	v := Verdict{Index: len(s.Verdicts), SHA256: shaOf(raw)}
	p, err := sctp.Parse(raw)
	if err != nil {
		v.Type = "INVALID"
		v.Decision = DecisionRejected
		v.Reason = err.Error()
		v.CumTSN = s.CumTSN
		return v
	}
	// 包级重传检测: 与任一已冻结包字节完全相同 → 重传, 状态不变。
	// 覆盖 DATA 重传、复合数据报整包重传与 FORWARD-TSN 重传
	// (否则后者会被误判为累计 TSN 回退)。
	for _, pv := range s.Verdicts {
		if pv.SHA256 == v.SHA256 {
			v.Decision = DecisionDuplicate
			v.Type = packetType(p.Chunks)
			v.Chunks = duplicateChunkList(p.Chunks)
			v.Reason = fmt.Sprintf("与第 %d 包字节完全相同的整包重传, 状态不变, 不增加消息数", pv.Index)
			v.CumTSN = s.CumTSN
			return v
		}
	}

	// 整包事务: 在快照上按线序试执行全部块。任一块违规即丢弃快照,
	// 首块在副本上建立的关联、缓存与累计 TSN 都不会落到本会话。
	work := s.snapshot()
	hasForward := false
	dataOutcomes := []string{}
	var reasons []string
	rejected := false
loop:
	for i, ch := range p.Chunks {
		switch {
		case ch.Data != nil:
			d := ch.Data
			out, note, ok := work.applyData(p, d, i, &v)
			if !ok {
				rejected = true
				break loop
			}
			dataOutcomes = append(dataOutcomes, out)
			v.Chunks = append(v.Chunks, ChunkInfo{
				Ordinal: i, Type: "DATA", Outcome: out,
				TSN: &d.TSN, SSN: &d.SSN, Reason: note,
			})
			if note != "" {
				reasons = append(reasons, fmt.Sprintf("块 %d(DATA TSN %d): %s", i, d.TSN, note))
			}
		case ch.Forward != nil:
			f := ch.Forward
			if !work.applyForward(p, f, i, &v) {
				rejected = true
				break loop
			}
			hasForward = true
			v.Chunks = append(v.Chunks, ChunkInfo{Ordinal: i, Type: "FORWARD-TSN", Outcome: outcomeAccepted})
		}
	}
	if rejected {
		// 整包回滚: 丢弃副本, 并清空裁决中在试执行期间累积的动态字段,
		// 使被拒裁决不显示任何未真正生效的缓存/跳过/交付; reason/evidence 保留。
		v.Chunks = nil
		v.BufferAdded = nil
		v.BufferRemoved = nil
		v.SkippedAdded = nil
		v.Delivered = nil
		v.Abandoned = nil
		v.TSN = nil
		v.SSN = nil
		v.Type = packetType(p.Chunks)
		v.CumTSN = s.CumTSN
		return v
	}

	// 全部块通过: 提交事务并汇总裁决。
	s.commit(work)
	v.Type = packetType(p.Chunks)
	v.CumTSN = s.CumTSN
	v.Decision = aggregateDecision(hasForward, dataOutcomes, &v)
	if len(p.Chunks) == 1 && p.Chunks[0].Data != nil {
		// 单块 DATA 数据报保留顶层 TSN/流序字段, 与历史视图和操作页兼容。
		tsn := p.Chunks[0].Data.TSN
		ssn := p.Chunks[0].Data.SSN
		v.TSN = &tsn
		v.SSN = &ssn
	}
	if v.Reason == "" {
		v.Reason = defaultReason(v.Decision, len(p.Chunks), reasons)
	}
	return v
}

// aggregateDecision 汇总数据报内所有块的结果, 得出整个原始包裁决。
// 含 FORWARD-TSN 的数据报(无论是否同时携带 DATA、是否顺带解锁交付)顶层裁决
// 恒为 accepted, 交付与跳过细节仍在裁决字段中展示; 纯 DATA 数据报按交付/缓存/
// 重传/旧片归类。
func aggregateDecision(hasForward bool, dataOutcomes []string, v *Verdict) string {
	if hasForward {
		return DecisionAccepted
	}
	if len(v.Delivered) > 0 {
		return DecisionDelivered
	}
	if len(dataOutcomes) > 0 {
		allDup, allIgnored := true, true
		for _, o := range dataOutcomes {
			if o != outcomeDuplicate {
				allDup = false
			}
			if o != outcomeDuplicate && o != outcomeStale {
				allIgnored = false
			}
		}
		if allDup {
			return DecisionDuplicate
		}
		if allIgnored {
			return DecisionStale
		}
	}
	return DecisionBuffered
}

func defaultReason(decision string, nChunks int, reasons []string) string {
	head := ""
	switch decision {
	case DecisionDelivered:
		head = fmt.Sprintf("数据报内 %d 个块按线序审查, 完整消息交付一次", nChunks)
	case DecisionAccepted:
		head = fmt.Sprintf("数据报内 %d 个块按线序审查, FORWARD-TSN 已应用", nChunks)
	case DecisionBuffered:
		head = fmt.Sprintf("数据报内 %d 个块按线序审查, 分片已缓存等待补齐", nChunks)
	case DecisionStale:
		head = fmt.Sprintf("数据报内 %d 个块均为已跨越旧片, 结论不变", nChunks)
	case DecisionDuplicate:
		head = fmt.Sprintf("数据报内 %d 个块均为重传, 不增加消息数", nChunks)
	}
	if len(reasons) > 0 {
		return head + "; " + strings.Join(reasons, "; ")
	}
	return head
}

func packetType(chunks []sctp.Chunk) string {
	seen := map[string]bool{}
	var order []string
	for _, ch := range chunks {
		name := ""
		switch {
		case ch.Data != nil:
			name = "DATA"
		case ch.Forward != nil:
			name = "FORWARD-TSN"
		}
		if name != "" && !seen[name] {
			seen[name] = true
			order = append(order, name)
		}
	}
	return strings.Join(order, "+")
}

func duplicateChunkList(chunks []sctp.Chunk) []ChunkInfo {
	var out []ChunkInfo
	for i, ch := range chunks {
		switch {
		case ch.Data != nil:
			tsn, ssn := ch.Data.TSN, ch.Data.SSN
			out = append(out, ChunkInfo{Ordinal: i, Type: "DATA", Outcome: outcomeDuplicate, TSN: &tsn, SSN: &ssn})
		case ch.Forward != nil:
			out = append(out, ChunkInfo{Ordinal: i, Type: "FORWARD-TSN", Outcome: outcomeDuplicate})
		}
	}
	return out
}

// applyData 在事务副本上处理一个 DATA 块, 返回 (逐块结果, 逐块说明, 是否通过)。
// ok=false 表示该块使整个数据报冻结拒绝(原因/依据已写入 v)。
func (s *Session) applyData(p *sctp.Packet, d *sctp.DataChunk, ordinal int, v *Verdict) (outcome, note string, ok bool) {
	reject := func(reason string) {
		v.Decision = DecisionRejected
		v.Reason = fmt.Sprintf("数据报内第 %d 块(DATA TSN %d)违规, 整包冻结拒绝: %s", ordinal, d.TSN, reason)
	}
	if s.Initialized {
		if p.SrcPort != s.SrcPort || p.DstPort != s.DstPort || p.VerTag != s.VerTag {
			reject(fmt.Sprintf("关联不匹配: 期望端口 %d→%d 验证标记 %08x", s.SrcPort, s.DstPort, s.VerTag))
			return "", "", false
		}
		if d.Stream != s.Stream {
			reject(fmt.Sprintf("非法流序: 流 %d 不属于受审有序流 %d", d.Stream, s.Stream))
			return "", "", false
		}
	}
	if d.U {
		reject("非法流序: 无序(U)DATA 不在单有序流审查范围")
		return "", "", false
	}
	if !s.Initialized && d.TSN == 0 {
		reject("首包 TSN 为 0, 无法建立审计基线")
		return "", "", false
	}
	// 同 TSN 指纹检查: 字节完全相同为重传, 不同则整包冻结拒绝并给出首个原始字节依据。
	if rec, exists := s.Seen[d.TSN]; exists {
		if rec.SHA256 != v.SHA256 {
			v.Decision = DecisionRejected
			v.Reason = fmt.Sprintf("数据报内第 %d 块 TSN %d 冲突: 与第 %d 包首次记录的字节不同, 整包冻结拒绝",
				ordinal, d.TSN, rec.Index)
			v.Evidence = &Evidence{
				TSN:              d.TSN,
				FirstIndex:       rec.Index,
				FirstSHA256:      rec.SHA256,
				FirstBytesHex:    rec.FirstHex,
				ConflictBytesHex: firstHex(d.Data, 16),
			}
			return "", "", false
		}
		return outcomeDuplicate, fmt.Sprintf("TSN %d 字节完全相同的重传, 不增加消息数", d.TSN), true
	}
	// 首次观测该 TSN: 记录指纹(含首个原始字节依据)。
	s.Seen[d.TSN] = SeenRec{SHA256: v.SHA256, FirstHex: firstHex(d.Data, 16), Index: v.Index}
	if !s.Initialized {
		s.Initialized = true
		s.SrcPort, s.DstPort, s.VerTag = p.SrcPort, p.DstPort, p.VerTag
		s.Stream = d.Stream
		s.CumTSN = d.TSN - 1
		s.ExpectedSSN = d.SSN
	}
	if d.TSN > s.MaxTSN {
		s.MaxTSN = d.TSN
	}
	// 旧片: 仅当被合法 FORWARD-TSN 跨越时才判旧。累计 TSN 只会越过已接收或已跳过的
	// TSN, 因此未见过且未被跳过的 TSN 一律进入缓存(乱序先到的捕获由此可互补交付)。
	if s.inSkipped(d.TSN) {
		return outcomeStale, fmt.Sprintf("TSN %d 已被 FORWARD-TSN 跨越, 补交旧片不改变结论", d.TSN), true
	}
	if d.SSN < s.ExpectedSSN {
		return outcomeStale, fmt.Sprintf("流序 %d 已过(当前期望 %d), 不再交付", d.SSN, s.ExpectedSSN), true
	}
	// 分片流序合法性(重复首/尾片、首尾倒置、跨消息交错)。
	if reason := s.checkFragmentOrder(d); reason != "" {
		reject(reason)
		return "", "", false
	}
	// 进入分片缓存。
	s.Buffered[d.TSN] = &Frag{TSN: d.TSN, SSN: d.SSN, B: d.B, E: d.E, Data: append([]byte(nil), d.Data...)}
	v.BufferAdded = append(v.BufferAdded, d.TSN)
	// 推进累计 TSN(吸收连续已缓存的 TSN)。
	for {
		if _, ok := s.Buffered[s.CumTSN+1]; ok {
			s.CumTSN++
		} else {
			break
		}
	}
	// 若该消息的分片区间被跳过范围跨越, 则消息作废, 不交付残缺消息。
	if removed, abandoned := s.checkDead(d.SSN); len(removed) > 0 {
		v.BufferRemoved = append(v.BufferRemoved, removed...)
		v.Abandoned = append(v.Abandoned, abandoned...)
		return outcomeBuffered, fmt.Sprintf("流序 %d 的分片区间被跳过范围跨越, 残缺消息作废不交付", d.SSN), true
	}
	delivered, removed := s.tryDeliver()
	v.BufferRemoved = append(v.BufferRemoved, removed...)
	v.Delivered = append(v.Delivered, delivered...)
	if len(delivered) > 0 {
		return outcomeDelivered, "", true
	}
	return outcomeBuffered, "分片已缓存, 等待补齐", true
}

// applyForward 在事务副本上处理一个 FORWARD-TSN 块; 返回 false 表示该块使
// 整个数据报冻结拒绝。
func (s *Session) applyForward(p *sctp.Packet, f *sctp.ForwardTSNChunk, ordinal int, v *Verdict) bool {
	reject := func(reason string) {
		v.Decision = DecisionRejected
		v.Reason = fmt.Sprintf("数据报内第 %d 块(FORWARD-TSN)违规, 整包冻结拒绝: %s", ordinal, reason)
	}
	if !s.Initialized {
		reject("越界跳过: 尚无关联上下文, 无法界定跳过范围")
		return false
	}
	if p.SrcPort != s.SrcPort || p.DstPort != s.DstPort || p.VerTag != s.VerTag {
		reject(fmt.Sprintf("关联不匹配: 期望端口 %d→%d 验证标记 %08x", s.SrcPort, s.DstPort, s.VerTag))
		return false
	}
	if f.NewCumTSN < s.CumTSN {
		reject(fmt.Sprintf("越界跳过: 新累计 TSN %d 低于当前累计 TSN %d", f.NewCumTSN, s.CumTSN))
		return false
	}
	if f.NewCumTSN > s.MaxTSN {
		reject(fmt.Sprintf("越界跳过: 新累计 TSN %d 超出已观测最大 TSN %d", f.NewCumTSN, s.MaxTSN))
		return false
	}
	for _, pr := range f.Pairs {
		if pr.Stream != s.Stream {
			reject(fmt.Sprintf("非法流序: FORWARD-TSN 指向未受审流 %d", pr.Stream))
			return false
		}
		if uint32(pr.SSN)+1 < uint32(s.ExpectedSSN) {
			reject(fmt.Sprintf("非法流序: 流序回退到 %d, 当前期望 %d", pr.SSN, s.ExpectedSSN))
			return false
		}
	}
	// 应用跳过: 移出被跨越的缓存分片, 记录跳过范围。
	if f.NewCumTSN > s.CumTSN {
		start := s.CumTSN + 1
		for t := range s.Buffered {
			if t >= start && t <= f.NewCumTSN {
				delete(s.Buffered, t)
				v.BufferRemoved = append(v.BufferRemoved, t)
			}
		}
		s.Skipped = mergeRanges(append(s.Skipped, Range{Start: start, End: f.NewCumTSN}))
		v.SkippedAdded = append(v.SkippedAdded, Range{Start: start, End: f.NewCumTSN})
		s.CumTSN = f.NewCumTSN
	}
	// 被跨越后残缺的消息作废, 不交付。
	ssnSet := map[uint16]bool{}
	for _, fr := range s.Buffered {
		ssnSet[fr.SSN] = true
	}
	for _, ssn := range ssset(ssnSet) {
		removed, abandoned := s.checkDead(ssn)
		v.BufferRemoved = append(v.BufferRemoved, removed...)
		v.Abandoned = append(v.Abandoned, abandoned...)
	}
	// 应用流序推进: 丢弃被放弃流序的缓存分片。
	for _, pr := range f.Pairs {
		if pr.SSN == 0xffff {
			continue // 不处理回绕, 审计范围内不会出现
		}
		if pr.SSN+1 > s.ExpectedSSN {
			s.ExpectedSSN = pr.SSN + 1
		}
		for t, fr := range s.Buffered {
			if fr.SSN <= pr.SSN {
				delete(s.Buffered, t)
				v.BufferRemoved = append(v.BufferRemoved, t)
				v.Abandoned = appendAbandoned(v.Abandoned, fr.SSN)
			}
		}
	}
	// 流序推进可能解锁后续已补齐的消息。
	delivered, removed := s.tryDeliver()
	v.BufferRemoved = append(v.BufferRemoved, removed...)
	v.Delivered = append(v.Delivered, delivered...)
	sortUint32s(v.BufferRemoved)
	return true
}

// ssset 返回缓存中尚存分片的流序集合(确定性顺序)。
func ssset(m map[uint16]bool) []uint16 {
	out := make([]uint16, 0, len(m))
	for ssn := range m {
		out = append(out, ssn)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// checkFragmentOrder 校验新分片与缓存分片之间的流序合法性, 返回拒绝原因(空串为合法)。
func (s *Session) checkFragmentOrder(d *sctp.DataChunk) string {
	type span struct {
		hasB, hasE bool
		tB, tE     uint32
	}
	spans := map[uint16]*span{}
	for _, f := range s.Buffered {
		sp := spans[f.SSN]
		if sp == nil {
			sp = &span{}
			spans[f.SSN] = sp
		}
		if f.B {
			sp.hasB, sp.tB = true, f.TSN
		}
		if f.E {
			sp.hasE, sp.tE = true, f.TSN
		}
	}
	if sp := spans[d.SSN]; sp != nil {
		if d.B && sp.hasB {
			return fmt.Sprintf("非法流序: 流序 %d 出现重复首片(B)", d.SSN)
		}
		if d.E && sp.hasE {
			return fmt.Sprintf("非法流序: 流序 %d 出现重复尾片(E)", d.SSN)
		}
		if d.B && sp.hasE && d.TSN > sp.tE {
			return fmt.Sprintf("非法流序: 流序 %d 首片(B) TSN %d 位于尾片(E) TSN %d 之后", d.SSN, d.TSN, sp.tE)
		}
		if d.E && sp.hasB && d.TSN < sp.tB {
			return fmt.Sprintf("非法流序: 流序 %d 尾片(E) TSN %d 位于首片(B) TSN %d 之前", d.SSN, d.TSN, sp.tB)
		}
		if !d.B && !d.E {
			if sp.hasB && d.TSN < sp.tB {
				return fmt.Sprintf("非法流序: 流序 %d 中间片 TSN %d 位于首片(B) TSN %d 之前", d.SSN, d.TSN, sp.tB)
			}
			if sp.hasE && d.TSN > sp.tE {
				return fmt.Sprintf("非法流序: 流序 %d 中间片 TSN %d 位于尾片(E) TSN %d 之后", d.SSN, d.TSN, sp.tE)
			}
		}
	}
	for ssn, sp := range spans {
		if ssn == d.SSN {
			continue
		}
		if sp.hasB && sp.hasE && sp.tB < d.TSN && d.TSN < sp.tE {
			return fmt.Sprintf("非法流序: TSN %d 交错落入流序 %d 的分片区间 [%d,%d]", d.TSN, ssn, sp.tB, sp.tE)
		}
	}
	return ""
}

// checkDead 若指定流序的缓存分片区间与跳过范围相交, 则作废该消息的全部缓存分片。
func (s *Session) checkDead(ssn uint16) ([]uint32, []uint16) {
	var lo, hi uint32
	found := false
	for _, f := range s.Buffered {
		if f.SSN != ssn {
			continue
		}
		if !found || f.TSN < lo {
			lo = f.TSN
		}
		if !found || f.TSN > hi {
			hi = f.TSN
		}
		found = true
	}
	if !found {
		return nil, nil
	}
	for _, r := range s.Skipped {
		if r.Start <= hi && r.End >= lo {
			var removed []uint32
			for t, f := range s.Buffered {
				if f.SSN == ssn {
					removed = append(removed, t)
					delete(s.Buffered, t)
				}
			}
			sortUint32s(removed)
			return removed, []uint16{ssn}
		}
	}
	return nil, nil
}

// tryDeliver 按流序交付所有已补齐的完整消息。
func (s *Session) tryDeliver() ([]Message, []uint32) {
	var delivered []Message
	var removedAll []uint32
	for {
		var tsns []uint32
		for t, f := range s.Buffered {
			if f.SSN == s.ExpectedSSN {
				tsns = append(tsns, t)
			}
		}
		if len(tsns) == 0 {
			break
		}
		sortUint32s(tsns)
		var tB, tE uint32
		hasB, hasE := false, false
		for _, t := range tsns {
			f := s.Buffered[t]
			if f.B {
				tB, hasB = t, true
			}
			if f.E {
				tE, hasE = t, true
			}
		}
		if !hasB || !hasE {
			break
		}
		// 一次捕获至多 MaxPackets 个包, 跨度超出该数的消息不可能补齐, 亦防止异常跨度空转。
		if tE-tB+1 > MaxPackets {
			break
		}
		complete := true
		for t := tB; t <= tE; t++ {
			f, ok := s.Buffered[t]
			if !ok || f.SSN != s.ExpectedSSN {
				complete = false
				break
			}
		}
		if !complete {
			break
		}
		var data []byte
		var mtsns []uint32
		for t := tB; t <= tE; t++ {
			data = append(data, s.Buffered[t].Data...)
			mtsns = append(mtsns, t)
		}
		msg := Message{
			Seq:    len(s.Messages),
			Stream: s.Stream,
			SSN:    s.ExpectedSSN,
			TSNs:   mtsns,
			Length: len(data),
			Hex:    hex.EncodeToString(data),
		}
		s.Messages = append(s.Messages, msg)
		delivered = append(delivered, msg)
		for _, t := range mtsns {
			delete(s.Buffered, t)
		}
		removedAll = append(removedAll, mtsns...)
		s.ExpectedSSN++
	}
	return delivered, removedAll
}

func (s *Session) inSkipped(tsn uint32) bool {
	for _, r := range s.Skipped {
		if tsn >= r.Start && tsn <= r.End {
			return true
		}
	}
	return false
}

func mergeRanges(rs []Range) []Range {
	if len(rs) == 0 {
		return nil
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].Start < rs[j].Start })
	out := []Range{rs[0]}
	for _, r := range rs[1:] {
		last := &out[len(out)-1]
		if r.Start <= last.End+1 {
			if r.End > last.End {
				last.End = r.End
			}
		} else {
			out = append(out, r)
		}
	}
	return out
}

func appendAbandoned(list []uint16, ssn uint16) []uint16 {
	for _, x := range list {
		if x == ssn {
			return list
		}
	}
	return append(list, ssn)
}

func sortUint32s(a []uint32) {
	sort.Slice(a, func(i, j int) bool { return a[i] < a[j] })
}
