// Package audit 实现星载控制中继弱链路控制消息的逐包裁决引擎:
// 单关联、单个有序流, 仅审查 DATA 与 FORWARD-TSN, 依据 TSN 与 B/E 标志
// 维护累计 TSN、缓存分片、跳过范围与已交付消息, 并对每个包给出冻结裁决。
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

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
	SHA256     string `json:"sha256"` // 块线序字节(而非整包)的指纹
	FirstHex   string `json:"firstHex"`
	Index      int    `json:"index"`
	ChunkIndex int    `json:"chunkIndex"`
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

// ChunkVerdict 是一个数据报内单个块(按线序)的裁决明细。
type ChunkVerdict struct {
	Index         int       `json:"index"` // 块在数据报内的线序位置
	Type          string    `json:"type"`  // DATA / FORWARD-TSN
	Decision      string    `json:"decision"`
	Reason        string    `json:"reason,omitempty"`
	TSN           *uint32   `json:"tsn,omitempty"`
	SSN           *uint16   `json:"ssn,omitempty"`
	CumTSN        uint32    `json:"cumTSN"` // 该块处理后的累计 TSN
	BufferAdded   []uint32  `json:"bufferAdded,omitempty"`
	BufferRemoved []uint32  `json:"bufferRemoved,omitempty"`
	SkippedAdded  []Range   `json:"skippedAdded,omitempty"`
	Delivered     []Message `json:"delivered,omitempty"`
	Abandoned     []uint16  `json:"abandonedSSN,omitempty"`
	Evidence      *Evidence `json:"evidence,omitempty"`
}

// Verdict 是单个(可能含多个块的)数据报的冻结裁决, 一旦记录不可更改。
// 复合数据报整体裁决: 任一块不合法则整包拒绝, 不留任何状态变化;
// 顶层缓存/跳过/交付字段为各块明细的聚合, Chunks 保留逐块线序裁决。
type Verdict struct {
	Index       int    `json:"index"`
	SHA256      string `json:"sha256"`
	ChunkCount  int    `json:"chunkCount"`
	Type        string `json:"type"` // DATA / FORWARD-TSN / MIXED / INVALID
	Decision    string `json:"decision"`
	Reason      string `json:"reason,omitempty"`
	CumTSN      uint32 `json:"cumTSN"` // 处理后的累计 TSN
	RejectChunk *int   `json:"rejectChunk,omitempty"`
	// TSN/SSN 仅在单块数据报上填充; 复合数据报请看 Chunks 逐块明细。
	TSN           *uint32   `json:"tsn,omitempty"`
	SSN           *uint16   `json:"ssn,omitempty"`
	BufferAdded   []uint32  `json:"bufferAdded,omitempty"`
	BufferRemoved []uint32  `json:"bufferRemoved,omitempty"`
	SkippedAdded  []Range   `json:"skippedAdded,omitempty"`
	Delivered     []Message `json:"delivered,omitempty"`
	Abandoned     []uint16  `json:"abandonedSSN,omitempty"`
	Evidence      *Evidence `json:"evidence,omitempty"`
	// Chunks 是数据报内按线序的逐块裁决; 整包拒绝时包含导致拒绝的块为止的明细。
	Chunks []ChunkVerdict `json:"chunks"`
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
	// SeenFwd 记录已应用 FORWARD-TSN 块的字节指纹 → 首次出现的包序号,
	// 用于把字节完全相同的 FORWARD-TSN 块重传判为 duplicate。
	SeenFwd  map[string]int `json:"seenFwd"`
	Messages []Message      `json:"messages"`
}

// engineState 是裁决一个数据报前的可变引擎状态快照, 用于整包原子回滚。
type engineState struct {
	Initialized      bool
	SrcPort, DstPort uint16
	VerTag           uint32
	Stream           uint16
	CumTSN, MaxTSN   uint32
	ExpectedSSN      uint16
	Buffered         map[uint32]*Frag
	Skipped          []Range
	Seen             map[uint32]SeenRec
	SeenFwd          map[string]int
	Messages         []Message
}

// NewSession 创建空会话。
func NewSession(id string) *Session {
	return &Session{
		ID:       id,
		Buffered: map[uint32]*Frag{},
		Seen:     map[uint32]SeenRec{},
		SeenFwd:  map[string]int{},
	}
}

func (s *Session) snapshotState() engineState {
	buf := make(map[uint32]*Frag, len(s.Buffered))
	for t, f := range s.Buffered {
		fc := *f
		fc.Data = append([]byte(nil), f.Data...)
		buf[t] = &fc
	}
	seen := make(map[uint32]SeenRec, len(s.Seen))
	for t, r := range s.Seen {
		seen[t] = r
	}
	seenFwd := make(map[string]int, len(s.SeenFwd))
	for h, i := range s.SeenFwd {
		seenFwd[h] = i
	}
	msgs := make([]Message, len(s.Messages))
	for i, m := range s.Messages {
		msgs[i] = m
		msgs[i].TSNs = append([]uint32(nil), m.TSNs...)
	}
	return engineState{
		Initialized: s.Initialized,
		SrcPort:     s.SrcPort,
		DstPort:     s.DstPort,
		VerTag:      s.VerTag,
		Stream:      s.Stream,
		CumTSN:      s.CumTSN,
		MaxTSN:      s.MaxTSN,
		ExpectedSSN: s.ExpectedSSN,
		Buffered:    buf,
		Skipped:     append([]Range(nil), s.Skipped...),
		Seen:        seen,
		SeenFwd:     seenFwd,
		Messages:    msgs,
	}
}

func (s *Session) restoreState(st engineState) {
	s.Initialized, s.SrcPort, s.DstPort = st.Initialized, st.SrcPort, st.DstPort
	s.VerTag, s.Stream = st.VerTag, st.Stream
	s.CumTSN, s.MaxTSN, s.ExpectedSSN = st.CumTSN, st.MaxTSN, st.ExpectedSSN
	s.Buffered, s.Skipped, s.Seen, s.SeenFwd, s.Messages =
		st.Buffered, st.Skipped, st.Seen, st.SeenFwd, st.Messages
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

// Apply 裁决一个原始报文(可能含多个按线序排列的块), 追加一条冻结裁决。
// 复合数据报整体原子裁决: 任一块被拒绝则回滚该包内已处理块的全部状态变化。
func (s *Session) Apply(raw []byte) Verdict {
	v := s.adjudicate(raw)
	s.Verdicts = append(s.Verdicts, v)
	s.Raw = append(s.Raw, raw)
	return v
}

func chunkType(ch *sctp.Chunk) string {
	switch ch.Type {
	case sctp.ChunkData:
		return "DATA"
	case sctp.ChunkForwardTSN:
		return "FORWARD-TSN"
	default:
		return "INVALID"
	}
}

func aggregateType(chunks []*sctp.Chunk) string {
	hasData, hasFwd := false, false
	for _, ch := range chunks {
		switch ch.Type {
		case sctp.ChunkData:
			hasData = true
		case sctp.ChunkForwardTSN:
			hasFwd = true
		}
	}
	switch {
	case hasData && hasFwd:
		return "MIXED"
	case hasFwd:
		return "FORWARD-TSN"
	default:
		return "DATA"
	}
}

func (s *Session) adjudicate(raw []byte) Verdict {
	packetIdx := len(s.Verdicts)
	v := Verdict{Index: packetIdx, SHA256: shaOf(raw)}
	p, err := sctp.Parse(raw)
	if err != nil {
		v.Type = "INVALID"
		v.Decision = DecisionRejected
		v.Reason = err.Error()
		v.CumTSN = s.CumTSN
		v.Chunks = []ChunkVerdict{}
		return v
	}
	v.ChunkCount = len(p.Chunks)
	v.Type = aggregateType(p.Chunks)
	// 整包重传检测: 与任一已冻结数据报字节完全相同 → 重传, 状态不变。
	// 覆盖 DATA 重传与 FORWARD-TSN 重传(否则后者会被误判为累计 TSN 回退)。
	for _, pv := range s.Verdicts {
		if pv.SHA256 == v.SHA256 {
			v.Decision = DecisionDuplicate
			v.Reason = fmt.Sprintf("与第 %d 包字节完全相同的整包重传, 状态不变", pv.Index)
			v.CumTSN = s.CumTSN
			v.Chunks = make([]ChunkVerdict, len(p.Chunks))
			for i, ch := range p.Chunks {
				cv := ChunkVerdict{
					Index: i, Type: chunkType(ch), Decision: DecisionDuplicate,
					CumTSN: s.CumTSN,
					Reason: fmt.Sprintf("整包重传: 与第 %d 包字节完全相同", pv.Index),
				}
				if ch.Data != nil {
					tsn, ssn := ch.Data.TSN, ch.Data.SSN
					cv.TSN, cv.SSN = &tsn, &ssn
				}
				v.Chunks[i] = cv
			}
			return v
		}
	}
	// 快照: 任一块拒绝即整体回滚, 保证数据报裁决的原子性。
	snap := s.snapshotState()
	cvs := make([]ChunkVerdict, 0, len(p.Chunks))
	for i, ch := range p.Chunks {
		cv := ChunkVerdict{Index: i, Type: chunkType(ch)}
		switch {
		case ch.Data != nil:
			tsn, ssn := ch.Data.TSN, ch.Data.SSN
			cv.TSN, cv.SSN = &tsn, &ssn
			s.applyData(p, ch, &cv)
		case ch.ForwardTSN != nil:
			s.applyForward(p, ch, &cv)
		}
		cv.CumTSN = s.CumTSN
		cvs = append(cvs, cv)
		if cv.Decision == DecisionRejected {
			s.restoreState(snap)
			v.Chunks = cvs
			v.Decision = DecisionRejected
			v.Reason = fmt.Sprintf("数据报内第 %d 块(%s)非法, 整包冻结拒绝: %s", i, cv.Type, cv.Reason)
			v.RejectChunk = &i
			v.Evidence = cv.Evidence
			v.TSN, v.SSN = cv.TSN, cv.SSN
			v.CumTSN = s.CumTSN
			return v
		}
	}
	// 全部块处理成功: 聚合各块的缓存变化、跳过范围、作废流序与交付消息。
	v.Chunks = cvs
	v.CumTSN = s.CumTSN
	hasDelivered, hasAccepted, hasBuffered, hasStale := false, false, false, false
	allDuplicate := true
	addedSeen := map[uint32]bool{}
	for _, cv := range cvs {
		for _, t := range cv.BufferAdded {
			if !addedSeen[t] {
				addedSeen[t] = true
				v.BufferAdded = append(v.BufferAdded, t)
			}
		}
		v.BufferRemoved = append(v.BufferRemoved, cv.BufferRemoved...)
		v.SkippedAdded = append(v.SkippedAdded, cv.SkippedAdded...)
		for _, ssn := range cv.Abandoned {
			v.Abandoned = appendAbandoned(v.Abandoned, ssn)
		}
		v.Delivered = append(v.Delivered, cv.Delivered...)
		switch cv.Decision {
		case DecisionDelivered:
			hasDelivered = true
		case DecisionAccepted:
			hasAccepted = true
		case DecisionBuffered:
			hasBuffered = true
		case DecisionStale:
			hasStale = true
		}
		if cv.Decision != DecisionDuplicate {
			allDuplicate = false
		}
	}
	sortUint32s(v.BufferRemoved)
	switch {
	case hasDelivered:
		v.Decision = DecisionDelivered
	case hasAccepted:
		v.Decision = DecisionAccepted
	case hasBuffered:
		v.Decision = DecisionBuffered
	case allDuplicate:
		v.Decision = DecisionDuplicate
	case hasStale:
		v.Decision = DecisionStale
	default:
		v.Decision = DecisionAccepted
	}
	if len(p.Chunks) > 1 {
		v.Reason = fmt.Sprintf("数据报含 %d 个块, 已按线序全部裁决, 整体状态原子提交", len(p.Chunks))
	} else {
		v.Reason = cvs[0].Reason
	}
	if len(p.Chunks) == 1 {
		v.TSN, v.SSN = cvs[0].TSN, cvs[0].SSN
	}
	return v
}

// applyData 处理一个 DATA 块。所有拒绝检查都在任何状态变更之前完成;
// 由 adjudicate 的快照保证: 复合数据报中后续块拒绝时, 本块的变更整体回滚。
func (s *Session) applyData(p *sctp.Packet, ch *sctp.Chunk, v *ChunkVerdict) {
	d := ch.Data
	reject := func(reason string) {
		v.Decision = DecisionRejected
		v.Reason = reason
	}
	if s.Initialized {
		if p.SrcPort != s.SrcPort || p.DstPort != s.DstPort || p.VerTag != s.VerTag {
			reject(fmt.Sprintf("关联不匹配: 期望端口 %d→%d 验证标记 %08x", s.SrcPort, s.DstPort, s.VerTag))
			return
		}
		if d.Stream != s.Stream {
			reject(fmt.Sprintf("非法流序: 流 %d 不属于受审有序流 %d", d.Stream, s.Stream))
			return
		}
	}
	if d.U {
		reject("非法流序: 无序(U)DATA 不在单有序流审查范围")
		return
	}
	if !s.Initialized && d.TSN == 0 {
		reject("首包 TSN 为 0, 无法建立审计基线")
		return
	}
	// 同 TSN 指纹检查: 块字节完全相同为重传, 不同则冻结拒绝并给出首个原始字节依据。
	chunkHash := shaOf(ch.Raw)
	if rec, ok := s.Seen[d.TSN]; ok {
		if rec.SHA256 != chunkHash {
			v.Decision = DecisionRejected
			v.Reason = fmt.Sprintf("TSN %d 冲突: 与第 %d 包第 %d 块首次记录的字节不同", d.TSN, rec.Index, rec.ChunkIndex)
			v.Evidence = &Evidence{
				TSN:              d.TSN,
				FirstIndex:       rec.Index,
				FirstSHA256:      rec.SHA256,
				FirstBytesHex:    rec.FirstHex,
				ConflictBytesHex: firstHex(d.Data, 16),
			}
			return
		}
		v.Decision = DecisionDuplicate
		v.Reason = fmt.Sprintf("TSN %d 字节完全相同的重传, 不增加消息数", d.TSN)
		return
	}
	// 首次观测该 TSN: 记录指纹(含首个原始字节依据)。
	s.Seen[d.TSN] = SeenRec{
		SHA256: chunkHash, FirstHex: firstHex(d.Data, 16),
		Index: len(s.Verdicts), ChunkIndex: v.Index,
	}
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
		v.Decision = DecisionStale
		v.Reason = fmt.Sprintf("TSN %d 已被 FORWARD-TSN 跨越, 补交旧片不改变结论", d.TSN)
		return
	}
	if d.SSN < s.ExpectedSSN {
		v.Decision = DecisionStale
		v.Reason = fmt.Sprintf("流序 %d 已过(当前期望 %d), 不再交付", d.SSN, s.ExpectedSSN)
		return
	}
	// 分片流序合法性(重复首/尾片、首尾倒置、跨消息交错)。
	if reason := s.checkFragmentOrder(d); reason != "" {
		reject(reason)
		return
	}
	// 进入分片缓存。
	s.Buffered[d.TSN] = &Frag{TSN: d.TSN, SSN: d.SSN, B: d.B, E: d.E, Data: append([]byte(nil), d.Data...)}
	v.BufferAdded = []uint32{d.TSN}
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
		v.Decision = DecisionBuffered
		v.Reason = fmt.Sprintf("流序 %d 的分片区间被跳过范围跨越, 残缺消息作废不交付", d.SSN)
		return
	}
	delivered, removed := s.tryDeliver()
	v.BufferRemoved = append(v.BufferRemoved, removed...)
	v.Delivered = delivered
	if len(delivered) > 0 {
		v.Decision = DecisionDelivered
	} else {
		v.Decision = DecisionBuffered
		v.Reason = "分片已缓存, 等待补齐"
	}
}

// applyForward 处理一个 FORWARD-TSN 块。所有拒绝检查都在任何状态变更之前完成;
// 由 adjudicate 的快照保证复合数据报内的原子性。
func (s *Session) applyForward(p *sctp.Packet, ch *sctp.Chunk, v *ChunkVerdict) {
	f := ch.ForwardTSN
	reject := func(reason string) {
		v.Decision = DecisionRejected
		v.Reason = reason
	}
	// 块字节完全相同的 FORWARD-TSN 重传 → duplicate, 不被误判为累计 TSN 回退。
	chunkHash := shaOf(ch.Raw)
	if first, ok := s.SeenFwd[chunkHash]; ok {
		v.Decision = DecisionDuplicate
		v.Reason = fmt.Sprintf("与第 %d 包字节完全相同的 FORWARD-TSN 重传, 状态不变", first)
		return
	}
	if !s.Initialized {
		reject("越界跳过: 尚无关联上下文, 无法界定跳过范围")
		return
	}
	if p.SrcPort != s.SrcPort || p.DstPort != s.DstPort || p.VerTag != s.VerTag {
		reject(fmt.Sprintf("关联不匹配: 期望端口 %d→%d 验证标记 %08x", s.SrcPort, s.DstPort, s.VerTag))
		return
	}
	if f.NewCumTSN < s.CumTSN {
		reject(fmt.Sprintf("越界跳过: 新累计 TSN %d 低于当前累计 TSN %d", f.NewCumTSN, s.CumTSN))
		return
	}
	if f.NewCumTSN > s.MaxTSN {
		reject(fmt.Sprintf("越界跳过: 新累计 TSN %d 超出已观测最大 TSN %d", f.NewCumTSN, s.MaxTSN))
		return
	}
	for _, pr := range f.Pairs {
		if pr.Stream != s.Stream {
			reject(fmt.Sprintf("非法流序: FORWARD-TSN 指向未受审流 %d", pr.Stream))
			return
		}
		if uint32(pr.SSN)+1 < uint32(s.ExpectedSSN) {
			reject(fmt.Sprintf("非法流序: 流序回退到 %d, 当前期望 %d", pr.SSN, s.ExpectedSSN))
			return
		}
	}
	s.SeenFwd[chunkHash] = len(s.Verdicts)
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
		v.SkippedAdded = []Range{{Start: start, End: f.NewCumTSN}}
		s.CumTSN = f.NewCumTSN
	}
	// 被跨越后残缺的消息作废, 不交付。
	ssnSet := map[uint16]bool{}
	for _, fr := range s.Buffered {
		ssnSet[fr.SSN] = true
	}
	for ssn := range ssnSet {
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
	v.Delivered = delivered
	sortUint32s(v.BufferRemoved)
	v.Decision = DecisionAccepted
	v.Reason = "FORWARD-TSN 已应用"
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
