package audit

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"sctpaudit/sctp"
)

const (
	testSrc = 5000
	testDst = 9
	testTag = 0x01020304
	testStr = 7
)

func data(tsn uint32, ssn uint16, u, b, e bool, payload string) []byte {
	return sctp.BuildData(testSrc, testDst, testTag, tsn, testStr, ssn, 0, u, b, e, []byte(payload))
}

func fwd(newCum uint32, pairs ...sctp.StreamPair) []byte {
	return sctp.BuildForwardTSN(testSrc, testDst, testTag, newCum, pairs...)
}

func hasU32(a []uint32, x uint32) bool {
	for _, v := range a {
		if v == x {
			return true
		}
	}
	return false
}

func hasU16(a []uint16, x uint16) bool {
	for _, v := range a {
		if v == x {
			return true
		}
	}
	return false
}

// 乱序互补的 DATA 仅交付一次完整消息, 且每包缓存变化可见。
func TestOutOfOrderFragmentsDeliverOnce(t *testing.T) {
	s := NewSession("t-ooo")
	v0 := s.Apply(data(1001, 10, false, false, true, "WORLD!"))
	if v0.Decision != DecisionBuffered || !hasU32(v0.BufferAdded, 1001) {
		t.Fatalf("首包(E片)应缓存: %+v", v0)
	}
	v1 := s.Apply(data(1000, 10, false, true, false, "HELLO-"))
	if v1.Decision != DecisionDelivered {
		t.Fatalf("次包(B片)应交付: %+v", v1)
	}
	if !hasU32(v1.BufferAdded, 1000) || !hasU32(v1.BufferRemoved, 1000) || !hasU32(v1.BufferRemoved, 1001) {
		t.Fatalf("缓存变化应展示 +1000 -1000,-1001: %+v", v1)
	}
	if len(s.Messages) != 1 || s.Messages[0].Hex != hex.EncodeToString([]byte("HELLO-WORLD!")) {
		t.Fatalf("应恰好交付一条完整消息: %+v", s.Messages)
	}
	// 字节完全相同的重传不得增加消息数。
	v2 := s.Apply(data(1000, 10, false, true, false, "HELLO-"))
	if v2.Decision != DecisionDuplicate || len(s.Messages) != 1 {
		t.Fatalf("重传应判 duplicate 且消息数不变: %+v, %d", v2, len(s.Messages))
	}
	v3 := s.Apply(data(1001, 10, false, false, true, "WORLD!"))
	if v3.Decision != DecisionDuplicate || len(s.Messages) != 1 {
		t.Fatalf("重传应判 duplicate 且消息数不变: %+v, %d", v3, len(s.Messages))
	}
}

// 缺失片段被合法 FORWARD-TSN 跨越后不交付残缺消息, 补交旧片不改变结论。
func TestForwardSkipThenStaleOldFragment(t *testing.T) {
	s := NewSession("t-skip")
	s.Apply(data(2000, 20, false, true, false, "AB"))
	s.Apply(data(2002, 20, false, false, true, "EF"))
	if len(s.Buffered) != 2 || s.CumTSN != 2000 {
		t.Fatalf("应缓存两片且累计 TSN 停在 2000: %+v", s.Buffered)
	}
	v := s.Apply(fwd(2001, sctp.StreamPair{Stream: testStr, SSN: 20}))
	if v.Decision != DecisionAccepted {
		t.Fatalf("合法 FORWARD-TSN 应被接受: %+v", v)
	}
	if len(v.SkippedAdded) != 1 || v.SkippedAdded[0].Start != 2001 || v.SkippedAdded[0].End != 2001 {
		t.Fatalf("应记录跳过范围 [2001,2001]: %+v", v.SkippedAdded)
	}
	if !hasU32(v.BufferRemoved, 2000) || !hasU32(v.BufferRemoved, 2002) || !hasU16(v.Abandoned, 20) {
		t.Fatalf("残缺消息应作废并移出缓存: %+v", v)
	}
	if len(s.Messages) != 0 || len(s.Buffered) != 0 || s.ExpectedSSN != 21 {
		t.Fatalf("不交付残缺消息: %+v", s.Messages)
	}
	// 补交旧片段: stale, 结论不变。
	v2 := s.Apply(data(2001, 20, false, false, false, "CD"))
	if v2.Decision != DecisionStale {
		t.Fatalf("旧片应判 stale: %+v", v2)
	}
	if len(s.Messages) != 0 || len(s.Buffered) != 0 || len(s.Skipped) != 1 {
		t.Fatalf("补交旧片改变了结论: %+v", s)
	}
}

// 同一 TSN 的不同字节必须冻结拒绝, 并稳定显示首个原始字节依据。
func TestTSNConflictEvidence(t *testing.T) {
	s := NewSession("t-conflict")
	s.Apply(data(100, 1, false, true, true, "ORIGINAL"))
	before := len(s.Messages)
	v := s.Apply(data(100, 1, false, true, true, "TAMPERED"))
	if v.Decision != DecisionRejected || v.Evidence == nil {
		t.Fatalf("同 TSN 不同字节应冻结拒绝: %+v", v)
	}
	if v.Evidence.FirstBytesHex != hex.EncodeToString([]byte("ORIGINAL")) {
		t.Fatalf("首个原始字节依据不稳定: %+v", v.Evidence)
	}
	if v.Evidence.ConflictBytesHex != hex.EncodeToString([]byte("TAMPERED")) {
		t.Fatalf("冲突字节记录错误: %+v", v.Evidence)
	}
	if len(s.Messages) != before || s.CumTSN != 100 {
		t.Fatalf("拒绝后状态被改变")
	}
	// 再次读取同一裁决: 依据保持一致(冻结)。
	again := s.Verdicts[1]
	if again.Evidence == nil || again.Evidence.FirstBytesHex != v.Evidence.FirstBytesHex {
		t.Fatalf("冻结裁决的依据不一致")
	}
}

// 被跨越 TSN 首次以旧片身份出现时记录指纹, 之后同 TSN 不同字节仍冻结拒绝。
func TestStaleThenConflictEvidence(t *testing.T) {
	s := NewSession("t-stale-conflict")
	s.Apply(data(3000, 30, false, true, false, "AB")) // B@3000 ssn30
	s.Apply(data(3002, 30, false, false, true, "EF")) // E@3002 ssn30, 缺 3001
	vf := s.Apply(fwd(3001, sctp.StreamPair{Stream: testStr, SSN: 30}))
	if vf.Decision != DecisionAccepted {
		t.Fatalf("FORWARD-TSN 应被接受: %+v", vf)
	}
	vStale := s.Apply(data(3001, 30, false, false, false, "CD"))
	if vStale.Decision != DecisionStale {
		t.Fatalf("被跨越 TSN 的迟到包应判 stale: %+v", vStale)
	}
	vConf := s.Apply(data(3001, 30, false, false, false, "XY"))
	if vConf.Decision != DecisionRejected || vConf.Evidence == nil ||
		vConf.Evidence.FirstBytesHex != hex.EncodeToString([]byte("CD")) {
		t.Fatalf("旧片指纹冲突应冻结拒绝并显示首个原始字节: %+v", vConf)
	}
	if len(s.Messages) != 0 {
		t.Fatalf("残缺消息不得交付: %+v", s.Messages)
	}
}

// 非法流序: 无序 DATA、错误流、关联不匹配。
func TestIllegalStreamOrderRejected(t *testing.T) {
	s := NewSession("t-stream")
	s.Apply(data(100, 1, false, true, true, "ok"))
	if v := s.Apply(data(101, 2, true, true, true, "u")); v.Decision != DecisionRejected {
		t.Fatalf("无序 DATA 应拒绝: %+v", v)
	}
	wrongStream := sctp.BuildData(testSrc, testDst, testTag, 101, 8, 2, 0, false, true, true, []byte("x"))
	if v := s.Apply(wrongStream); v.Decision != DecisionRejected {
		t.Fatalf("非受审流应拒绝: %+v", v)
	}
	wrongTag := sctp.BuildData(testSrc, testDst, 0xFFFFFFFF, 101, testStr, 2, 0, false, true, true, []byte("x"))
	if v := s.Apply(wrongTag); v.Decision != DecisionRejected {
		t.Fatalf("关联不匹配应拒绝: %+v", v)
	}
	if len(s.Messages) != 1 || s.CumTSN != 100 {
		t.Fatalf("拒绝后状态被改变")
	}
}

// 越界跳过: 超出已观测范围、低于当前累计 TSN、无关联上下文。
func TestOutOfBoundsSkipRejected(t *testing.T) {
	s := NewSession("t-oob")
	if v := s.Apply(fwd(500)); v.Decision != DecisionRejected {
		t.Fatalf("无上下文 FORWARD-TSN 应拒绝: %+v", v)
	}
	s.Apply(data(100, 1, false, true, true, "a"))
	if v := s.Apply(fwd(105)); v.Decision != DecisionRejected {
		t.Fatalf("超出已观测最大 TSN 的跳过应拒绝: %+v", v)
	}
	s.Apply(data(101, 2, false, true, true, "b"))
	if v := s.Apply(fwd(101)); v.Decision != DecisionAccepted {
		t.Fatalf("合法 FORWARD-TSN 应接受: %+v", v)
	}
	if v := s.Apply(fwd(100)); v.Decision != DecisionRejected {
		t.Fatalf("低于累计 TSN 的回退跳过应拒绝: %+v", v)
	}
	if len(s.Skipped) != 0 || s.CumTSN != 101 {
		t.Fatalf("拒绝后跳过状态被改变: %+v", s.Skipped)
	}
}

// 非法流序: 重复首片、首片在尾片后、跨消息交错。
func TestFragmentOrderViolations(t *testing.T) {
	s := NewSession("t-frag")
	s.Apply(data(100, 1, false, true, false, "A")) // B@100 ssn1
	s.Apply(data(103, 1, false, false, true, "D")) // E@103 ssn1 (缺口 101,102)
	if v := s.Apply(data(105, 1, false, true, false, "X")); v.Decision != DecisionRejected {
		t.Fatalf("重复首片应拒绝: %+v", v)
	}
	if v := s.Apply(data(106, 1, false, false, true, "Y")); v.Decision != DecisionRejected {
		t.Fatalf("重复尾片应拒绝: %+v", v)
	}
	if v := s.Apply(data(102, 2, false, true, true, "Z")); v.Decision != DecisionRejected {
		t.Fatalf("交错落入他消息区间应拒绝: %+v", v)
	}
	if len(s.Buffered) != 2 {
		t.Fatalf("拒绝后缓存被改变: %+v", s.Buffered)
	}
	// 尾片先于首片到达是合法乱序; 但首片 TSN 大于已有尾片则非法。
	s2 := NewSession("t-frag-2")
	s2.Apply(data(200, 1, false, false, true, "E")) // E@200
	if v := s2.Apply(data(201, 1, false, true, false, "B")); v.Decision != DecisionRejected {
		t.Fatalf("首片在尾片之后应拒绝: %+v", v)
	}
}

// FORWARD-TSN 流序推进可解锁后续已补齐的消息。
func TestForwardUnlocksLaterMessage(t *testing.T) {
	s := NewSession("t-unlock")
	s.Apply(data(100, 1, false, true, false, "A")) // B@100 ssn1
	s.Apply(data(102, 1, false, false, true, "C")) // E@102 ssn1 (缺 101)
	s.Apply(data(103, 2, false, true, true, "M2")) // 完整消息 ssn2, 因流序等待
	if len(s.Messages) != 0 {
		t.Fatalf("ssn2 不应提前交付")
	}
	v := s.Apply(fwd(101, sctp.StreamPair{Stream: testStr, SSN: 1}))
	if v.Decision != DecisionAccepted {
		t.Fatalf("FORWARD-TSN 应接受: %+v", v)
	}
	if !hasU16(v.Abandoned, 1) {
		t.Fatalf("ssn1 应作废: %+v", v)
	}
	if len(s.Messages) != 1 || s.Messages[0].SSN != 2 || s.Messages[0].Hex != hex.EncodeToString([]byte("M2")) {
		t.Fatalf("ssn2 应在流序推进后交付: %+v", s.Messages)
	}
}

// 非法流序: FORWARD-TSN 流序回退、指向未受审流。
func TestForwardStreamViolations(t *testing.T) {
	s := NewSession("t-fwd-stream")
	s.Apply(data(100, 5, false, true, true, "a")) // 交付 ssn5 → 期望 6
	s.Apply(data(101, 6, false, true, true, "b")) // 交付 ssn6 → 期望 7
	if v := s.Apply(fwd(101, sctp.StreamPair{Stream: testStr, SSN: 4})); v.Decision != DecisionRejected {
		t.Fatalf("流序回退应拒绝: %+v", v)
	}
	if v := s.Apply(fwd(101, sctp.StreamPair{Stream: 99, SSN: 7})); v.Decision != DecisionRejected {
		t.Fatalf("指向未受审流应拒绝: %+v", v)
	}
}

// 超大 TSN 跨度不会导致空转: 分片跨度超出单审计可能补齐的范围即不再尝试交付;
// 跳过范围按缓存键应用, 不按区间逐个迭代。
func TestHugeSpansDoNotHang(t *testing.T) {
	s := NewSession("t-huge")
	s.Apply(data(100, 1, false, true, false, "A"))
	v := s.Apply(data(4000000000, 1, false, false, true, "Z"))
	if v.Decision != DecisionBuffered {
		t.Fatalf("巨大跨度分片应仅缓存: %+v", v)
	}
	f := fwd(3999999999, sctp.StreamPair{Stream: testStr, SSN: 1})
	v2 := s.Apply(f)
	if v2.Decision != DecisionAccepted {
		t.Fatalf("超大跳过范围应被接受: %+v", v2)
	}
	if !hasU32(v2.BufferRemoved, 100) || !hasU32(v2.BufferRemoved, 4000000000) {
		t.Fatalf("被跨越的残缺消息应作废: %+v", v2)
	}
	if len(s.Messages) != 0 || len(s.Buffered) != 0 {
		t.Fatalf("不交付残缺消息: %+v", s.Messages)
	}
}

// 字节完全相同的 FORWARD-TSN 重传判为 duplicate, 不被误判为回退。
func TestForwardRetransmissionDuplicate(t *testing.T) {
	s := NewSession("t-fwd-dup")
	s.Apply(data(100, 1, false, true, true, "a"))
	s.Apply(data(101, 2, false, true, true, "b")) // 累计 TSN 101
	f := fwd(101)
	if v := s.Apply(f); v.Decision != DecisionAccepted {
		t.Fatalf("首次 FORWARD-TSN 应接受: %+v", v)
	}
	s.Apply(data(102, 3, false, true, true, "c")) // 累计 TSN 推进到 102
	v := s.Apply(f)
	if v.Decision != DecisionDuplicate {
		t.Fatalf("FORWARD-TSN 重传应判 duplicate 而非回退拒绝: %+v", v)
	}
	if s.CumTSN != 102 || len(s.Skipped) != 0 {
		t.Fatalf("重传后状态被改变: %d %+v", s.CumTSN, s.Skipped)
	}
}

// 损坏报文(校验和错误)冻结拒绝且状态不变。
func TestInvalidPacketRejected(t *testing.T) {
	s := NewSession("t-invalid")
	s.Apply(data(100, 1, false, true, true, "ok"))
	bad := data(101, 2, false, true, true, "bad")
	bad[len(bad)-1] ^= 0xFF
	v := s.Apply(bad)
	if v.Decision != DecisionRejected || v.Type != "INVALID" {
		t.Fatalf("CRC 错误应冻结拒绝: %+v", v)
	}
	if s.CumTSN != 100 || len(s.Messages) != 1 {
		t.Fatalf("拒绝后状态被改变")
	}
}

// 单分片消息按序到达: 缓存 +t/-t 可见并立即交付。
func TestInOrderSingleFragment(t *testing.T) {
	s := NewSession("t-single")
	v := s.Apply(data(100, 1, false, true, true, "ping"))
	if v.Decision != DecisionDelivered || !hasU32(v.BufferAdded, 100) || !hasU32(v.BufferRemoved, 100) {
		t.Fatalf("单分片应立即交付且缓存变化可见: %+v", v)
	}
	if s.CumTSN != 100 || s.ExpectedSSN != 2 {
		t.Fatalf("累计 TSN/期望流序错误: %d/%d", s.CumTSN, s.ExpectedSSN)
	}
}

// bundle 构造同一公共头后按线序携带多个块的复合数据报。
func bundle(specs ...sctp.ChunkSpec) []byte {
	return sctp.BuildPacket(testSrc, testDst, testTag, specs...)
}

func dataSpec(tsn uint32, ssn uint16, u, b, e bool, payload string) sctp.ChunkSpec {
	return sctp.ChunkSpec{Data: &sctp.DataSpec{TSN: tsn, Stream: testStr, SSN: ssn, U: u, B: b, E: e, Data: []byte(payload)}}
}

// 连续 B、E 两个 DATA 块装入同一个 SCTP 数据报: 只形成一个原始包裁决,
// 展示两个分片的缓存进出, 恰好交付一次拼接后的消息。
func TestBundledBeginThenEndDeliversOnce(t *testing.T) {
	s := NewSession("t-bundle-be")
	pkt := bundle(
		dataSpec(5000, 42, false, true, false, "HELLO-"),
		dataSpec(5001, 42, false, false, true, "WORLD!"),
	)
	v := s.Apply(pkt)
	if len(s.Verdicts) != 1 {
		t.Fatalf("复合数据报应只形成一个原始包裁决: %d", len(s.Verdicts))
	}
	if v.Decision != DecisionDelivered {
		t.Fatalf("应交付: %+v", v)
	}
	if len(v.Chunks) != 2 || v.Chunks[0].Outcome != "buffered" || v.Chunks[1].Outcome != "delivered" {
		t.Fatalf("逐块线序结果应为先缓存(B片)后交付(E片): %+v", v.Chunks)
	}
	if v.Chunks[0].TSN == nil || *v.Chunks[0].TSN != 5000 || v.Chunks[1].TSN == nil || *v.Chunks[1].TSN != 5001 {
		t.Fatalf("逐块 TSN 线序错误: %+v", v.Chunks)
	}
	if !hasU32(v.BufferAdded, 5000) || !hasU32(v.BufferAdded, 5001) ||
		!hasU32(v.BufferRemoved, 5000) || !hasU32(v.BufferRemoved, 5001) {
		t.Fatalf("应展示两个分片的缓存进出 +5000,+5001 -5000,-5001: +%v -%v", v.BufferAdded, v.BufferRemoved)
	}
	if len(s.Messages) != 1 {
		t.Fatalf("应恰好交付一条消息: %d", len(s.Messages))
	}
	if s.Messages[0].Hex != hex.EncodeToString([]byte("HELLO-WORLD!")) || len(s.Messages[0].TSNs) != 2 {
		t.Fatalf("拼接消息错误: %+v", s.Messages[0])
	}
	if s.CumTSN != 5001 || len(s.Buffered) != 0 {
		t.Fatalf("交付后累计 TSN=5001 且缓存清空: cum=%d buf=%v", s.CumTSN, s.Buffered)
	}

	// 字节完全相同的整包重传: 一个裁决 duplicate, 消息数不增加。
	vDup := s.Apply(pkt)
	if vDup.Decision != DecisionDuplicate || len(vDup.Chunks) != 2 {
		t.Fatalf("整包重传应判 duplicate 且保留逐块记录: %+v", vDup)
	}
	if len(s.Messages) != 1 || len(s.Verdicts) != 2 {
		t.Fatalf("重传不得增加消息数或改变状态: messages=%d verdicts=%d", len(s.Messages), len(s.Verdicts))
	}
}

// 复合数据报内 DATA 后紧随合法 FORWARD-TSN: 同一裁决反映跳过范围、残缺消息
// 作废及随后可交付消息; 整包重传不增加消息数。
func TestBundledDataThenForwardTSN(t *testing.T) {
	s := NewSession("t-bundle-fwd")
	// 前置: ssn1 仅有 B 片(TSN100), 缺口 101; ssn2 的完整消息(TSN103)已缓存等待。
	s.Apply(data(100, 1, false, true, false, "A"))
	s.Apply(data(103, 2, false, true, true, "M2"))
	if len(s.Messages) != 0 || s.CumTSN != 100 {
		t.Fatalf("前置状态不应交付: messages=%d cum=%d", len(s.Messages), s.CumTSN)
	}
	// 一个数据报: E 片(TSN102, ssn1, 仍缺 101) + FORWARD-TSN 跨越 101 并放弃 ssn1。
	pkt := bundle(
		dataSpec(102, 1, false, false, true, "C"),
		sctp.ChunkSpec{Forward: &sctp.ForwardTSNChunk{
			NewCumTSN: 101,
			Pairs:     []sctp.StreamPair{{Stream: testStr, SSN: 1}},
		}},
	)
	v := s.Apply(pkt)
	if len(s.Verdicts) != 3 {
		t.Fatalf("原始包裁决数应为 3: %d", len(s.Verdicts))
	}
	if v.Decision != DecisionAccepted {
		t.Fatalf("含 FORWARD-TSN 的复合数据报应判 accepted: %+v", v)
	}
	if len(v.Chunks) != 2 || v.Chunks[0].Type != "DATA" || v.Chunks[1].Type != "FORWARD-TSN" {
		t.Fatalf("逐块线序错误: %+v", v.Chunks)
	}
	if len(v.SkippedAdded) != 1 || v.SkippedAdded[0].Start != 101 || v.SkippedAdded[0].End != 101 {
		t.Fatalf("同一裁决应反映跳过范围 [101,101]: %+v", v.SkippedAdded)
	}
	if !hasU32(v.BufferAdded, 102) {
		t.Fatalf("DATA 块应先将 102 加入缓存: +%v", v.BufferAdded)
	}
	if !hasU32(v.BufferRemoved, 100) || !hasU32(v.BufferRemoved, 102) || !hasU16(v.Abandoned, 1) {
		t.Fatalf("残缺消息 ssn1 应作废并移出缓存: -%v 作废%v", v.BufferRemoved, v.Abandoned)
	}
	if len(v.Delivered) != 1 || v.Delivered[0].SSN != 2 ||
		v.Delivered[0].Hex != hex.EncodeToString([]byte("M2")) {
		t.Fatalf("同一裁决应交付随后可交付的 ssn2 消息: %+v", v.Delivered)
	}
	if len(s.Messages) != 1 || s.CumTSN != 101 {
		t.Fatalf("恰好交付一条且累计 TSN=101: messages=%d cum=%d", len(s.Messages), s.CumTSN)
	}
	// 整包重传: duplicate, 消息数不变。
	vDup := s.Apply(pkt)
	if vDup.Decision != DecisionDuplicate || len(s.Messages) != 1 || s.CumTSN != 101 {
		t.Fatalf("整包重传应判 duplicate 且消息数/状态不变: %+v messages=%d", vDup, len(s.Messages))
	}
}

// 原子性: 首块正常、后续块流标识非法的复合数据报必须整体冻结拒绝,
// 不留下首块建立的关联、缓存或累计 TSN。
func TestBundledLaterChunkViolationRollsBackAtomically(t *testing.T) {
	s := NewSession("t-bundle-atomic")
	pkt := bundle(
		dataSpec(7000, 1, false, true, false, "A"), // 首块正常(B 片)
		sctp.ChunkSpec{Data: &sctp.DataSpec{TSN: 7001, Stream: 8, // 后续块: 非受审流
			SSN: 1, B: false, E: true, Data: []byte("B")}},
	)
	v := s.Apply(pkt)
	if v.Decision != DecisionRejected {
		t.Fatalf("后续块非法应整体拒绝: %+v", v)
	}
	if s.Initialized || s.CumTSN != 0 || s.MaxTSN != 0 || len(s.Buffered) != 0 ||
		len(s.Seen) != 0 || len(s.Messages) != 0 {
		t.Fatalf("回滚不彻底, 首块状态泄漏: init=%v cum=%d max=%d buf=%d seen=%d",
			s.Initialized, s.CumTSN, s.MaxTSN, len(s.Buffered), len(s.Seen))
	}
	// 被拒裁决本身也不得显示首块试执行时的缓存进出/逐块记录。
	if len(v.Chunks) != 0 || len(v.BufferAdded) != 0 || len(v.BufferRemoved) != 0 ||
		len(v.Delivered) != 0 {
		t.Fatalf("被拒裁决不应残留试执行动态字段: chunks=%v +%v -%v delivered=%v",
			v.Chunks, v.BufferAdded, v.BufferRemoved, v.Delivered)
	}
	// 拒绝后仍可用完全相同的合法首片重新建立关联(证明未被污染)。
	ok := s.Apply(data(7000, 1, false, true, true, "A"))
	if ok.Decision != DecisionDelivered || !s.Initialized || s.CumTSN != 7000 {
		t.Fatalf("回滚后应能正常建立关联并交付: %+v cum=%d", ok, s.CumTSN)
	}
}

// 原子性: 复合数据报中第二块为 FORWARD-TSN 但越界跳过时, 首块已入缓存的
// 状态也必须整体回滚。
func TestBundledForwardViolationRollsBackAtomically(t *testing.T) {
	s := NewSession("t-bundle-atomic-2")
	pkt := bundle(
		dataSpec(8000, 1, false, true, true, "A"),
		sctp.ChunkSpec{Forward: &sctp.ForwardTSNChunk{NewCumTSN: 9999}}, // 超出已观测范围
	)
	v := s.Apply(pkt)
	if v.Decision != DecisionRejected {
		t.Fatalf("后续 FORWARD-TSN 越界应整体拒绝: %+v", v)
	}
	if s.Initialized || s.CumTSN != 0 || len(s.Buffered) != 0 || len(s.Messages) != 0 {
		t.Fatalf("回滚不彻底: init=%v cum=%d buf=%d msgs=%d",
			s.Initialized, s.CumTSN, len(s.Buffered), len(s.Messages))
	}
}

// 重新打开冻结记录: 复合数据报场景下逐包结果、缓存变化、跳过范围与消息列表
// 必须与首次一致。
func TestBundledPersistenceReload(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	batch := [][]byte{
		bundle(
			dataSpec(9000, 1, false, true, false, "FOO-"),
			dataSpec(9001, 1, false, false, true, "BAR"),
		),
		bundle(
			dataSpec(9002, 2, false, true, false, "L"),
			sctp.ChunkSpec{Forward: &sctp.ForwardTSNChunk{
				NewCumTSN: 9002, Pairs: []sctp.StreamPair{{Stream: testStr, SSN: 2}},
			}},
		),
	}
	if _, c, err := st.Submit("bundle-persist", batch); err != nil || c != nil {
		t.Fatalf("提交失败: %v conflict=%+v", err, c)
	}
	first, ok, err := st.Get("bundle-persist")
	if err != nil || !ok {
		t.Fatalf("读取失败: %v", ok)
	}
	want := viewJSON(t, first)

	st2, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, ok, err := st2.Get("bundle-persist")
	if err != nil || !ok {
		t.Fatalf("恢复失败: %v", ok)
	}
	if g := viewJSON(t, got); g != want {
		t.Fatalf("复合数据报场景恢复后视图不一致:\n%s\n%s", g, want)
	}
}

func viewJSON(t *testing.T, s *Session) string {
	t.Helper()
	data, err := json.Marshal(s.View())
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
