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

func viewJSON(t *testing.T, s *Session) string {
	t.Helper()
	data, err := json.Marshal(s.View())
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// 一个数据报内按线序的 B 片 + E 片: 只形成一个原始包裁决, 恰好交付一次拼接消息。
func TestConsecutiveDataChunksSingleDatagram(t *testing.T) {
	s := NewSession("t-multi-be")
	dg := sctp.BuildDatagram(
		data(5000, 50, false, true, false, "WEAK-"),
		data(5001, 50, false, false, true, "LINK!"),
	)
	v := s.Apply(dg)
	if len(s.Verdicts) != 1 {
		t.Fatalf("复合数据报应只形成一个裁决: %d", len(s.Verdicts))
	}
	if v.Decision != DecisionDelivered || v.ChunkCount != 2 || v.Type != "DATA" {
		t.Fatalf("裁决应为 delivered 的双 DATA 包: %+v", v)
	}
	if len(v.Chunks) != 2 {
		t.Fatalf("应有两条逐块明细: %d", len(v.Chunks))
	}
	if v.Chunks[0].Decision != DecisionBuffered || !hasU32(v.Chunks[0].BufferAdded, 5000) {
		t.Fatalf("第 0 块(B片)应缓存: %+v", v.Chunks[0])
	}
	if v.Chunks[1].Decision != DecisionDelivered || !hasU32(v.Chunks[1].BufferAdded, 5001) ||
		!hasU32(v.Chunks[1].BufferRemoved, 5000) || !hasU32(v.Chunks[1].BufferRemoved, 5001) {
		t.Fatalf("第 1 块(E片)应交付并显示两片段进出缓存: %+v", v.Chunks[1])
	}
	if !hasU32(v.BufferAdded, 5000) || !hasU32(v.BufferAdded, 5001) ||
		!hasU32(v.BufferRemoved, 5000) || !hasU32(v.BufferRemoved, 5001) {
		t.Fatalf("顶层裁决应聚合缓存进出: +%v -%v", v.BufferAdded, v.BufferRemoved)
	}
	if len(s.Messages) != 1 || s.Messages[0].Hex != hex.EncodeToString([]byte("WEAK-LINK!")) ||
		len(s.Messages[0].TSNs) != 2 {
		t.Fatalf("应恰好交付一条拼接消息: %+v", s.Messages)
	}
	if s.CumTSN != 5001 || s.ExpectedSSN != 51 || len(s.Buffered) != 0 {
		t.Fatalf("累计 TSN/流序/缓存错误: %d/%d/%d", s.CumTSN, s.ExpectedSSN, len(s.Buffered))
	}
	// 字节完全相同的整包重传: 一个 duplicate 裁决, 消息数不变。
	v2 := s.Apply(dg)
	if v2.Decision != DecisionDuplicate || len(s.Verdicts) != 2 {
		t.Fatalf("整包重传应判 duplicate: %+v", v2)
	}
	if len(s.Messages) != 1 {
		t.Fatalf("整包重传不得增加消息数: %d", len(s.Messages))
	}
}

// DATA 后紧随合法 FORWARD-TSN(及后续可交付消息)在同一裁决中反映
// 跳过范围、残缺消息作废与随后交付。
func TestDataFollowedByForwardTSNInOneDatagram(t *testing.T) {
	s := NewSession("t-multi-fwd")
	dg := sctp.BuildDatagram(
		data(6000, 60, false, true, false, "AB"),  // B 片
		data(6002, 60, false, false, true, "EF"),  // E 片, 缺 6001
		data(6003, 61, false, true, true, "NEXT"), // 下一条完整消息, 等待流序
		fwd(6001, sctp.StreamPair{Stream: testStr, SSN: 60}),
	)
	v := s.Apply(dg)
	if len(s.Verdicts) != 1 {
		t.Fatalf("应只形成一个裁决: %d", len(s.Verdicts))
	}
	if v.Type != "MIXED" || v.ChunkCount != 4 {
		t.Fatalf("应为 MIXED 四块数据报: %s/%d", v.Type, v.ChunkCount)
	}
	last := v.Chunks[3]
	if last.Type != "FORWARD-TSN" || last.Decision != DecisionAccepted {
		t.Fatalf("末块应为 accepted FORWARD-TSN: %+v", last)
	}
	if len(v.SkippedAdded) != 1 || v.SkippedAdded[0].Start != 6001 || v.SkippedAdded[0].End != 6001 {
		t.Fatalf("应在同一裁决记录跳过范围 [6001,6001]: %+v", v.SkippedAdded)
	}
	if !hasU16(v.Abandoned, 60) {
		t.Fatalf("应在同一裁决作废残缺消息流序 60: %+v", v.Abandoned)
	}
	if len(s.Messages) != 1 || s.Messages[0].Hex != hex.EncodeToString([]byte("NEXT")) {
		t.Fatalf("残缺消息不交付, 随后消息交付一次: %+v", s.Messages)
	}
	if s.CumTSN != 6001 || s.ExpectedSSN != 62 || len(s.Buffered) != 0 {
		t.Fatalf("状态错误: cum=%d ssn=%d buf=%d", s.CumTSN, s.ExpectedSSN, len(s.Buffered))
	}
}

// 原子性(流标识非法): 首块正常、后续块流标识非法的复合数据报整体冻结拒绝,
// 不留下首块建立的关联、缓存或累计 TSN。
func TestCompoundRejectionIsAtomic(t *testing.T) {
	s := NewSession("t-multi-atomic")
	badStream := sctp.BuildData(testSrc, testDst, testTag, 7001, 99, 70, 0, false, true, true, []byte("X"))
	dg := sctp.BuildDatagram(
		data(7000, 70, false, true, true, "FIRST"),
		badStream,
	)
	v := s.Apply(dg)
	if v.Decision != DecisionRejected || v.RejectChunk == nil || *v.RejectChunk != 1 {
		t.Fatalf("应整体拒绝并指出第 1 块: %+v", v)
	}
	if s.Initialized || s.CumTSN != 0 || s.MaxTSN != 0 || len(s.Buffered) != 0 ||
		len(s.Seen) != 0 || len(s.Messages) != 0 {
		t.Fatalf("回滚不彻底, 首块状态泄漏: init=%v cum=%d max=%d buf=%d seen=%d msg=%d",
			s.Initialized, s.CumTSN, s.MaxTSN, len(s.Buffered), len(s.Seen), len(s.Messages))
	}
	// 拒绝后, 同一会话仍可用合法包建立关联(证明无残留)。
	v2 := s.Apply(data(7000, 70, false, true, true, "OK"))
	if v2.Decision != DecisionDelivered || !s.Initialized || s.CumTSN != 7000 || len(s.Messages) != 1 {
		t.Fatalf("原子回滚后应能正常建立关联: %+v", v2)
	}
}

// 原子性(交付回滚): 首块完整交付一条消息, 后续块非法时整包拒绝,
// 连首块的交付、流序推进与累计 TSN 一并回滚。
func TestCompoundRejectionRollsBackDelivery(t *testing.T) {
	s := NewSession("t-multi-rollback-deliver")
	uChunk := sctp.BuildData(testSrc, testDst, testTag, 8001, testStr, 81, 0, true, true, true, []byte("X"))
	dg := sctp.BuildDatagram(
		data(8000, 80, false, true, true, "FIRST"),
		uChunk,
	)
	v := s.Apply(dg)
	if v.Decision != DecisionRejected || v.RejectChunk == nil || *v.RejectChunk != 1 {
		t.Fatalf("应整体拒绝并指出第 1 块: %+v", v)
	}
	if s.Initialized || s.CumTSN != 0 || s.MaxTSN != 0 || s.ExpectedSSN != 0 ||
		len(s.Buffered) != 0 || len(s.Seen) != 0 || len(s.Messages) != 0 {
		t.Fatalf("回滚不彻底, 首块交付泄漏: init=%v cum=%d max=%d ssn=%d buf=%d seen=%d msg=%d",
			s.Initialized, s.CumTSN, s.MaxTSN, s.ExpectedSSN,
			len(s.Buffered), len(s.Seen), len(s.Messages))
	}
}

// 原子性(FORWARD-TSN 违规): 首块合法缓存, 后续 FORWARD-TSN 指向未受审流,
// 整包回滚, 不留跳过范围与累计 TSN 推进。
func TestCompoundForwardStreamViolationAtomic(t *testing.T) {
	s := NewSession("t-multi-fwd-atomic")
	dg := sctp.BuildDatagram(
		data(8100, 80, false, true, false, "AB"),
		fwd(8100, sctp.StreamPair{Stream: 99, SSN: 80}),
	)
	if v := s.Apply(dg); v.Decision != DecisionRejected {
		t.Fatalf("FORWARD-TSN 指向未受审流应整体拒绝: %+v", v)
	}
	if s.Initialized || len(s.Buffered) != 0 || s.CumTSN != 0 || len(s.Skipped) != 0 {
		t.Fatalf("回滚不彻底: init=%v buf=%d cum=%d skipped=%v",
			s.Initialized, len(s.Buffered), s.CumTSN, s.Skipped)
	}
}

// 冻结持久化: 复合数据报重新打开后逐包结果、缓存变化、跳过范围与消息列表一致。
func TestCompoundVerdictPersistence(t *testing.T) {
	dir := t.TempDir()
	st, _ := NewStore(dir)
	dg := sctp.BuildDatagram(
		data(9000, 90, false, true, false, "AB"),
		data(9002, 90, false, false, true, "EF"),
		fwd(9001, sctp.StreamPair{Stream: testStr, SSN: 90}),
	)
	if _, _, err := st.Submit("multi-persist", [][]byte{dg}); err != nil {
		t.Fatal(err)
	}
	first, _, _ := st.Get("multi-persist")
	want := viewJSON(t, first)
	st2, _ := NewStore(dir)
	got, ok, err := st2.Get("multi-persist")
	if err != nil || !ok {
		t.Fatalf("恢复失败: %v %v", ok, err)
	}
	if g := viewJSON(t, got); g != want {
		t.Fatalf("复合裁决恢复后不一致:\n%s\n%s", g, want)
	}
}
