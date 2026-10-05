package sctp

import (
	"encoding/binary"
	"hash/crc32"
	"testing"
)

func TestChecksumCastagnoliVector(t *testing.T) {
	// RFC 3720 附录 B.4 的 CRC32C 标准测试向量。
	if got := crc32.Checksum([]byte("123456789"), crc32.MakeTable(crc32.Castagnoli)); got != 0xE3069283 {
		t.Fatalf("CRC32C 测试向量失败: %08x", got)
	}
}

func TestParseDataRoundTrip(t *testing.T) {
	raw := BuildData(5000, 9, 0xAABBCCDD, 12345, 7, 3, 0, false, true, false, []byte("ping"))
	p, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse 失败: %v", err)
	}
	if p.SrcPort != 5000 || p.DstPort != 9 || p.VerTag != 0xAABBCCDD {
		t.Fatalf("公共头解析错误: %+v", p)
	}
	if len(p.Chunks) != 1 {
		t.Fatalf("块数应为 1: %d", len(p.Chunks))
	}
	d := p.Chunks[0].Data
	if d == nil {
		t.Fatalf("块类型错误: %+v", p.Chunks[0])
	}
	if d.TSN != 12345 || d.Stream != 7 || d.SSN != 3 || !d.B || d.E || d.U {
		t.Fatalf("DATA 字段错误: %+v", d)
	}
	if string(d.Data) != "ping" {
		t.Fatalf("用户数据错误: %q", d.Data)
	}
	// 校验和字段以小端存放且与计算值一致。
	if got := binary.LittleEndian.Uint32(raw[8:12]); got != Checksum(raw) {
		t.Fatalf("校验和字段 %08x 与计算值不一致", got)
	}
}

func TestParseForwardTSNRoundTrip(t *testing.T) {
	raw := BuildForwardTSN(5000, 9, 1, 777, StreamPair{Stream: 7, SSN: 20}, StreamPair{Stream: 7, SSN: 21})
	p, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse 失败: %v", err)
	}
	if len(p.Chunks) != 1 {
		t.Fatalf("块数应为 1: %d", len(p.Chunks))
	}
	f := p.Chunks[0].Forward
	if f == nil {
		t.Fatalf("块类型错误: %+v", p.Chunks[0])
	}
	if f.NewCumTSN != 777 || len(f.Pairs) != 2 || f.Pairs[1].SSN != 21 {
		t.Fatalf("FORWARD-TSN 字段错误: %+v", f)
	}
}

// 复合数据报: 同一公共头后按线序携带多个允许块, Parse 必须保留线序。
func TestParseBundledChunksInWireOrder(t *testing.T) {
	raw := BuildPacket(5000, 9, 0xAABBCCDD,
		ChunkSpec{Data: &DataSpec{TSN: 12345, Stream: 7, SSN: 3, B: true, Data: []byte("HELLO-")}},
		ChunkSpec{Data: &DataSpec{TSN: 12346, Stream: 7, SSN: 3, E: true, Data: []byte("WORLD!")}},
	)
	p, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse 失败: %v", err)
	}
	if len(p.Chunks) != 2 {
		t.Fatalf("应解析出 2 个块: %d", len(p.Chunks))
	}
	if p.Chunks[0].Data == nil || p.Chunks[0].Data.TSN != 12345 || !p.Chunks[0].Data.B ||
		string(p.Chunks[0].Data.Data) != "HELLO-" {
		t.Fatalf("首块(B片)解析错误: %+v", p.Chunks[0].Data)
	}
	if p.Chunks[1].Data == nil || p.Chunks[1].Data.TSN != 12346 || !p.Chunks[1].Data.E ||
		string(p.Chunks[1].Data.Data) != "WORLD!" {
		t.Fatalf("次块(E片)解析错误: %+v", p.Chunks[1].Data)
	}

	// DATA 后紧随 FORWARD-TSN。
	fwd := BuildPacket(5000, 9, 0xAABBCCDD,
		ChunkSpec{Data: &DataSpec{TSN: 77, Stream: 7, SSN: 1, B: true, Data: []byte("x")}},
		ChunkSpec{Forward: &ForwardTSNChunk{NewCumTSN: 80, Pairs: []StreamPair{{Stream: 7, SSN: 1}}}},
	)
	p2, err := Parse(fwd)
	if err != nil {
		t.Fatalf("DATA+FORWARD-TSN 复合数据报解析失败: %v", err)
	}
	if len(p2.Chunks) != 2 || p2.Chunks[0].Data == nil || p2.Chunks[1].Forward == nil ||
		p2.Chunks[1].Forward.NewCumTSN != 80 {
		t.Fatalf("DATA+FORWARD-TSN 线序解析错误: %+v", p2.Chunks)
	}
}

// 复合数据报中任一后续块类型非法或截断, 整包解析失败(交由上层整体冻结拒绝)。
func TestParseBundledRejectsInvalidLaterChunk(t *testing.T) {
	// 首块合法 DATA, 次块为不支持的 SACK(类型 3)。
	raw := BuildPacket(5000, 9, 1,
		ChunkSpec{Data: &DataSpec{TSN: 100, Stream: 7, SSN: 1, B: true, E: true, Data: []byte("x")}},
		ChunkSpec{Forward: &ForwardTSNChunk{NewCumTSN: 100}},
	)
	// 手工把第二块(FORWARD-TSN)改成 SACK, 结构保持完整, 再修正 CRC32C。
	off := HeaderLen
	firstLen := int(binary.BigEndian.Uint16(raw[off+2 : off+4]))
	off += (firstLen + 3) &^ 3
	raw[off] = 3
	FixChecksum(raw)
	if _, err := Parse(raw); err == nil {
		t.Fatal("后续块为不支持的类型时整包必须解析失败")
	}

	// 首块合法但第二块声明长度超出报文 → 截断, 整包失败。
	good := BuildData(5000, 9, 1, 100, 7, 1, 0, false, true, true, []byte("x"))
	truncated := append([]byte(nil), good...)
	truncated = append(truncated, ChunkData, 0, 0, 20, 0, 0, 0, 101) // 声明 20 字节, 实给 8
	FixChecksum(truncated)
	if _, err := Parse(truncated); err == nil {
		t.Fatal("后续块截断时整包必须解析失败")
	}
}

func TestParseRejectsCorruptedChecksum(t *testing.T) {
	raw := BuildData(5000, 9, 1, 100, 7, 1, 0, false, true, true, []byte("x"))
	raw[len(raw)-1] ^= 0xFF // 破坏用户数据, CRC32C 必然失配
	if _, err := Parse(raw); err == nil {
		t.Fatal("CRC32C 损坏的报文未被拒绝")
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	cases := map[string][]byte{
		"过短": make([]byte, 15),
		"空":  {},
	}
	for name, raw := range cases {
		if _, err := Parse(raw); err == nil {
			t.Fatalf("%s: 未被拒绝", name)
		}
	}
	// 尾部垃圾(重算校验和后应命中长度不一致)。
	raw := BuildData(5000, 9, 1, 100, 7, 1, 0, false, true, true, []byte("x"))
	raw = append(raw, 0)
	FixChecksum(raw)
	if _, err := Parse(raw); err == nil {
		t.Fatal("尾部垃圾: 未被拒绝")
	}
	// 不支持的块类型(SACK=3)。
	raw = BuildData(5000, 9, 1, 100, 7, 1, 0, false, true, true, []byte("x"))
	raw[12] = 3
	FixChecksum(raw)
	if _, err := Parse(raw); err == nil {
		t.Fatal("不支持的块类型未被拒绝")
	}
	// 无用户数据的 DATA 块。
	raw = BuildData(5000, 9, 1, 100, 7, 1, 0, false, true, true, []byte("x"))
	binary.BigEndian.PutUint16(raw[14:16], 16)
	raw = raw[:28]
	FixChecksum(raw)
	if _, err := Parse(raw); err == nil {
		t.Fatal("空用户数据 DATA 未被拒绝")
	}
}
