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
	d, ok := p.Chunk.(*DataChunk)
	if !ok {
		t.Fatalf("块类型错误: %T", p.Chunk)
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
	f, ok := p.Chunk.(*ForwardTSNChunk)
	if !ok {
		t.Fatalf("块类型错误: %T", p.Chunk)
	}
	if f.NewCumTSN != 777 || len(f.Pairs) != 2 || f.Pairs[1].SSN != 21 {
		t.Fatalf("FORWARD-TSN 字段错误: %+v", f)
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
