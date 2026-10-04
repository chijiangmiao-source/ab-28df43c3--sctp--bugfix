// Package sctp 实现审计台所需的最小 SCTP 报文检查能力:
// 公共头解析、CRC32C(Castagnoli)校验, 以及 DATA 与 FORWARD-TSN 块的解析。
// 系统仅审查单关联、单个有序流中的 DATA 与 FORWARD-TSN, 其他块类型一律拒绝。
package sctp

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
)

const (
	// ChunkData 是 DATA 块类型(RFC 4960 §3.3.1)。
	ChunkData = 0
	// ChunkForwardTSN 是 FORWARD-TSN 块类型(RFC 3758 §3.5)。
	ChunkForwardTSN = 192

	// FlagU 表示无序(Unordered)投递。
	FlagU = 0x04
	// FlagB 表示消息首片(Beginning)。
	FlagB = 0x02
	// FlagE 表示消息尾片(End)。
	FlagE = 0x01

	// HeaderLen 是 SCTP 公共头长度。
	HeaderLen = 12
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// Checksum 计算整个 SCTP 报文的 CRC32C, 计算时校验和字段按 0 处理。
// SCTP 校验和在报文中以小端存放(RFC 3309 / RFC 4960 附录 B)。
func Checksum(packet []byte) uint32 {
	h := crc32.New(castagnoli)
	h.Write(packet[:8])
	h.Write([]byte{0, 0, 0, 0})
	if len(packet) > HeaderLen {
		h.Write(packet[HeaderLen:])
	}
	return h.Sum32()
}

// Packet 是一个通过公共头与 CRC32C 校验的 SCTP 报文。
type Packet struct {
	SrcPort  uint16
	DstPort  uint16
	VerTag   uint32
	Checksum uint32 // 报文中携带的校验和(小端)
	Chunk    any    // *DataChunk 或 *ForwardTSNChunk
}

// DataChunk 是 DATA 块(RFC 4960 §3.3.1)。
type DataChunk struct {
	TSN    uint32
	Stream uint16
	SSN    uint16
	PPID   uint32
	U      bool
	B      bool
	E      bool
	Data   []byte
}

// StreamPair 是 FORWARD-TSN 中的 (流标识, 流序号) 对。
type StreamPair struct {
	Stream uint16
	SSN    uint16
}

// ForwardTSNChunk 是 FORWARD-TSN 块(RFC 3758 §3.5)。
type ForwardTSNChunk struct {
	NewCumTSN uint32
	Pairs     []StreamPair
}

// Parse 校验公共头与 CRC32C, 并解析唯一的 DATA 或 FORWARD-TSN 块。
// 任何格式错误、校验失败或不支持的块类型都返回错误(由上层冻结拒绝)。
func Parse(raw []byte) (*Packet, error) {
	if len(raw) < HeaderLen+4 {
		return nil, fmt.Errorf("报文过短: %d 字节, 不足公共头加块头", len(raw))
	}
	p := &Packet{
		SrcPort:  binary.BigEndian.Uint16(raw[0:2]),
		DstPort:  binary.BigEndian.Uint16(raw[2:4]),
		VerTag:   binary.BigEndian.Uint32(raw[4:8]),
		Checksum: binary.LittleEndian.Uint32(raw[8:12]),
	}
	if got := Checksum(raw); got != p.Checksum {
		return nil, fmt.Errorf("CRC32C 校验失败: 报文携带 %08x, 实算 %08x", p.Checksum, got)
	}
	ctype := raw[12]
	flags := raw[13]
	clen := int(binary.BigEndian.Uint16(raw[14:16]))
	if clen < 4 {
		return nil, fmt.Errorf("块长度非法: %d", clen)
	}
	padded := (clen + 3) &^ 3
	firstEnd := HeaderLen + padded
	if firstEnd > len(raw) {
		return nil, fmt.Errorf("报文长度 %d 小于首块长度 %d(填充后 %d)", len(raw), clen, firstEnd)
	}
	for off := firstEnd; off < len(raw); {
		if len(raw)-off < 4 {
			return nil, fmt.Errorf("后续块头截断: 偏移 %d", off)
		}
		extraLen := int(binary.BigEndian.Uint16(raw[off+2 : off+4]))
		if extraLen < 4 {
			return nil, fmt.Errorf("后续块长度非法: 偏移 %d 长度 %d", off, extraLen)
		}
		extraPadded := (extraLen + 3) &^ 3
		if extraPadded > len(raw)-off {
			return nil, fmt.Errorf("后续块截断: 偏移 %d 长度 %d", off, extraLen)
		}
		off += extraPadded
	}
	body := raw[16 : HeaderLen+clen]
	switch ctype {
	case ChunkData:
		if clen < 17 {
			return nil, fmt.Errorf("DATA 块长度 %d 不足: 缺少用户数据", clen)
		}
		d := &DataChunk{
			TSN:    binary.BigEndian.Uint32(body[0:4]),
			Stream: binary.BigEndian.Uint16(body[4:6]),
			SSN:    binary.BigEndian.Uint16(body[6:8]),
			PPID:   binary.BigEndian.Uint32(body[8:12]),
			U:      flags&FlagU != 0,
			B:      flags&FlagB != 0,
			E:      flags&FlagE != 0,
			Data:   append([]byte(nil), body[12:]...),
		}
		p.Chunk = d
	case ChunkForwardTSN:
		if clen < 8 || (clen-8)%4 != 0 {
			return nil, fmt.Errorf("FORWARD-TSN 块长度非法: %d", clen)
		}
		f := &ForwardTSNChunk{NewCumTSN: binary.BigEndian.Uint32(body[0:4])}
		for off := 4; off+4 <= len(body); off += 4 {
			f.Pairs = append(f.Pairs, StreamPair{
				Stream: binary.BigEndian.Uint16(body[off : off+2]),
				SSN:    binary.BigEndian.Uint16(body[off+2 : off+4]),
			})
		}
		p.Chunk = f
	default:
		return nil, fmt.Errorf("不支持的块类型 %d: 仅审查 DATA 与 FORWARD-TSN", ctype)
	}
	return p, nil
}
