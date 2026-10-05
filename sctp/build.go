package sctp

import "encoding/binary"

// 本文件提供构造合法 SCTP 报文的辅助函数, 供冒烟工具、单元测试与演示使用。

// DataSpec 描述复合数据报中的一个 DATA 块。
type DataSpec struct {
	TSN    uint32
	Stream uint16
	SSN    uint16
	PPID   uint32
	U      bool
	B      bool
	E      bool
	Data   []byte
}

// ChunkSpec 描述复合数据报中的一个块: Data 与 Forward 中恰有一个非 nil。
type ChunkSpec struct {
	Data    *DataSpec
	Forward *ForwardTSNChunk
}

// BuildData 构造只含一个 DATA 块、带正确 CRC32C 的 SCTP 报文。
func BuildData(srcPort, dstPort uint16, verTag, tsn uint32, stream, ssn uint16, ppid uint32, u, b, e bool, data []byte) []byte {
	return BuildPacket(srcPort, dstPort, verTag, ChunkSpec{Data: &DataSpec{
		TSN: tsn, Stream: stream, SSN: ssn, PPID: ppid, U: u, B: b, E: e, Data: data,
	}})
}

// BuildForwardTSN 构造只含一个 FORWARD-TSN 块、带正确 CRC32C 的 SCTP 报文。
func BuildForwardTSN(srcPort, dstPort uint16, verTag, newCum uint32, pairs ...StreamPair) []byte {
	return BuildPacket(srcPort, dstPort, verTag, ChunkSpec{Forward: &ForwardTSNChunk{NewCumTSN: newCum, Pairs: pairs}})
}

// BuildPacket 构造一个公共头之后按给定线序携带多个块、带正确 CRC32C 的 SCTP 报文。
// 弱链路捕获可能把同一关联、同一有序流的连续 DATA(或 DATA 后紧随 FORWARD-TSN)
// 装入同一个数据报。
func BuildPacket(srcPort, dstPort uint16, verTag uint32, specs ...ChunkSpec) []byte {
	if len(specs) == 0 {
		panic("sctp.BuildPacket: 至少需要一个块")
	}
	chunks := make([][]byte, len(specs))
	total := HeaderLen
	for i, sp := range specs {
		var chunk []byte
		switch {
		case sp.Data != nil:
			d := sp.Data
			clen := 16 + len(d.Data)
			padded := (clen + 3) &^ 3
			chunk = make([]byte, padded)
			var flags byte
			if d.U {
				flags |= FlagU
			}
			if d.B {
				flags |= FlagB
			}
			if d.E {
				flags |= FlagE
			}
			chunk[0] = ChunkData
			chunk[1] = flags
			binary.BigEndian.PutUint16(chunk[2:4], uint16(clen))
			binary.BigEndian.PutUint32(chunk[4:8], d.TSN)
			binary.BigEndian.PutUint16(chunk[8:10], d.Stream)
			binary.BigEndian.PutUint16(chunk[10:12], d.SSN)
			binary.BigEndian.PutUint32(chunk[12:16], d.PPID)
			copy(chunk[16:], d.Data)
		case sp.Forward != nil:
			f := sp.Forward
			clen := 8 + 4*len(f.Pairs)
			padded := (clen + 3) &^ 3
			chunk = make([]byte, padded)
			chunk[0] = ChunkForwardTSN
			binary.BigEndian.PutUint16(chunk[2:4], uint16(clen))
			binary.BigEndian.PutUint32(chunk[4:8], f.NewCumTSN)
			off := 8
			for _, pr := range f.Pairs {
				binary.BigEndian.PutUint16(chunk[off:off+2], pr.Stream)
				binary.BigEndian.PutUint16(chunk[off+2:off+4], pr.SSN)
				off += 4
			}
		default:
			panic("sctp.BuildPacket: 空块说明")
		}
		chunks[i] = chunk
		total += len(chunk)
	}
	out := make([]byte, HeaderLen, total)
	binary.BigEndian.PutUint16(out[0:2], srcPort)
	binary.BigEndian.PutUint16(out[2:4], dstPort)
	binary.BigEndian.PutUint32(out[4:8], verTag)
	for _, chunk := range chunks {
		out = append(out, chunk...)
	}
	FixChecksum(out)
	return out
}

// FixChecksum 重算报文的 CRC32C 并以小端写回校验和字段。
func FixChecksum(packet []byte) {
	binary.LittleEndian.PutUint32(packet[8:12], Checksum(packet))
}
