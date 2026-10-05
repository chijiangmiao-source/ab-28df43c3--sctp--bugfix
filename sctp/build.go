package sctp

import "encoding/binary"

// 本文件提供构造合法 SCTP 报文的辅助函数, 供冒烟工具、单元测试与演示使用。

// BuildData 构造只含一个 DATA 块、带正确 CRC32C 的 SCTP 报文。
func BuildData(srcPort, dstPort uint16, verTag, tsn uint32, stream, ssn uint16, ppid uint32, u, b, e bool, data []byte) []byte {
	clen := 16 + len(data)
	padded := (clen + 3) &^ 3
	out := make([]byte, HeaderLen+padded)
	binary.BigEndian.PutUint16(out[0:2], srcPort)
	binary.BigEndian.PutUint16(out[2:4], dstPort)
	binary.BigEndian.PutUint32(out[4:8], verTag)
	var flags byte
	if u {
		flags |= FlagU
	}
	if b {
		flags |= FlagB
	}
	if e {
		flags |= FlagE
	}
	out[12] = ChunkData
	out[13] = flags
	binary.BigEndian.PutUint16(out[14:16], uint16(clen))
	binary.BigEndian.PutUint32(out[16:20], tsn)
	binary.BigEndian.PutUint16(out[20:22], stream)
	binary.BigEndian.PutUint16(out[22:24], ssn)
	binary.BigEndian.PutUint32(out[24:28], ppid)
	copy(out[28:], data)
	FixChecksum(out)
	return out
}

// BuildForwardTSN 构造只含一个 FORWARD-TSN 块、带正确 CRC32C 的 SCTP 报文。
func BuildForwardTSN(srcPort, dstPort uint16, verTag, newCum uint32, pairs ...StreamPair) []byte {
	clen := 8 + 4*len(pairs)
	padded := (clen + 3) &^ 3
	out := make([]byte, HeaderLen+padded)
	binary.BigEndian.PutUint16(out[0:2], srcPort)
	binary.BigEndian.PutUint16(out[2:4], dstPort)
	binary.BigEndian.PutUint32(out[4:8], verTag)
	out[12] = ChunkForwardTSN
	binary.BigEndian.PutUint16(out[14:16], uint16(clen))
	binary.BigEndian.PutUint32(out[16:20], newCum)
	off := 20
	for _, pr := range pairs {
		binary.BigEndian.PutUint16(out[off:off+2], pr.Stream)
		binary.BigEndian.PutUint16(out[off+2:off+4], pr.SSN)
		off += 4
	}
	FixChecksum(out)
	return out
}

// BuildDatagram 把多个单块报文(均由 BuildData / BuildForwardTSN 构造)按给定线序
// 合并为一个 SCTP 数据报: 共享公共头, 块依次排列(去除各自公共头), 重算 CRC32C。
// 用于复现弱链路捕获把同一关联的连续块装入一个数据报的情形。
func BuildDatagram(parts ...[]byte) []byte {
	if len(parts) == 0 {
		return nil
	}
	total := HeaderLen
	chunkBytes := make([][]byte, len(parts))
	for i, p := range parts {
		if len(p) < HeaderLen {
			panic("BuildDatagram: 分片短于公共头")
		}
		cb := append([]byte(nil), p[HeaderLen:]...)
		chunkBytes[i] = cb
		total += len(cb)
	}
	out := make([]byte, HeaderLen, total)
	copy(out, parts[0][:HeaderLen])
	for _, cb := range chunkBytes {
		out = append(out, cb...)
	}
	FixChecksum(out)
	return out
}

// FixChecksum 重算报文的 CRC32C 并以小端写回校验和字段。
func FixChecksum(packet []byte) {
	binary.LittleEndian.PutUint32(packet[8:12], Checksum(packet))
}
