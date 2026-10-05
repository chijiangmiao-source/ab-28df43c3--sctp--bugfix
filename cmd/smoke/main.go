// 冒烟工具: 对运行中的审计台执行验收场景的 API/HTTP 检查, 以退出码报告结果。
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"sctpaudit/audit"
	"sctpaudit/sctp"
)

var (
	addr     = flag.String("addr", "http://localhost:8080", "审计台基础地址")
	failures int
)

func check(ok bool, format string, args ...any) {
	if ok {
		fmt.Printf("  PASS "+format+"\n", args...)
	} else {
		failures++
		fmt.Printf("  FAIL "+format+"\n", args...)
	}
}

func b64(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }

func get(path string) (int, []byte) {
	resp, err := http.Get(*addr + path)
	if err != nil {
		return -1, []byte(err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

func post(id string, raws ...[]byte) (int, *audit.View, []byte) {
	packets := make([]string, len(raws))
	for i, r := range raws {
		packets[i] = b64(r)
	}
	reqBody, _ := json.Marshal(map[string]any{"packets": packets})
	resp, err := http.Post(*addr+"/api/audits/"+id+"/packets", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return -1, nil, []byte(err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	v := &audit.View{}
	_ = json.Unmarshal(body, v)
	return resp.StatusCode, v, body
}

func getView(id string) (int, *audit.View) {
	status, body := get("/api/audits/" + id)
	v := &audit.View{}
	_ = json.Unmarshal(body, v)
	return status, v
}

// frozenJSON 提取逐包裁决与消息列表的 JSON, 用于一致性比较。
func frozenJSON(v *audit.View) string {
	data, _ := json.Marshal(struct {
		Verdicts []audit.Verdict `json:"verdicts"`
		Messages []audit.Message `json:"messages"`
	}{v.Verdicts, v.Messages})
	return string(data)
}

func containsUint32(a []uint32, x uint32) bool {
	for _, v := range a {
		if v == x {
			return true
		}
	}
	return false
}

func containsUint16(a []uint16, x uint16) bool {
	for _, v := range a {
		if v == x {
			return true
		}
	}
	return false
}

const (
	srcPort = 5000
	dstPort = 9
	verTag  = 0x01020304
	stream  = 7
)

func data(tsn uint32, ssn uint16, u, b, e bool, payload string) []byte {
	return sctp.BuildData(srcPort, dstPort, verTag, tsn, stream, ssn, 0, u, b, e, []byte(payload))
}

// datagram 把多个单块报文合并为一个共享公共头的复合 SCTP 数据报。
func datagram(parts ...[]byte) []byte {
	return sctp.BuildDatagram(parts...)
}

func main() {
	flag.Parse()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	fmt.Println("== 冒烟: 健康响应与操作页 ==")
	status, body := get("/health")
	var health struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(body, &health)
	check(status == 200 && health.Status == "ok", "GET /health 返回 200 且 status ok (实际 %d %s)", status, bytes.TrimSpace(body))
	status, body = get("/")
	check(status == 200 && bytes.Contains(body, []byte("审计")), "GET / 返回操作页 (实际 %d)", status)
	status, _ = get("/api/audits/unknown-" + suffix)
	check(status == 404, "未知审计标识返回 404 (实际 %d)", status)

	fmt.Println("== 场景 A: 乱序互补 DATA 仅交付一次, 重传/冲突/越界/非法流序 ==")
	idA := "smoke-a-" + suffix
	d1 := data(1000, 10, false, true, false, "HELLO-")
	d2 := data(1001, 10, false, false, true, "WORLD!")
	wantHex := hex.EncodeToString([]byte("HELLO-WORLD!"))

	status, va, _ := post(idA, d2, d1)
	check(status == 200, "提交乱序分片 [E,B] 返回 200 (实际 %d)", status)
	check(va.PacketCount == 2 && len(va.Verdicts) == 2, "裁决数为 2 (实际 %d)", va.PacketCount)
	if len(va.Verdicts) == 2 {
		check(va.Verdicts[0].Decision == "buffered" && containsUint32(va.Verdicts[0].BufferAdded, 1001),
			"包0(E片) 缓存, 缓存+ 含 1001 (实际 %s %+v)", va.Verdicts[0].Decision, va.Verdicts[0].BufferAdded)
		check(va.Verdicts[1].Decision == "delivered" && containsUint32(va.Verdicts[1].BufferAdded, 1000) &&
			containsUint32(va.Verdicts[1].BufferRemoved, 1000) && containsUint32(va.Verdicts[1].BufferRemoved, 1001),
			"包1(B片) 交付, 缓存变化 +1000 -1000,-1001 (实际 %s +%v -%v)",
			va.Verdicts[1].Decision, va.Verdicts[1].BufferAdded, va.Verdicts[1].BufferRemoved)
	}
	check(len(va.Messages) == 1 && va.Messages[0].Hex == wantHex,
		"恰好交付一条完整消息 %q (实际 %d 条)", "HELLO-WORLD!", len(va.Messages))
	check(va.State.CumTSN == 1001 && va.State.ExpectedSSN == 11, "累计 TSN=1001, 期望流序=11 (实际 %d/%d)", va.State.CumTSN, va.State.ExpectedSSN)
	frozenA := frozenJSON(va)

	status, va2, _ := post(idA, d2, d1)
	check(status == 200 && frozenJSON(va2) == frozenA, "同一标识重复提交同批包: 裁决与消息列表完全一致")

	status, va3, _ := post(idA, d2, d1, d1)
	check(status == 200 && len(va3.Verdicts) == 3 && va3.Verdicts[2].Decision == "duplicate" && len(va3.Messages) == 1,
		"字节完全相同的 DATA 重传判为 duplicate 且不增加消息数 (实际 %v/%d)",
		va3.Verdicts[len(va3.Verdicts)-1].Decision, len(va3.Messages))

	d1x := data(1000, 10, false, true, false, "XXXXXX")
	status, va4, _ := post(idA, d2, d1, d1, d1x)
	conflictOK := status == 200 && len(va4.Verdicts) == 4 && va4.Verdicts[3].Decision == "rejected" &&
		va4.Verdicts[3].Evidence != nil && va4.Verdicts[3].Evidence.FirstBytesHex == hex.EncodeToString([]byte("HELLO-"))
	check(conflictOK, "同一 TSN 不同字节被冻结拒绝并稳定显示首个原始字节依据")
	check(len(va4.Messages) == 1 && va4.State.CumTSN == 1001, "冲突拒绝后状态不变 (消息 %d, 累计 TSN %d)", len(va4.Messages), va4.State.CumTSN)

	fwdOOB := sctp.BuildForwardTSN(srcPort, dstPort, verTag, 5000)
	status, va5, _ := post(idA, d2, d1, d1, d1x, fwdOOB)
	check(status == 200 && len(va5.Verdicts) == 5 && va5.Verdicts[4].Decision == "rejected",
		"越界跳过(新累计 TSN 超出已观测范围)被冻结拒绝 (实际 %v)", va5.Verdicts[len(va5.Verdicts)-1].Decision)
	check(len(va5.State.Skipped) == 0, "越界跳过被拒绝后无跳过范围 (实际 %+v)", va5.State.Skipped)

	du := data(1002, 11, true, true, true, "Z")
	status, va6, _ := post(idA, d2, d1, d1, d1x, fwdOOB, du)
	check(status == 200 && len(va6.Verdicts) == 6 && va6.Verdicts[5].Decision == "rejected",
		"无序(U)DATA 非法流序被冻结拒绝 (实际 %v)", va6.Verdicts[len(va6.Verdicts)-1].Decision)

	status, vaGet := getView(idA)
	check(status == 200 && frozenJSON(vaGet) == frozenJSON(va6),
		"重新读取同一审计标识: 逐包裁决和消息列表与首次一致")

	fmt.Println("== 场景 B: 缺失片段被合法 FORWARD-TSN 跨越, 补交旧片不改变结论 ==")
	idB := "smoke-b-" + suffix
	g1 := data(2000, 20, false, true, false, "AB")
	g3 := data(2002, 20, false, false, true, "EF")
	status, vb, _ := post(idB, g1, g3)
	check(status == 200 && len(vb.Verdicts) == 2 &&
		vb.Verdicts[0].Decision == "buffered" && vb.Verdicts[1].Decision == "buffered",
		"缺失中间片的两个分片均被缓存 (实际 %v/%v)", vb.Verdicts[0].Decision, vb.Verdicts[1].Decision)
	check(vb.State.CumTSN == 2000 && len(vb.Messages) == 0, "存在缺口, 累计 TSN 停在 2000, 无交付 (实际 %d/%d)", vb.State.CumTSN, len(vb.Messages))

	fwd := sctp.BuildForwardTSN(srcPort, dstPort, verTag, 2001, sctp.StreamPair{Stream: stream, SSN: 20})
	status, vb2, _ := post(idB, g1, g3, fwd)
	v2 := vb2.Verdicts[2]
	check(status == 200 && v2.Decision == "accepted", "合法 FORWARD-TSN 被接受 (实际 %v)", v2.Decision)
	check(len(v2.SkippedAdded) == 1 && v2.SkippedAdded[0].Start == 2001 && v2.SkippedAdded[0].End == 2001,
		"记录跳过范围 [2001,2001] (实际 %+v)", v2.SkippedAdded)
	check(containsUint32(v2.BufferRemoved, 2000) && containsUint32(v2.BufferRemoved, 2002) && containsUint16(v2.Abandoned, 20),
		"被跨越的残缺消息作废并移出缓存 (移除 %v, 作废 %v)", v2.BufferRemoved, v2.Abandoned)
	check(len(vb2.Messages) == 0 && len(vb2.State.Buffered) == 0 && vb2.State.ExpectedSSN == 21,
		"不交付残缺消息, 缓存清空, 期望流序推进到 21 (实际 %d/%d/%d)", len(vb2.Messages), len(vb2.State.Buffered), vb2.State.ExpectedSSN)

	g2 := data(2001, 20, false, false, false, "CD")
	status, vb3, _ := post(idB, g1, g3, fwd, g2)
	check(status == 200 && vb3.Verdicts[3].Decision == "stale",
		"补交被跨越的旧片段判为 stale (实际 %v)", vb3.Verdicts[3].Decision)
	check(len(vb3.Messages) == 0 && len(vb3.State.Buffered) == 0 &&
		len(vb3.State.Skipped) == 1 && vb3.State.Skipped[0].Start == 2001,
		"补交旧片不改变结论: 仍无交付、缓存为空、跳过范围不变")
	status, vbGet := getView(idB)
	check(status == 200 && frozenJSON(vbGet) == frozenJSON(vb3), "重新读取审计 B: 裁决与消息列表一致")

	fmt.Println("== 场景 C: 提交冲突与参数校验 ==")
	idC := "smoke-c-" + suffix
	p0 := data(3000, 30, false, true, true, "ONE")
	status, _, _ = post(idC, p0)
	check(status == 200, "提交首包返回 200 (实际 %d)", status)
	p0mod := data(3000, 30, false, true, true, "TWO")
	status, _, body = post(idC, p0mod)
	var apiErr struct {
		Conflict *audit.Conflict `json:"conflict"`
	}
	_ = json.Unmarshal(body, &apiErr)
	check(status == 409 && apiErr.Conflict != nil && apiErr.Conflict.Index == 0 &&
		apiErr.Conflict.FrozenFirstBytesHex == hex.EncodeToString(p0[:16]),
		"同一捕获位置的不同字节返回 409 并给出已冻结首个原始字节 (实际 %d)", status)
	many := make([][]byte, 33)
	for i := range many {
		many[i] = data(4000+uint32(i), 40, false, true, true, "x")
	}
	status, _, _ = post(idC, many...)
	check(status == 400, "超过 32 个包返回 400 (实际 %d)", status)
	status, _, body = postRaw(idC, `{"packets":["!!!not-base64!!!"]}`)
	check(status == 400, "非法 Base64 返回 400 (实际 %d)", status)

	fmt.Println("== 场景 D: 一个数据报内连续 B/E DATA 只形成一个裁决并交付一次 ==")
	idD := "smoke-d-" + suffix
	dB := data(7000, 40, false, true, false, "WEAK-")
	dE := data(7001, 40, false, false, true, "LINK!")
	dgBE := datagram(dB, dE)
	status, vd, _ := post(idD, dgBE)
	check(status == 200, "提交双 DATA 数据报返回 200 (实际 %d)", status)
	check(vd.PacketCount == 1 && len(vd.Verdicts) == 1,
		"只形成一个原始包裁决 (实际 %d 个)", vd.PacketCount)
	if len(vd.Verdicts) == 1 {
		v0 := vd.Verdicts[0]
		check(v0.Decision == "delivered" && v0.ChunkCount == 2,
			"裁决 delivered, 含 2 块 (实际 %s/%d)", v0.Decision, v0.ChunkCount)
		check(len(v0.Chunks) == 2 && v0.Chunks[0].Decision == "buffered" &&
			containsUint32(v0.Chunks[0].BufferAdded, 7000),
			"第0块(B片) buffered, 缓存+ 7000 (实际 %s +%v)", v0.Chunks[0].Decision, v0.Chunks[0].BufferAdded)
		check(v0.Chunks[1].Decision == "delivered" &&
			containsUint32(v0.Chunks[1].BufferAdded, 7001) &&
			containsUint32(v0.Chunks[1].BufferRemoved, 7000) &&
			containsUint32(v0.Chunks[1].BufferRemoved, 7001),
			"第1块(E片) delivered, 两个分片缓存进出 (实际 %s +%v -%v)",
			v0.Chunks[1].Decision, v0.Chunks[1].BufferAdded, v0.Chunks[1].BufferRemoved)
		check(containsUint32(v0.BufferAdded, 7000) && containsUint32(v0.BufferAdded, 7001) &&
			containsUint32(v0.BufferRemoved, 7000) && containsUint32(v0.BufferRemoved, 7001),
			"顶层聚合两个分片的缓存进出 (+%v -%v)", v0.BufferAdded, v0.BufferRemoved)
	}
	check(len(vd.Messages) == 1 && vd.Messages[0].Hex == hex.EncodeToString([]byte("WEAK-LINK!")),
		"恰好交付一次拼接消息 %q (实际 %d 条)", "WEAK-LINK!", len(vd.Messages))
	check(vd.State.CumTSN == 7001 && vd.State.ExpectedSSN == 41 && len(vd.State.Buffered) == 0,
		"累计 TSN=7001, 期望流序=41, 缓存空 (实际 %d/%d/%d)",
		vd.State.CumTSN, vd.State.ExpectedSSN, len(vd.State.Buffered))

	// 字节完全相同的整包重传(新捕获位置): duplicate, 不增加消息数。
	status, vd2, _ := post(idD, dgBE, dgBE)
	check(status == 200 && len(vd2.Verdicts) == 2 && vd2.Verdicts[1].Decision == "duplicate" &&
		len(vd2.Messages) == 1,
		"字节完全相同的整包重传 duplicate 且不增加消息数 (实际 %d 裁决/%d 消息)",
		len(vd2.Verdicts), len(vd2.Messages))
	// 按标识重读: 逐包结果、缓存变化、跳过范围和消息列表与首次一致(逐字节)。
	status, vd3 := getView(idD)
	check(status == 200 && len(vd3.Verdicts) == 2 && frozenJSON(vd3) == frozenJSON(vd2) &&
		len(vd3.Messages) == 1,
		"重新读取审计 D: 逐包裁决与消息列表与首次一致")
	check(vd3.State.CumTSN == 7001 && len(vd3.State.Buffered) == 0 &&
		len(vd3.State.Skipped) == 0,
		"重读审计 D: 缓存与跳过范围与首次一致")

	fmt.Println("== 场景 E: DATA 后紧随合法 FORWARD-TSN, 同一裁决反映跳过/作废/交付 ==")
	idE := "smoke-e-" + suffix
	eB := data(8000, 50, false, true, false, "AB")
	eE := data(8002, 50, false, false, true, "EF")
	eN := data(8003, 51, false, true, true, "NEXT")
	eFwd := sctp.BuildForwardTSN(srcPort, dstPort, verTag, 8001, sctp.StreamPair{Stream: stream, SSN: 50})
	dgFwd := datagram(eB, eE, eN, eFwd)
	status, ve, _ := post(idE, dgFwd)
	check(status == 200 && ve.PacketCount == 1 && len(ve.Verdicts) == 1,
		"四块复合数据报只形成一个裁决 (实际 %d)", ve.PacketCount)
	if len(ve.Verdicts) == 1 {
		v0 := ve.Verdicts[0]
		check(v0.Type == "MIXED" && v0.ChunkCount == 4,
			"类型 MIXED, 4 块 (实际 %s/%d)", v0.Type, v0.ChunkCount)
		check(v0.Chunks[3].Decision == "accepted",
			"末块 FORWARD-TSN accepted (实际 %s)", v0.Chunks[3].Decision)
		check(len(v0.SkippedAdded) == 1 && v0.SkippedAdded[0].Start == 8001 && v0.SkippedAdded[0].End == 8001,
			"同一裁决记录跳过范围 [8001,8001] (实际 %+v)", v0.SkippedAdded)
		check(containsUint16(v0.Abandoned, 50),
			"同一裁决作废流序 50 (实际 %+v)", v0.Abandoned)
		check(len(v0.Delivered) == 1 && v0.Delivered[0].Hex == hex.EncodeToString([]byte("NEXT")),
			"同一裁决交付随后完整消息 NEXT (实际 %+v)", v0.Delivered)
	}
	check(len(ve.Messages) == 1 && ve.Messages[0].Hex == hex.EncodeToString([]byte("NEXT")),
		"残缺消息不交付, 随后消息恰好一次 (实际 %d 条)", len(ve.Messages))
	check(ve.State.CumTSN == 8001 && ve.State.ExpectedSSN == 52 && len(ve.State.Buffered) == 0 &&
		len(ve.State.Skipped) == 1,
		"累计 TSN=8001, 流序=52, 缓存空, 跳过 1 段 (实际 %d/%d/%d/%d)",
		ve.State.CumTSN, ve.State.ExpectedSSN, len(ve.State.Buffered), len(ve.State.Skipped))
	status, ve2 := getView(idE)
	check(status == 200 && frozenJSON(ve2) == frozenJSON(ve) &&
		len(ve2.State.Skipped) == 1 && ve2.State.Skipped[0].Start == 8001,
		"重读审计 E: 逐包裁决、跳过范围与消息列表一致")

	fmt.Println("== 场景 F: 后续块违规的复合数据报整体冻结拒绝(原子性) ==")
	idF := "smoke-f-" + suffix
	fFirst := data(9000, 60, false, true, true, "FIRST")
	fBad := sctp.BuildData(srcPort, dstPort, verTag, 9001, 99, 60, 0, false, true, true, []byte("X"))
	dgBad := datagram(fFirst, fBad)
	status, vf, _ := post(idF, dgBad)
	check(status == 200 && vf.PacketCount == 1 && vf.Verdicts[0].Decision == "rejected" &&
		vf.Verdicts[0].RejectChunk != nil && *vf.Verdicts[0].RejectChunk == 1,
		"首块正常后续流标识非法: 整包 rejected, rejectChunk=1 (实际 %d/%s)",
		vf.PacketCount, vf.Verdicts[0].Decision)
	check(!vf.State.Initialized && vf.State.CumTSN == 0 && vf.State.MaxTSN == 0 &&
		len(vf.State.Buffered) == 0,
		"不留下关联、缓存或累计 TSN (init=%v cum=%d max=%d buf=%d)",
		vf.State.Initialized, vf.State.CumTSN, vf.State.MaxTSN, len(vf.State.Buffered))
	// 冻结会话中: 原包在新捕获位置的字节相同重放判 duplicate;
	// 再来一个"首块合法、后续块非法"的新复合包(新 TSN), 仍须整体拒绝。
	fFirst2 := data(9010, 61, false, true, true, "SECOND")
	fBad2 := sctp.BuildData(srcPort, dstPort, verTag, 9011, 99, 61, 0, false, true, true, []byte("Y"))
	dgBad2 := datagram(fFirst2, fBad2)
	status, vf2, _ := post(idF, dgBad, dgBad, dgBad2)
	check(status == 200 && len(vf2.Verdicts) == 3 &&
		vf2.Verdicts[1].Decision == "duplicate" &&
		vf2.Verdicts[2].Decision == "rejected" &&
		vf2.Verdicts[2].RejectChunk != nil && *vf2.Verdicts[2].RejectChunk == 1 &&
		!vf2.State.Initialized && len(vf2.Messages) == 0,
		"原包重放 duplicate、新复合违规包 rejected, 均不建立关联/缓存/消息 (实际 %s/%s init=%v)",
		vf2.Verdicts[1].Decision, vf2.Verdicts[2].Decision, vf2.State.Initialized)
	// 按标识重新打开冻结记录: 逐包结果、缓存变化、跳过范围和消息列表与首次一致。
	status, vfGet := getView(idF)
	check(status == 200 && frozenJSON(vfGet) == frozenJSON(vf2),
		"重新读取审计 F: 逐包裁决与消息列表一致")
	check(!vfGet.State.Initialized && vfGet.State.CumTSN == 0 &&
		len(vfGet.State.Buffered) == 0 && len(vfGet.State.Skipped) == 0,
		"重读审计 F: 关联、缓存、跳过范围、累计 TSN 与首次一致")

	fmt.Println()
	if failures > 0 {
		fmt.Printf("冒烟失败: %d 项未通过\n", failures)
		os.Exit(1)
	}
	fmt.Println("冒烟全部通过")
}

func postRaw(id, body string) (int, *audit.View, []byte) {
	resp, err := http.Post(*addr+"/api/audits/"+id+"/packets", "application/json", bytes.NewReader([]byte(body)))
	if err != nil {
		return -1, nil, []byte(err.Error())
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, nil, data
}
