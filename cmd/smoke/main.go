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

// fullJSON 是整个只读视图(含累计状态、缓存、跳过范围)的确定性 JSON,
// 用于按标识重读时的逐字节一致性比较。
func fullJSON(v *audit.View) string {
	data, _ := json.Marshal(v)
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

// dspec 构造复合数据报中的一个 DATA 块说明。
func dspec(tsn uint32, ssn uint16, b, e bool, payload string) sctp.ChunkSpec {
	return sctp.ChunkSpec{Data: &sctp.DataSpec{TSN: tsn, Stream: stream, SSN: ssn, B: b, E: e, Data: []byte(payload)}}
}

// dspecStream 构造指定流标识的 DATA 块说明(用于构造非法流)。
func dspecStream(tsn uint32, s uint16, ssn uint16, b, e bool, payload string) sctp.ChunkSpec {
	return sctp.ChunkSpec{Data: &sctp.DataSpec{TSN: tsn, Stream: s, SSN: ssn, B: b, E: e, Data: []byte(payload)}}
}

func fspec(newCum uint32, pairs ...sctp.StreamPair) sctp.ChunkSpec {
	return sctp.ChunkSpec{Forward: &sctp.ForwardTSNChunk{NewCumTSN: newCum, Pairs: pairs}}
}

func bundle(specs ...sctp.ChunkSpec) []byte {
	return sctp.BuildPacket(srcPort, dstPort, verTag, specs...)
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

	fmt.Println("== 场景 D: 同一数据报内连续 B、E 双 DATA —— 单裁决、缓存进出、交付一次 ==")
	idD := "smoke-d-" + suffix
	be := bundle(
		dspec(5000, 42, true, false, "HELLO-"),
		dspec(5001, 42, false, true, "WORLD!"),
	)
	wantConcat := hex.EncodeToString([]byte("HELLO-WORLD!"))
	status, vd, _ := post(idD, be)
	check(status == 200, "复合数据报(B,E)提交返回 200 (实际 %d)", status)
	check(vd.PacketCount == 1 && len(vd.Verdicts) == 1,
		"两个 DATA 在一个数据报内只形成一个原始包裁决 (实际 %d)", vd.PacketCount)
	if len(vd.Verdicts) == 1 {
		v0 := vd.Verdicts[0]
		check(v0.Type == "DATA" && v0.Decision == "delivered",
			"裁决类型 DATA 且 delivered (实际 %s/%s)", v0.Type, v0.Decision)
		check(len(v0.Chunks) == 2 && v0.Chunks[0].Outcome == "buffered" && v0.Chunks[1].Outcome == "delivered",
			"逐块按线序: B片 buffered → E片 delivered (实际 %+v)", v0.Chunks)
		check(containsUint32(v0.BufferAdded, 5000) && containsUint32(v0.BufferAdded, 5001) &&
			containsUint32(v0.BufferRemoved, 5000) && containsUint32(v0.BufferRemoved, 5001),
			"同一裁决展示两个分片缓存进出 +5000,+5001 -5000,-5001 (实际 +%v -%v)",
			v0.BufferAdded, v0.BufferRemoved)
		check(v0.CumTSN == 5001 && len(v0.Delivered) == 1 && v0.Delivered[0].Hex == wantConcat,
			"累计 TSN=5001 且裁决内交付拼接消息 (实际 cum=%d delivered=%+v)", v0.CumTSN, v0.Delivered)
	}
	check(len(vd.Messages) == 1 && vd.Messages[0].Hex == wantConcat &&
		len(vd.Messages[0].TSNs) == 2 && vd.Messages[0].TSNs[0] == 5000 && vd.Messages[0].TSNs[1] == 5001,
		"恰好交付一次拼接后的 HELLO-WORLD! (实际 %d 条 %+v)", len(vd.Messages), vd.Messages)
	check(len(vd.State.Buffered) == 0, "交付后缓存为空 (实际 %d)", len(vd.State.Buffered))

	// 字节完全相同的整包重传: 不增加消息数。
	status, vdDup, _ := post(idD, be, be)
	check(status == 200 && len(vdDup.Verdicts) == 2,
		"整包重传提交返回 200 且裁决数为 2 (实际 %d/%d)", status, len(vdDup.Verdicts))
	check(len(vdDup.Verdicts) == 2 && vdDup.Verdicts[1].Decision == "duplicate" &&
		len(vdDup.Verdicts[1].Chunks) == 2,
		"字节完全相同的整包重传判 duplicate, 逐块仍为 2 个 (实际 %+v)",
		func() any {
			if len(vdDup.Verdicts) == 2 {
				return vdDup.Verdicts[1]
			}
			return nil
		}())
	check(len(vdDup.Messages) == 1, "整包重传不增加消息数 (实际 %d)", len(vdDup.Messages))

	status, vdGet := getView(idD)
	check(status == 200 && fullJSON(vdGet) == fullJSON(vdDup),
		"按标识重读 D: 逐包结果、缓存变化、消息列表与首次一致")

	fmt.Println("== 场景 E: 同一数据报 DATA 后紧随 FORWARD-TSN —— 跳过/作废/随后交付, 整包重传 ==")
	idE := "smoke-e-" + suffix
	// 前置: ssn20 缺中间片(B@6100, E@6102, 缺 6101); ssn21 完整消息已缓存等待流序。
	e1 := data(6100, 20, false, true, false, "AB")
	e2 := data(6103, 21, false, true, true, "NEXT")
	status, ve0, _ := post(idE, e1, e2)
	check(status == 200 && len(ve0.Messages) == 0, "前置两个分片缓存且无交付 (实际 %d)", len(ve0.Messages))
	// 一个数据报: E 片(TSN6102, ssn20, 仍缺 6101) + FORWARD-TSN 跨越 6101 放弃 ssn20。
	df := bundle(
		dspec(6102, 20, false, true, "EF"),
		fspec(6101, sctp.StreamPair{Stream: stream, SSN: 20}),
	)
	status, ve, _ := post(idE, e1, e2, df)
	check(status == 200 && len(ve.Verdicts) == 3,
		"DATA+FORWARD-TSN 复合数据报作为第三个原始包裁决 (实际 %d/%d)", status, len(ve.Verdicts))
	if len(ve.Verdicts) == 3 {
		v2 := ve.Verdicts[2]
		check(v2.Decision == "accepted" && len(v2.Chunks) == 2 &&
			v2.Chunks[0].Type == "DATA" && v2.Chunks[1].Type == "FORWARD-TSN",
			"复合裁决 accepted 且逐块线序为 DATA → FORWARD-TSN (实际 %s %+v)", v2.Decision, v2.Chunks)
		check(len(v2.SkippedAdded) == 1 && v2.SkippedAdded[0].Start == 6101 && v2.SkippedAdded[0].End == 6101,
			"同一裁决反映跳过范围 [6101,6101] (实际 %+v)", v2.SkippedAdded)
		check(containsUint32(v2.BufferAdded, 6102) &&
			containsUint32(v2.BufferRemoved, 6100) && containsUint32(v2.BufferRemoved, 6102) &&
			containsUint16(v2.Abandoned, 20),
			"同一裁决展示 6102 入缓存、残缺消息 ssn20 作废移出 (+%v -%v 作废%v)",
			v2.BufferAdded, v2.BufferRemoved, v2.Abandoned)
		check(len(v2.Delivered) == 1 && v2.Delivered[0].SSN == 21 &&
			v2.Delivered[0].Hex == hex.EncodeToString([]byte("NEXT")),
			"同一裁决随后交付 ssn21 消息 (实际 %+v)", v2.Delivered)
	}
	check(len(ve.Messages) == 1 && ve.Messages[0].SSN == 21,
		"恰好交付一条随后可交付消息 (实际 %+v)", ve.Messages)
	check(len(ve.State.Buffered) == 0 && ve.State.CumTSN == 6101,
		"缓存清空、累计 TSN=6101(残缺片随作废移出, 不被确认) (实际 buf=%d cum=%d)",
		len(ve.State.Buffered), ve.State.CumTSN)

	// 整包重传: duplicate, 不增加消息数、不改变跳过范围。
	status, veDup, _ := post(idE, e1, e2, df, df)
	check(status == 200 && len(veDup.Verdicts) == 4 &&
		veDup.Verdicts[3].Decision == "duplicate",
		"DATA+FORWARD-TSN 整包重传判 duplicate (实际 %d %+v)",
		status, func() any {
			if len(veDup.Verdicts) == 4 {
				return veDup.Verdicts[3].Decision
			}
			return nil
		}())
	check(len(veDup.Messages) == 1 && len(veDup.State.Skipped) == 1,
		"重传后消息仍为 1 条、跳过范围不变 (实际 msgs=%d skipped=%+v)",
		len(veDup.Messages), veDup.State.Skipped)

	status, veGet := getView(idE)
	check(status == 200 && fullJSON(veGet) == fullJSON(veDup),
		"按标识重读 E: 逐包结果、缓存变化、跳过范围与消息列表与首次一致")

	fmt.Println("== 场景 F: 复合数据报整包原子性 —— 首块正常、后续块违规整体冻结拒绝 ==")
	idF := "smoke-f-" + suffix
	// 首块为正常 B 片, 第二块 DATA 属于非受审流(流 8)。
	bad := bundle(
		dspec(7000, 1, true, false, "A"),
		dspecStream(7001, 8, 1, false, true, "B"),
	)
	status, vf, _ := post(idF, bad)
	check(status == 200 && len(vf.Verdicts) == 1,
		"违规复合数据报提交返回 200 且形成 1 个裁决 (实际 %d/%d)", status, len(vf.Verdicts))
	check(len(vf.Verdicts) == 1 && vf.Verdicts[0].Decision == "rejected",
		"后续块流标识非法时整包裁决 rejected (实际 %+v)",
		func() any {
			if len(vf.Verdicts) == 1 {
				return vf.Verdicts[0].Decision
			}
			return nil
		}())
	check(!vf.State.Initialized && vf.State.CumTSN == 0 && vf.State.MaxTSN == 0 &&
		len(vf.State.Buffered) == 0 && len(vf.Messages) == 0,
		"整体冻结拒绝: 未留下首块建立的关联、缓存或累计 TSN (实际 init=%v cum=%d max=%d buf=%d msgs=%d)",
		vf.State.Initialized, vf.State.CumTSN, vf.State.MaxTSN, len(vf.State.Buffered), len(vf.Messages))
	frozenFullF := fullJSON(vf)

	// 同一数据报原样重放: 已冻结, 裁决一致(幂等), 仍无任何状态。
	status, vfReplay, _ := post(idF, bad)
	check(status == 200 && len(vfReplay.Verdicts) == 1 &&
		vfReplay.Verdicts[0].Decision == "rejected" && fullJSON(vfReplay) == frozenFullF,
		"同一标识重新打开冻结记录: 逐包结果与首次一致(整体拒绝, 无状态)")

	// 首块 DATA 合法、第二块 FORWARD-TSN 越界: 同样整体回滚。
	idF2 := "smoke-f2-" + suffix
	badFwd := bundle(
		dspec(8000, 1, true, true, "Z"),
		fspec(9999), // 新累计 TSN 超出已观测最大 TSN
	)
	status, vf2, _ := post(idF2, badFwd)
	check(status == 200 && len(vf2.Verdicts) == 1 && vf2.Verdicts[0].Decision == "rejected",
		"首块正常、后续 FORWARD-TSN 越界也整体 rejected (实际 %d %+v)",
		status, func() any {
			if len(vf2.Verdicts) == 1 {
				return vf2.Verdicts[0].Decision
			}
			return nil
		}())
	check(!vf2.State.Initialized && len(vf2.State.Buffered) == 0 && len(vf2.Messages) == 0,
		"FORWARD-TSN 违规回滚: 首块缓存/关联同样不保留")
	status, vf2Get := getView(idF2)
	check(status == 200 && fullJSON(vf2Get) == fullJSON(vf2),
		"按标识重读 F2: 冻结记录与首次一致")

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
