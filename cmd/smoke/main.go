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
