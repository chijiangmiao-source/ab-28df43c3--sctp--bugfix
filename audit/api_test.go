package audit

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 持久化: 重新打开同一审计标识(模拟重启后从新 Store 读取), 视图与首次一致。
func TestPersistenceReload(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	batch := [][]byte{
		data(1001, 10, false, false, true, "WORLD!"),
		data(1000, 10, false, true, false, "HELLO-"),
		data(1000, 10, false, true, false, "HELLO-"), // 重传
	}
	if _, _, err := st.Submit("persist-1", batch); err != nil {
		t.Fatal(err)
	}
	first, ok, err := st.Get("persist-1")
	if err != nil || !ok {
		t.Fatalf("读取失败: %v %v", ok, err)
	}
	want := viewJSON(t, first)

	st2, err := NewStore(dir) // 全新 Store, 从磁盘恢复
	if err != nil {
		t.Fatal(err)
	}
	got, ok, err := st2.Get("persist-1")
	if err != nil || !ok {
		t.Fatalf("恢复失败: %v %v", ok, err)
	}
	if got := viewJSON(t, got); got != want {
		t.Fatalf("恢复后视图不一致:\n%s\n%s", got, want)
	}
}

// 幂等重放与冲突: 同批重提交结果一致; 同一捕获位置不同字节报 409 冲突。
func TestSubmitIdempotentAndConflict(t *testing.T) {
	st, _ := NewStore(t.TempDir())
	batch := [][]byte{data(100, 1, false, true, true, "ONE")}
	v1, c, err := st.Submit("idem", batch)
	if err != nil || c != nil {
		t.Fatal(err)
	}
	v2, c, err := st.Submit("idem", batch)
	if err != nil || c != nil {
		t.Fatal(err)
	}
	j1, _ := json.Marshal(v1)
	j2, _ := json.Marshal(v2)
	if string(j1) != string(j2) {
		t.Fatalf("重复提交结果不一致")
	}
	if len(v2.Verdicts) != 1 {
		t.Fatalf("重放不得新增裁决: %d", len(v2.Verdicts))
	}
	// 扩展捕获: 追加新包。
	ext := append(batch, data(101, 2, false, true, true, "TWO"))
	v3, c, err := st.Submit("idem", ext)
	if err != nil || c != nil || len(v3.Verdicts) != 2 {
		t.Fatalf("扩展失败: %v %v", c, err)
	}
	// 同一位置不同字节 → 冲突, 且已有裁决不变。
	_, c, err = st.Submit("idem", [][]byte{data(100, 1, false, true, true, "CHANGED")})
	if err != nil || c == nil || c.Index != 0 {
		t.Fatalf("应报告位置 0 冲突: %v %+v", err, c)
	}
	after, _, _ := st.Get("idem")
	if len(after.Verdicts) != 2 {
		t.Fatalf("冲突后裁决数被改变: %d", len(after.Verdicts))
	}
}

// 每批与会话总量均不得超过 32 个包。
func TestMaxPackets(t *testing.T) {
	st, _ := NewStore(t.TempDir())
	var raws [][]byte
	for i := 0; i < 33; i++ {
		raws = append(raws, data(1000+uint32(i), 1, false, true, true, "x"))
	}
	if _, _, err := st.Submit("cap", raws); err == nil {
		t.Fatal("33 个包应被拒绝")
	}
	if _, _, err := st.Submit("cap", raws[:32]); err != nil {
		t.Fatalf("32 个包应允许: %v", err)
	}
	if _, _, err := st.Submit("cap", append(raws[:32], data(9999, 1, false, true, true, "y"))); err == nil {
		t.Fatal("第 33 个包应被拒绝")
	}
}

func b64s(raws ...[]byte) string {
	var sb strings.Builder
	for i, r := range raws {
		if i > 0 {
			sb.WriteString(`","`)
		}
		sb.WriteString(base64.StdEncoding.EncodeToString(r))
	}
	return sb.String()
}

func postJSON(t *testing.T, h http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// HTTP 冒烟(进程内): 健康、操作页、提交、重读一致、404、400、409。
func TestHTTPAPI(t *testing.T) {
	st, _ := NewStore(t.TempDir())
	h := NewHandler(st)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/health", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"status": "ok"`) {
		t.Fatalf("健康响应错误: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "审计") {
		t.Fatalf("操作页错误: %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/audits/nope", nil))
	if rec.Code != 404 {
		t.Fatalf("未知标识应 404: %d", rec.Code)
	}

	d1 := data(1000, 10, false, true, false, "HELLO-")
	d2 := data(1001, 10, false, false, true, "WORLD!")
	body := fmt.Sprintf(`{"packets":["%s"]}`, b64s(d2, d1))
	rec = postJSON(t, h, "/api/audits/http-1/packets", body)
	if rec.Code != 200 {
		t.Fatalf("提交失败: %d %s", rec.Code, rec.Body.String())
	}
	var v View
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Messages) != 1 || v.Verdicts[1].Decision != DecisionDelivered {
		t.Fatalf("乱序互补应交付一条消息: %+v", v)
	}

	// 重新读取同一标识: 与首次一致。
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/audits/http-1", nil))
	if rec.Code != 200 || rec.Body.String() == "" {
		t.Fatalf("重读失败: %d", rec.Code)
	}
	var v2 View
	if err := json.Unmarshal(rec.Body.Bytes(), &v2); err != nil {
		t.Fatal(err)
	}
	j1, _ := json.Marshal(v.Verdicts)
	j2, _ := json.Marshal(v2.Verdicts)
	m1, _ := json.Marshal(v.Messages)
	m2, _ := json.Marshal(v2.Messages)
	if string(j1) != string(j2) || string(m1) != string(m2) {
		t.Fatalf("重读的逐包裁决或消息列表与首次不一致")
	}

	// 同一捕获位置不同字节 → 409 与冻结依据。
	bad := fmt.Sprintf(`{"packets":["%s"]}`, b64s(data(1001, 10, false, false, true, "XXXXXX")))
	rec = postJSON(t, h, "/api/audits/http-1/packets", bad)
	if rec.Code != 409 {
		t.Fatalf("冲突应 409: %d %s", rec.Code, rec.Body.String())
	}
	var apiErr apiError
	if err := json.Unmarshal(rec.Body.Bytes(), &apiErr); err != nil {
		t.Fatal(err)
	}
	if apiErr.Conflict == nil || apiErr.Conflict.Index != 0 || apiErr.Conflict.FrozenFirstBytesHex == "" {
		t.Fatalf("409 应携带冻结依据: %+v", apiErr)
	}

	// 参数校验。
	rec = postJSON(t, h, "/api/audits/http-1/packets", `{"packets":["!!!"]}`)
	if rec.Code != 400 {
		t.Fatalf("非法 Base64 应 400: %d", rec.Code)
	}
	rec = postJSON(t, h, "/api/audits/http-1/packets", `{"packets":[]}`)
	if rec.Code != 400 {
		t.Fatalf("空批应 400: %d", rec.Code)
	}
	var pkts []string
	for i := 0; i < 33; i++ {
		pkts = append(pkts, base64.StdEncoding.EncodeToString(data(2000+uint32(i), 1, false, true, true, "x")))
	}
	rec = postJSON(t, h, "/api/audits/http-1/packets", `{"packets":["`+strings.Join(pkts, `","`)+`"]}`)
	if rec.Code != 400 {
		t.Fatalf("超过 32 个包应 400: %d", rec.Code)
	}
	rec = postJSON(t, h, "/api/audits/bad.id!/packets", body)
	if rec.Code != 400 {
		t.Fatalf("非法标识应 400: %d", rec.Code)
	}
}
