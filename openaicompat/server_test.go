package openaicompat

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeHost 记录宿主角；终态/错误按用例注入。
type fakeHost struct {
	turns     []Turn
	result    SessionResult
	createErr error
	waitErr   error
	canceled  []string
}

func (h *fakeHost) CreateSession(_ context.Context, turn Turn) (string, error) {
	h.turns = append(h.turns, turn)
	if h.createErr != nil {
		return "", h.createErr
	}
	return "sess-test-1", nil
}

func (h *fakeHost) WaitTerminal(context.Context, string) (SessionResult, error) {
	return h.result, h.waitErr
}

func (h *fakeHost) Cancel(_ context.Context, sessionID string) error {
	h.canceled = append(h.canceled, sessionID)
	return nil
}

// fakeSource 注入事件总线：事件预置在缓冲通道后关闭（实时侧结束）。
type fakeSource struct {
	ch chan Event
}

func (f *fakeSource) Subscribe(string) (<-chan Event, func()) {
	return f.ch, func() {}
}

func newFakeSource(events ...Event) *fakeSource {
	ch := make(chan Event, len(events))
	for _, ev := range events {
		ch <- ev
	}
	close(ch)
	return &fakeSource{ch: ch}
}

// authHost 宿主鉴权缝：allow 决定 Authorize 放行（产品策略替身）。
type authHost struct {
	fakeHost
	allow bool
}

func (h *authHost) Authorize(*http.Request) bool { return h.allow }

const testToken = "sk-test"

func doChat(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	if testToken != "" {
		req.Header.Set("Authorization", "Bearer "+testToken)
	}
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// parseSSE 解析 data 帧，返回 chunk 序列与是否见到 [DONE]。
func parseSSE(t *testing.T, body string) ([]Chunk, bool) {
	t.Helper()
	var chunks []Chunk
	done := false
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ":") {
			continue
		}
		if line == "data: [DONE]" {
			done = true
			continue
		}
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			t.Fatalf("非 SSE 行: %q", line)
		}
		c, err := DecodeChunk([]byte(data))
		if err != nil {
			t.Fatalf("chunk 解码: %v (%s)", err, data)
		}
		chunks = append(chunks, c)
	}
	return chunks, done
}

func apiError(t *testing.T, rec *httptest.ResponseRecorder) (code int, msg string) {
	t.Helper()
	var body struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("错误体解析: %v (%s)", err, rec.Body.String())
	}
	return rec.Code, body.Error.Message
}

// TestAuthorized 恒时 Bearer 闸：空 token 恒拒、错 token 拒、对 token 过。
func TestAuthorized(t *testing.T) {
	s := New(nil, nil, Config{Token: testToken})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	if s.authorized(req) {
		t.Fatal("无头应拒")
	}
	req.Header.Set("Authorization", "Bearer wrong")
	if s.authorized(req) {
		t.Fatal("错 token 应拒")
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	if !s.authorized(req) {
		t.Fatal("对 token 应过")
	}
	s2 := New(nil, nil, Config{})
	req.Header.Set("Authorization", "Bearer whatever")
	if s2.authorized(req) {
		t.Fatal("空 token 配置应恒拒")
	}
}

func TestHandlerUnauthorized(t *testing.T) {
	s := New(nil, nil, Config{Token: testToken})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader("{}"))
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("无凭据应 401: %d", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, "Bearer") {
		t.Fatalf("401 应带 Bearer 提示: %q", got)
	}
}

func TestModelsEndpoint(t *testing.T) {
	s := New(nil, nil, Config{Token: testToken})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("models 状态: %d", rec.Code)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != `{"object":"list","data":[]}` {
		t.Fatalf("models 清单: %s", body)
	}
}

func TestChatCompletionsNonStream(t *testing.T) {
	host := &fakeHost{result: SessionResult{Succeeded: true, FinalReport: "# 报告\n\n磁盘正常。"}}
	s := New(host, nil, Config{Token: testToken})
	rec := doChat(t, s, `{"model":"gpt-4o","messages":[
		{"role":"system","content":"你是专家"},
		{"role":"user","content":"磁盘告警"}
	]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态: %d (%s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type: %q", ct)
	}
	var c Completion
	if err := json.Unmarshal(rec.Body.Bytes(), &c); err != nil {
		t.Fatalf("补全解码: %v", err)
	}
	if c.ID != "chatcmpl-sess-test-1" || c.Object != ObjectChatCompletion || c.Model != "gpt-4o" {
		t.Fatalf("补全帧头: %+v", c)
	}
	if len(c.Choices) != 1 || c.Choices[0].Message.Role != "assistant" ||
		c.Choices[0].Message.Content != "# 报告\n\n磁盘正常。" ||
		c.Choices[0].FinishReason != "stop" {
		t.Fatalf("补全正文: %+v", c.Choices)
	}
	if len(host.turns) != 1 {
		t.Fatalf("建会话次数: %d", len(host.turns))
	}
	turn := host.turns[0]
	if turn.Model != "gpt-4o" || turn.Input != "磁盘告警" ||
		turn.Instruction != "system: 你是专家" || turn.Stream {
		t.Fatalf("Turn 翻译: %+v", turn)
	}
}

func TestChatCompletionsNonStreamFailure(t *testing.T) {
	host := &fakeHost{result: SessionResult{Succeeded: false, Status: "failed", FinalReport: "半截结论"}}
	s := New(host, nil, Config{Token: testToken})
	rec := doChat(t, s, `{"model":"m","messages":[{"role":"user","content":"x"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态: %d (%s)", rec.Code, rec.Body.String())
	}
	var c Completion
	if err := json.Unmarshal(rec.Body.Bytes(), &c); err != nil {
		t.Fatalf("补全解码: %v", err)
	}
	if got := c.Choices[0].Message.Content; got != "半截结论\n\n[会话未成功: failed]" {
		t.Fatalf("失败说明: %q", got)
	}
}

func TestChatCompletionsWaitError(t *testing.T) {
	host := &fakeHost{waitErr: errors.New("boom")}
	s := New(host, nil, Config{Token: testToken})
	rec := doChat(t, s, `{"model":"m","messages":[{"role":"user","content":"x"}]}`)
	code, msg := apiError(t, rec)
	if code != http.StatusBadGateway || !strings.Contains(msg, "会话查询失败") {
		t.Fatalf("终态查询失败: %d %q", code, msg)
	}
}

func TestChatCompletionsCreateError(t *testing.T) {
	host := &fakeHost{createErr: errors.New("db down")}
	s := New(host, nil, Config{Token: testToken})
	rec := doChat(t, s, `{"model":"m","messages":[{"role":"user","content":"x"}]}`)
	code, msg := apiError(t, rec)
	if code != http.StatusInternalServerError || !strings.Contains(msg, "建会话失败") {
		t.Fatalf("建会话失败: %d %q", code, msg)
	}
}

func TestChatCompletionsBadRequests(t *testing.T) {
	host := &fakeHost{result: SessionResult{Succeeded: true}}
	s := New(host, nil, Config{Token: testToken})
	t.Run("invalid json", func(t *testing.T) {
		rec := doChat(t, s, `{`)
		code, msg := apiError(t, rec)
		if code != http.StatusBadRequest || !strings.Contains(msg, "invalid JSON body") {
			t.Fatalf("非法 JSON: %d %q", code, msg)
		}
	})
	t.Run("no input", func(t *testing.T) {
		rec := doChat(t, s, `{"model":"m","messages":[]}`)
		code, msg := apiError(t, rec)
		if code != http.StatusBadRequest || !strings.Contains(msg, ErrNoInput.Error()) {
			t.Fatalf("无输入: %d %q", code, msg)
		}
	})
	t.Run("nil host", func(t *testing.T) {
		s := New(nil, nil, Config{Token: testToken})
		rec := doChat(t, s, `{"model":"m","messages":[{"role":"user","content":"x"}]}`)
		code, msg := apiError(t, rec)
		if code != http.StatusInternalServerError || !strings.Contains(msg, "host 未配置") {
			t.Fatalf("nil host: %d %q", code, msg)
		}
	})
}

// TestChatCompletionsStream 全事件序：reasoning→思考字段、text→正文、
// 重复 ID 去重、usage 累计到末帧、turn_ended 收口 + [DONE]。
func TestChatCompletionsStream(t *testing.T) {
	host := &fakeHost{result: SessionResult{Succeeded: true, FinalReport: "终报全文"}}
	source := newFakeSource(
		Event{ID: 1, Type: EventReasoningDelta, Payload: map[string]any{"text": "想"}},
		Event{ID: 2, Type: EventTextDelta, Payload: map[string]any{"text": "答复"}},
		Event{ID: 2, Type: EventTextDelta, Payload: map[string]any{"text": "重复帧应丢"}},
		Event{ID: 3, Type: EventLLMUsage, Payload: map[string]any{
			"prompt_tokens": float64(10), "completion_tokens": float64(5), "total_tokens": float64(15)}},
		Event{ID: 4, Type: EventTurnEnded, Payload: map[string]any{"status": "succeeded"}},
	)
	s := New(host, source, Config{Token: testToken})
	rec := doChat(t, s, `{"model":"gpt-4o","stream":true,"messages":[
		{"role":"system","content":"你是专家"},
		{"role":"user","content":"磁盘告警"}
	]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态: %d (%s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type: %q", ct)
	}
	chunks, done := parseSSE(t, rec.Body.String())
	if !done {
		t.Fatal("流应以 [DONE] 收尾")
	}
	if len(chunks) != 3 {
		t.Fatalf("应有 reasoning + content + finish 三帧: %+v", chunks)
	}
	if chunks[0].Choices[0].Delta.ReasoningContent != "想" || chunks[0].Choices[0].Delta.Content != "" {
		t.Fatalf("reasoning 帧: %+v", chunks[0])
	}
	if chunks[1].Choices[0].Delta.Content != "答复" {
		t.Fatalf("正文帧: %+v", chunks[1])
	}
	final := chunks[2]
	if final.Choices[0].FinishReason != "stop" || final.Usage == nil ||
		final.Usage.PromptTokens != 10 || final.Usage.CompletionTokens != 5 || final.Usage.TotalTokens != 15 {
		t.Fatalf("收口帧: %+v", final)
	}
	if final.ID != "chatcmpl-sess-test-1" || final.Object != ObjectChatCompletionChunk || final.Model != "gpt-4o" {
		t.Fatalf("帧头: %+v", final)
	}
	if strings.Contains(rec.Body.String(), "重复帧应丢") || strings.Contains(rec.Body.String(), "终报全文") {
		t.Fatalf("重复帧/终报兜底不应出现: %s", rec.Body.String())
	}
	if len(host.turns) != 1 || host.turns[0].Input != "磁盘告警" || !host.turns[0].Stream {
		t.Fatalf("Turn: %+v", host.turns)
	}
}

// TestStreamFallbackFinalReport 一帧正文都没投影（极端丢帧）：终报全文兜底。
func TestStreamFallbackFinalReport(t *testing.T) {
	host := &fakeHost{result: SessionResult{Succeeded: true, FinalReport: "终报全文"}}
	source := newFakeSource(Event{ID: 1, Type: EventTurnEnded, Payload: map[string]any{"status": "succeeded"}})
	s := New(host, source, Config{Token: testToken})
	rec := doChat(t, s, `{"model":"m","stream":true,"messages":[{"role":"user","content":"x"}]}`)
	chunks, done := parseSSE(t, rec.Body.String())
	if !done || len(chunks) != 2 {
		t.Fatalf("兜底应为 content + finish: done=%v chunks=%+v", done, chunks)
	}
	if chunks[0].Choices[0].Delta.Content != "终报全文" || chunks[1].Choices[0].FinishReason != "stop" {
		t.Fatalf("终报兜底帧: %+v", chunks)
	}
}

// TestStreamFailureNote 失败终态：即使已有正文，末帧前补一行状态说明。
func TestStreamFailureNote(t *testing.T) {
	host := &fakeHost{result: SessionResult{Succeeded: false, Status: "failed"}}
	source := newFakeSource(
		Event{ID: 1, Type: EventTextDelta, Payload: map[string]any{"text": "中间结论"}},
		Event{ID: 2, Type: EventTurnEnded, Payload: map[string]any{"status": "failed"}},
	)
	s := New(host, source, Config{Token: testToken})
	rec := doChat(t, s, `{"model":"m","stream":true,"messages":[{"role":"user","content":"x"}]}`)
	chunks, done := parseSSE(t, rec.Body.String())
	if !done || len(chunks) != 3 {
		t.Fatalf("应为 content + 失败说明 + finish: done=%v chunks=%+v", done, chunks)
	}
	if chunks[0].Choices[0].Delta.Content != "中间结论" ||
		chunks[1].Choices[0].Delta.Content != "\n\n[会话未成功: failed]" ||
		chunks[2].Choices[0].FinishReason != "stop" {
		t.Fatalf("失败说明帧序: %+v", chunks)
	}
}

// TestStreamChannelClosesEarly 实时通道提前关闭（无 turn_ended）：终态对账后
// 正常收口，不重复正文（已有正文则不补终报）。
func TestStreamChannelClosesEarly(t *testing.T) {
	host := &fakeHost{result: SessionResult{Succeeded: true, FinalReport: "终报全文"}}
	source := newFakeSource(Event{ID: 1, Type: EventTextDelta, Payload: map[string]any{"text": "已有正文"}})
	s := New(host, source, Config{Token: testToken})
	rec := doChat(t, s, `{"model":"m","stream":true,"messages":[{"role":"user","content":"x"}]}`)
	chunks, done := parseSSE(t, rec.Body.String())
	if !done || len(chunks) != 2 {
		t.Fatalf("提前关通道应 content + finish: done=%v chunks=%+v", done, chunks)
	}
	if chunks[0].Choices[0].Delta.Content != "已有正文" || chunks[1].Choices[0].FinishReason != "stop" {
		t.Fatalf("提前关通道帧序: %+v", chunks)
	}
}

// TestStreamWithoutEventSource 未注入事件总线：直接终态对账并输出终报。
func TestStreamWithoutEventSource(t *testing.T) {
	host := &fakeHost{result: SessionResult{Succeeded: true, FinalReport: "仅终报"}}
	s := New(host, nil, Config{Token: testToken})
	rec := doChat(t, s, `{"model":"m","stream":true,"messages":[{"role":"user","content":"x"}]}`)
	chunks, done := parseSSE(t, rec.Body.String())
	if !done || len(chunks) != 2 {
		t.Fatalf("无事件源应终报兜底 + finish: done=%v chunks=%+v", done, chunks)
	}
	if chunks[0].Choices[0].Delta.Content != "仅终报" {
		t.Fatalf("终报帧: %+v", chunks)
	}
}

func TestConfigDefaults(t *testing.T) {
	s := New(nil, nil, Config{})
	if s.addr != DefaultAddr || s.turnTimeout != DefaultTurnTimeout ||
		s.heartbeat != DefaultHeartbeatInterval || s.maxBody != DefaultMaxBodyBytes {
		t.Fatalf("缺省装配: addr=%q timeout=%v heartbeat=%v maxBody=%d",
			s.addr, s.turnTimeout, s.heartbeat, s.maxBody)
	}
	if got := (Config{Addr: "127.0.0.1:9999"}).AddrOrDefault(); got != "127.0.0.1:9999" {
		t.Fatalf("自定义地址: %s", got)
	}
}

// TestAuthorizerOverride Host 实现 Authorizer 后由宿主接管鉴权（Token 兜底不生效）。
func TestAuthorizerOverride(t *testing.T) {
	models := func(s *Server, token string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		s.Handler().ServeHTTP(rec, req)
		return rec
	}
	t.Run("host allow without token", func(t *testing.T) {
		s := New(&authHost{allow: true}, nil, Config{Token: testToken})
		if rec := models(s, ""); rec.Code != http.StatusOK {
			t.Fatalf("宿主放行应 200: %d", rec.Code)
		}
	})
	t.Run("host deny despite token", func(t *testing.T) {
		s := New(&authHost{allow: false}, nil, Config{Token: testToken})
		if rec := models(s, testToken); rec.Code != http.StatusUnauthorized {
			t.Fatalf("宿主拒绝应 401: %d", rec.Code)
		}
	})
}
