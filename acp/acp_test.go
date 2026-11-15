package acp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// fakeHost 记录桥接调用序；终态/错误按用例注入。
type fakeHost struct {
	created   []SessionRequest
	inputs    []string
	result    SessionResult
	createErr error
	inputErr  error
	waitErr   error
}

func (h *fakeHost) CreateSession(_ context.Context, req SessionRequest) (string, error) {
	h.created = append(h.created, req)
	if h.createErr != nil {
		return "", h.createErr
	}
	return "host-sess-1", nil
}

func (h *fakeHost) SendInput(_ context.Context, sessionID, text string) error {
	h.inputs = append(h.inputs, sessionID+":"+text)
	return h.inputErr
}

func (h *fakeHost) WaitTerminal(context.Context, string) (SessionResult, error) {
	return h.result, h.waitErr
}

// run 跑一次 Serve 并把输出逐行解码（每行一个 JSON-RPC 帧）。
func run(t *testing.T, host Host, opts Options, lines ...string) []map[string]json.RawMessage {
	t.Helper()
	var out strings.Builder
	in := strings.NewReader(strings.Join(lines, "\n") + "\n")
	if err := Serve(context.Background(), in, &out, host, opts); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var frames []map[string]json.RawMessage
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var frame map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &frame); err != nil {
			t.Fatalf("输出不是 JSON-RPC 帧: %q (%v)", line, err)
		}
		frames = append(frames, frame)
	}
	return frames
}

func decode[T any](t *testing.T, raw json.RawMessage) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("解码失败: %v (%s)", err, raw)
	}
	return v
}

func rawString(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	return decode[string](t, raw)
}

// idText id 可为数字或字符串，统一取字面文本（断言回显用）。
func idText(raw json.RawMessage) string {
	return strings.Trim(strings.TrimSpace(string(raw)), `"`)
}

func errorCode(t *testing.T, frame map[string]json.RawMessage) int {
	t.Helper()
	if _, ok := frame["result"]; ok {
		t.Fatalf("不应有 result: %v", frame)
	}
	errObj, ok := frame["error"]
	if !ok {
		t.Fatalf("缺 error 帧: %v", frame)
	}
	var e RPCError
	if err := json.Unmarshal(errObj, &e); err != nil {
		t.Fatalf("error 帧解析: %v", err)
	}
	return e.Code
}

func TestInitialize(t *testing.T) {
	frames := run(t, &fakeHost{}, Options{AgentName: "ops-agent", AgentDescription: "运维专家"}, []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
	}...)
	if len(frames) != 1 {
		t.Fatalf("initialize 应回一帧: %d", len(frames))
	}
	if got := rawString(t, frames[0]["jsonrpc"]); got != "2.0" {
		t.Fatalf("jsonrpc: %q", got)
	}
	if got := idText(frames[0]["id"]); got != "1" {
		t.Fatalf("id 应原样回显: %q", got)
	}
	var result struct {
		ProtocolVersion   int `json:"protocolVersion"`
		AgentCapabilities struct {
			LoadSession        bool            `json:"loadSession"`
			PromptCapabilities map[string]bool `json:"promptCapabilities"`
		} `json:"agentCapabilities"`
		AgentCard struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"agentCard"`
	}
	if err := json.Unmarshal(frames[0]["result"], &result); err != nil {
		t.Fatalf("result 解析: %v", err)
	}
	if result.ProtocolVersion != ProtocolVersion || result.AgentCapabilities.LoadSession {
		t.Fatalf("capabilities 不符: %+v", result)
	}
	if len(result.AgentCapabilities.PromptCapabilities) != 0 {
		t.Fatalf("promptCapabilities 应空: %+v", result.AgentCapabilities.PromptCapabilities)
	}
	if result.AgentCard.Name != "ops-agent" || result.AgentCard.Description != "运维专家" {
		t.Fatalf("agentCard: %+v", result.AgentCard)
	}
}

func TestInitializeDefaults(t *testing.T) {
	frames := run(t, nil, Options{}, `{"jsonrpc":"2.0","id":"init-1","method":"initialize"}`)
	var result struct {
		AgentCard struct {
			Name string `json:"name"`
		} `json:"agentCard"`
	}
	if err := json.Unmarshal(frames[0]["result"], &result); err != nil {
		t.Fatalf("result 解析: %v", err)
	}
	if result.AgentCard.Name != "ACP Agent" {
		t.Fatalf("缺省 agent 名: %q", result.AgentCard.Name)
	}
	if got := idText(frames[0]["id"]); got != "init-1" {
		t.Fatalf("字符串 id 应原样回显: %q", got)
	}
}

func TestSessionNewAndPrompt(t *testing.T) {
	host := &fakeHost{result: SessionResult{Succeeded: true, FinalReport: "# 诊断报告\n\n磁盘正常。"}}
	frames := run(t, host, Options{}, []string{
		`{"jsonrpc":"2.0","id":2,"method":"session/new","params":{}}`,
		`{"jsonrpc":"2.0","id":3,"method":"session/prompt","params":{"sessionId":"acp-x","prompt":"磁盘告警排查一下"}}`,
	}...)
	if len(frames) != 3 {
		t.Fatalf("应回 2 响应 + 1 通知: %d", len(frames))
	}
	var created struct {
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(frames[0]["result"], &created); err != nil {
		t.Fatalf("session/new result: %v", err)
	}
	if !strings.HasPrefix(created.SessionID, "acp-") {
		t.Fatalf("sessionId 前缀: %q", created.SessionID)
	}
	// 通知先于响应（客户端先渲染 agent_message_chunk，再收 end_of_turn）。
	if got := rawString(t, frames[1]["method"]); got != "session/update" {
		t.Fatalf("prompt 应先发 session/update: %v", frames[1])
	}
	var update struct {
		SessionID string `json:"sessionId"`
		Update    struct {
			SessionUpdate string `json:"sessionUpdate"`
			Content       struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"update"`
	}
	if err := json.Unmarshal(frames[1]["params"], &update); err != nil {
		t.Fatalf("通知 params: %v", err)
	}
	if update.SessionID != "acp-x" || update.Update.SessionUpdate != "agent_message_chunk" ||
		update.Update.Content.Type != "text" || update.Update.Content.Text != host.result.FinalReport {
		t.Fatalf("通知内容不符: %+v", update)
	}
	var result struct {
		StopReason string `json:"stopReason"`
	}
	if err := json.Unmarshal(frames[2]["result"], &result); err != nil {
		t.Fatalf("prompt result: %v", err)
	}
	if result.StopReason != "end_of_turn" || idText(frames[2]["id"]) != "3" {
		t.Fatalf("prompt 收束帧: %+v", frames[2])
	}
	if len(host.created) != 1 || host.created[0].Input != "磁盘告警排查一下" {
		t.Fatalf("首问应建会话: %+v", host.created)
	}
	if len(host.inputs) != 0 {
		t.Fatalf("首问不应投递 input: %+v", host.inputs)
	}
}

func TestFollowupReusesSession(t *testing.T) {
	host := &fakeHost{result: SessionResult{Succeeded: true, FinalReport: "答"}}
	frames := run(t, host, Options{}, []string{
		`{"jsonrpc":"2.0","id":1,"method":"session/prompt","params":{"sessionId":"acp-1","prompt":"第一问"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"session/prompt","params":{"sessionId":"acp-1","prompt":"第二问"}}`,
	}...)
	if len(frames) != 4 {
		t.Fatalf("两轮应各 1 通知 + 1 响应: %d", len(frames))
	}
	if len(host.created) != 1 {
		t.Fatalf("追问不得再建会话: %+v", host.created)
	}
	if len(host.inputs) != 1 || host.inputs[0] != "host-sess-1:第二问" {
		t.Fatalf("追问应走 SendInput: %+v", host.inputs)
	}
}

func TestPromptContentBlocks(t *testing.T) {
	host := &fakeHost{result: SessionResult{Succeeded: true, FinalReport: "ok"}}
	frames := run(t, host, Options{}, `{"jsonrpc":"2.0","id":1,"method":"session/prompt","params":{"sessionId":"acp-1","prompt":[{"type":"text","text":"a"},{"type":"image","text":"忽略"},{"type":"text","text":"b"}]}}`)
	if len(frames) != 2 {
		t.Fatalf("应回通知 + 响应: %d", len(frames))
	}
	if len(host.created) != 1 || host.created[0].Input != "ab" {
		t.Fatalf("content block 只取 text: %+v", host.created)
	}
}

func TestPromptSingleBlockObject(t *testing.T) {
	host := &fakeHost{result: SessionResult{Succeeded: true, FinalReport: "ok"}}
	run(t, host, Options{}, `{"jsonrpc":"2.0","id":1,"method":"session/prompt","params":{"sessionId":"acp-1","prompt":{"type":"text","text":"单块"}}}`)
	if len(host.created) != 1 || host.created[0].Input != "单块" {
		t.Fatalf("单 block 对象: %+v", host.created)
	}
}

func TestUnknownMethod(t *testing.T) {
	frames := run(t, nil, Options{}, []string{
		`{"jsonrpc":"2.0","id":9,"method":"fs/read","params":{}}`,
		`{"jsonrpc":"2.0","id":10,"method":"session/load","params":{}}`,
		`{"jsonrpc":"2.0","method":"fs/write","params":{}}`, // 未知通知：不回包
		`{"jsonrpc":"2.0","id":11,"method":"initialize","params":{}}`,
	}...)
	if len(frames) != 3 {
		t.Fatalf("未知请求应回 2 错误 + initialize，未知通知静默: %d", len(frames))
	}
	for _, i := range []int{0, 1} {
		if code := errorCode(t, frames[i]); code != CodeMethodNotFound {
			t.Fatalf("未支持方法应 -32601: %d", code)
		}
	}
	if _, ok := frames[2]["result"]; !ok {
		t.Fatalf("initialize 应继续可用: %v", frames[2])
	}
}

func TestNotificationNeverAnswered(t *testing.T) {
	frames := run(t, &fakeHost{}, Options{}, []string{
		`{"jsonrpc":"2.0","method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{}}`,
	}...)
	if len(frames) != 1 {
		t.Fatalf("通知不得回包: %d", len(frames))
	}
	if idText(frames[0]["id"]) != "2" {
		t.Fatalf("只有请求应回包: %v", frames[0])
	}
}

func TestParseError(t *testing.T) {
	frames := run(t, nil, Options{}, []string{
		`not a json rpc line`,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
	}...)
	if len(frames) != 2 {
		t.Fatalf("噪声行应回 parse error 并继续: %d", len(frames))
	}
	if code := errorCode(t, frames[0]); code != CodeParseError {
		t.Fatalf("parse error code: %d", code)
	}
	var id any
	if err := json.Unmarshal(frames[0]["id"], &id); err != nil || id != nil {
		t.Fatalf("parse error 的 id 应为 null: %v %v", id, err)
	}
	if _, ok := frames[1]["result"]; !ok {
		t.Fatalf("parse error 后应继续服务: %v", frames[1])
	}
}

func TestInvalidRequest(t *testing.T) {
	frames := run(t, nil, Options{}, []string{
		`{"jsonrpc":"2.0","id":2}`,
		`{"id":3,"method":"initialize"}`,
		`{"jsonrpc":"2.0","id":{},"method":"initialize"}`,
	}...)
	if len(frames) != 3 {
		t.Fatalf("三个非法请求应各回一帧: %d", len(frames))
	}
	for i, frame := range frames {
		if code := errorCode(t, frame); code != CodeInvalidRequest {
			t.Fatalf("第 %d 帧应 -32600: %d", i, code)
		}
	}
}

func TestPromptInvalidParams(t *testing.T) {
	frames := run(t, &fakeHost{}, Options{}, []string{
		`{"jsonrpc":"2.0","id":1,"method":"session/prompt","params":{"prompt":"缺 sessionId"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"session/prompt","params":{"sessionId":"acp-1","prompt":"  "}}`,
		`{"jsonrpc":"2.0","id":3,"method":"session/prompt","params":{"sessionId":"acp-1"}}`,
		`{"jsonrpc":"2.0","id":4,"method":"session/prompt","params":"not-an-object"}`,
	}...)
	if len(frames) != 4 {
		t.Fatalf("四个非法参数应各回一帧: %d", len(frames))
	}
	for i, frame := range frames {
		if code := errorCode(t, frame); code != CodeInvalidParams {
			t.Fatalf("第 %d 帧应 -32602: %d", i, code)
		}
	}
}

func TestHostErrors(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		frames := run(t, &fakeHost{createErr: errors.New("boom")}, Options{},
			`{"jsonrpc":"2.0","id":1,"method":"session/prompt","params":{"sessionId":"acp-1","prompt":"x"}}`)
		if code := errorCode(t, frames[0]); code != CodeInternalError {
			t.Fatalf("建会话失败应 -32603: %d", code)
		}
	})
	t.Run("input", func(t *testing.T) {
		host := &fakeHost{inputErr: errors.New("input boom")}
		b := New(host, Options{})
		b.sessions["acp-1"] = "host-sess-1"
		_, err := b.prompt(context.Background(), "acp-1", "追问")
		if err == nil || !strings.Contains(err.Error(), "追问投递失败") {
			t.Fatalf("SendInput 失败应透传: %v", err)
		}
	})
	t.Run("wait", func(t *testing.T) {
		frames := run(t, &fakeHost{waitErr: errors.New("wait boom")}, Options{},
			`{"jsonrpc":"2.0","id":1,"method":"session/prompt","params":{"sessionId":"acp-1","prompt":"x"}}`)
		if code := errorCode(t, frames[0]); code != CodeInternalError {
			t.Fatalf("终态失败应 -32603: %d", code)
		}
	})
	t.Run("nil host", func(t *testing.T) {
		frames := run(t, nil, Options{},
			`{"jsonrpc":"2.0","id":1,"method":"session/prompt","params":{"sessionId":"acp-1","prompt":"x"}}`)
		if code := errorCode(t, frames[0]); code != CodeInternalError {
			t.Fatalf("nil host 应 -32603: %d", code)
		}
	})
}

func TestPromptNoReport(t *testing.T) {
	frames := run(t, &fakeHost{result: SessionResult{Succeeded: true}}, Options{},
		`{"jsonrpc":"2.0","id":1,"method":"session/prompt","params":{"sessionId":"acp-1","prompt":"x"}}`)
	if len(frames) != 2 {
		t.Fatalf("成功无报告也应回通知 + 响应: %d", len(frames))
	}
	var update struct {
		Update struct {
			Content struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"update"`
	}
	if err := json.Unmarshal(frames[0]["params"], &update); err != nil {
		t.Fatalf("通知: %v", err)
	}
	if !strings.Contains(update.Update.Content.Text, "无定稿报告") {
		t.Fatalf("成功无报告兜底文案: %q", update.Update.Content.Text)
	}
}

func TestPromptFailedNoReport(t *testing.T) {
	frames := run(t, &fakeHost{result: SessionResult{Succeeded: false, Status: "failed"}}, Options{},
		`{"jsonrpc":"2.0","id":1,"method":"session/prompt","params":{"sessionId":"acp-1","prompt":"x"}}`)
	if code := errorCode(t, frames[0]); code != CodeInternalError {
		t.Fatalf("失败终态应 -32603: %d", code)
	}
}

func TestHandleExtension(t *testing.T) {
	b := New(nil, Options{})
	b.Handle("x/ping", func(context.Context, json.RawMessage) (any, error) {
		return map[string]any{"pong": true}, nil
	})
	var out strings.Builder
	if err := b.Serve(context.Background(), strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"x/ping"}`+"\n"), &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if !strings.Contains(out.String(), `"pong":true`) {
		t.Fatalf("扩展方法未路由: %s", out.String())
	}
}
