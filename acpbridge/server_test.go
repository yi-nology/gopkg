package acpbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type fakeHost struct {
	createCwd string
	createID  string
	createErr error

	promptSID   string
	promptText  string
	promptErr   error
	stopReason  string
	chunks      []string
	emitErr     error
	canceledSID string

	promptCalled bool
}

func (h *fakeHost) CreateSession(_ context.Context, cwd string) (string, error) {
	h.createCwd = cwd
	return h.createID, h.createErr
}

func (h *fakeHost) Prompt(_ context.Context, sessionID, text string, emit func(string) error) (string, error) {
	h.promptCalled = true
	h.promptSID, h.promptText = sessionID, text
	for _, c := range h.chunks {
		if err := emit(c); err != nil {
			h.emitErr = err
			return "", err
		}
	}
	if h.promptErr != nil {
		return "", h.promptErr
	}
	return h.stopReason, nil
}

func (h *fakeHost) Cancel(_ context.Context, sessionID string) error {
	h.canceledSID = sessionID
	return nil
}

type line struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	Result  json.RawMessage `json:"result"`
	Error   *RPCError       `json:"error"`
}

func run(t *testing.T, host Host, input string) ([]line, error) {
	t.Helper()
	var out bytes.Buffer
	err := Serve(t.Context(), host, strings.NewReader(input), &out)
	var lines []line
	for _, raw := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		var l line
		if uerr := json.Unmarshal([]byte(raw), &l); uerr != nil {
			t.Fatalf("输出不是 JSON: %q: %v", raw, uerr)
		}
		lines = append(lines, l)
	}
	return lines, err
}

func TestInitialize(t *testing.T) {
	t.Parallel()
	lines, err := run(t, &fakeHost{}, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":1}}`+"\n")
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if len(lines) != 1 || lines[0].Error != nil {
		t.Fatalf("lines = %+v", lines)
	}
	var res struct {
		ProtocolVersion   int `json:"protocolVersion"`
		AgentCapabilities struct {
			LoadSession        bool            `json:"loadSession"`
			PromptCapabilities map[string]bool `json:"promptCapabilities"`
		} `json:"agentCapabilities"`
		AgentInfo struct {
			Name string `json:"name"`
		} `json:"agentInfo"`
		AuthMethods []any `json:"authMethods"`
	}
	if err := json.Unmarshal(lines[0].Result, &res); err != nil {
		t.Fatalf("result: %v", err)
	}
	if res.ProtocolVersion != ProtocolVersion || res.AgentCapabilities.LoadSession {
		t.Fatalf("initialize result = %+v", res)
	}
	if res.AgentCapabilities.PromptCapabilities == nil || res.AuthMethods == nil {
		t.Fatalf("capabilities 缺字段: %+v", res)
	}
	if res.AgentInfo.Name == "" {
		t.Fatal("agentInfo.name 为空")
	}
}

func TestSessionNew(t *testing.T) {
	t.Parallel()
	host := &fakeHost{createID: "s-1"}
	lines, err := run(t, host, `{"jsonrpc":"2.0","id":"a","method":"session/new","params":{"cwd":"/work","mcpServers":[]}}`+"\n")
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if len(lines) != 1 || lines[0].Error != nil {
		t.Fatalf("lines = %+v", lines)
	}
	var res struct {
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(lines[0].Result, &res); err != nil {
		t.Fatalf("result: %v", err)
	}
	if res.SessionID != "s-1" || host.createCwd != "/work" {
		t.Fatalf("res=%+v cwd=%q", res, host.createCwd)
	}
	if string(lines[0].ID) != `"a"` {
		t.Fatalf("id = %s", lines[0].ID)
	}
}

func TestSessionNewErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		host Host
		line string
		code int
	}{
		{"host error", &fakeHost{createErr: errors.New("boom")}, `{"jsonrpc":"2.0","id":1,"method":"session/new","params":{}}`, CodeInternalError},
		{"empty id", &fakeHost{}, `{"jsonrpc":"2.0","id":1,"method":"session/new","params":{}}`, CodeInternalError},
		{"bad params", &fakeHost{}, `{"jsonrpc":"2.0","id":1,"method":"session/new","params":"x"}`, CodeInvalidParams},
		{"nil host", nil, `{"jsonrpc":"2.0","id":1,"method":"session/new","params":{}}`, CodeInternalError},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			lines, err := run(t, tt.host, tt.line+"\n")
			if err != nil {
				t.Fatalf("Serve: %v", err)
			}
			if len(lines) != 1 || lines[0].Error == nil || lines[0].Error.Code != tt.code {
				t.Fatalf("lines = %+v", lines)
			}
		})
	}
}

func TestPromptStreaming(t *testing.T) {
	t.Parallel()
	host := &fakeHost{chunks: []string{"hello", " world"}, stopReason: "max_tokens"}
	in := `{"jsonrpc":"2.0","id":7,"method":"session/prompt","params":{"sessionId":"s-1","prompt":[{"type":"text","text":"hi"},{"type":"image","data":"x"}]}}` + "\n"
	lines, err := run(t, host, in)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if !host.promptCalled || host.promptSID != "s-1" || host.promptText != "hi" {
		t.Fatalf("host = %+v", host)
	}
	if len(lines) != 3 {
		t.Fatalf("lines = %d, want 2 notifications + 1 response: %+v", len(lines), lines)
	}
	for i, want := range []string{"hello", " world"} {
		if lines[i].Method != "session/update" || lines[i].ID != nil {
			t.Fatalf("notification[%d] = %+v", i, lines[i])
		}
		var p sessionUpdateParams
		if err := json.Unmarshal(lines[i].Params, &p); err != nil {
			t.Fatal(err)
		}
		if p.SessionID != "s-1" || p.Update.SessionUpdate != "agent_message_chunk" ||
			p.Update.Content.Type != "text" || p.Update.Content.Text != want {
			t.Fatalf("notification[%d] params = %+v", i, p)
		}
	}
	var res struct {
		StopReason string `json:"stopReason"`
	}
	if err := json.Unmarshal(lines[2].Result, &res); err != nil {
		t.Fatal(err)
	}
	if res.StopReason != "max_tokens" {
		t.Fatalf("stopReason = %q", res.StopReason)
	}
}

func TestPromptStringCompatAndDefaultStop(t *testing.T) {
	t.Parallel()
	host := &fakeHost{}
	lines, err := run(t, host, `{"jsonrpc":"2.0","id":1,"method":"session/prompt","params":{"sessionId":"s","prompt":"  plain  "}}`+"\n")
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if host.promptText != "plain" {
		t.Fatalf("promptText = %q", host.promptText)
	}
	if len(lines) != 1 || lines[0].Error != nil {
		t.Fatalf("lines = %+v", lines)
	}
	var res struct {
		StopReason string `json:"stopReason"`
	}
	if err := json.Unmarshal(lines[0].Result, &res); err != nil {
		t.Fatal(err)
	}
	if res.StopReason != StopEndTurn {
		t.Fatalf("stopReason = %q, want %q", res.StopReason, StopEndTurn)
	}
}

func TestPromptErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		host *fakeHost
		line string
		code int
	}{
		{"missing session", &fakeHost{}, `{"jsonrpc":"2.0","id":1,"method":"session/prompt","params":{"prompt":"x"}}`, CodeInvalidParams},
		{"empty prompt", &fakeHost{}, `{"jsonrpc":"2.0","id":1,"method":"session/prompt","params":{"sessionId":"s","prompt":[]}}`, CodeInvalidParams},
		{"bad prompt type", &fakeHost{}, `{"jsonrpc":"2.0","id":1,"method":"session/prompt","params":{"sessionId":"s","prompt":3}}`, CodeInvalidParams},
		{"bad params", &fakeHost{}, `{"jsonrpc":"2.0","id":1,"method":"session/prompt","params":"x"}`, CodeInvalidParams},
		{"host failure", &fakeHost{promptErr: errors.New("engine down")}, `{"jsonrpc":"2.0","id":1,"method":"session/prompt","params":{"sessionId":"s","prompt":"x"}}`, CodeInternalError},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			lines, err := run(t, tt.host, tt.line+"\n")
			if err != nil {
				t.Fatalf("Serve: %v", err)
			}
			if len(lines) != 1 || lines[0].Error == nil || lines[0].Error.Code != tt.code {
				t.Fatalf("lines = %+v", lines)
			}
		})
	}
}

func TestMethodNotFoundAndUnknownNotification(t *testing.T) {
	t.Parallel()
	in := `{"jsonrpc":"2.0","id":1,"method":"session/load","params":{}}` + "\n" +
		`{"jsonrpc":"2.0","method":"fs/read_text_file","params":{}}` + "\n"
	lines, err := run(t, &fakeHost{}, in)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if len(lines) != 1 {
		t.Fatalf("lines = %+v, want only request error", lines)
	}
	if lines[0].Error == nil || lines[0].Error.Code != CodeMethodNotFound {
		t.Fatalf("error = %+v", lines[0].Error)
	}
}

func TestNoiseSkipped(t *testing.T) {
	t.Parallel()
	in := "\nnot-json\n" + `{"jsonrpc":"2.0","id":1,"method":"initialize"}` + "\n"
	lines, err := run(t, &fakeHost{}, in)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if len(lines) != 1 || lines[0].Error != nil {
		t.Fatalf("lines = %+v", lines)
	}
}

func TestCancel(t *testing.T) {
	t.Parallel()
	host := &fakeHost{}
	in := `{"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":"s-9"}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"session/cancel","params":{"sessionId":"s-9"}}` + "\n"
	lines, err := run(t, host, in)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if host.canceledSID != "s-9" {
		t.Fatalf("canceledSID = %q", host.canceledSID)
	}
	if len(lines) != 1 || lines[0].Error != nil {
		t.Fatalf("lines = %+v, want 1 response for request form", lines)
	}
}

func TestEOFReturnsNil(t *testing.T) {
	t.Parallel()
	lines, err := run(t, &fakeHost{}, "")
	if err != nil || len(lines) != 0 {
		t.Fatalf("lines=%+v err=%v", lines, err)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("pipe closed") }

func TestWriterFailureStopsServe(t *testing.T) {
	t.Parallel()
	host := &fakeHost{chunks: []string{"chunk"}}
	srv := NewServer(host, strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"session/prompt","params":{"sessionId":"s","prompt":"x"}}`+"\n"), failWriter{})
	if err := srv.Serve(t.Context()); err == nil {
		t.Fatal("写侧失败应终止 Serve")
	}
}

func TestMaxLineBytes(t *testing.T) {
	t.Parallel()
	srv := NewServer(&fakeHost{}, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`+"\n"), &bytes.Buffer{})
	srv.MaxLineBytes = 8
	if err := srv.Serve(t.Context()); err == nil {
		t.Fatal("超长行应报错（bufio.Scanner 上限）")
	}
}
