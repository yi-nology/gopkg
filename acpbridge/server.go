package acpbridge

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// JSON-RPC 2.0 错误码（协议标准值）。
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
)

// ProtocolVersion 本桥实现了的 ACP 协议版本。
const ProtocolVersion = 1

// StopEndTurn 宿主未指定 stopReason 时的缺省值（ACP 正常结束）。
const StopEndTurn = "end_turn"

// Host 宿主接口缝：协议桥只认这三个动作。
type Host interface {
	// CreateSession 创建一个真实会话，返回 ACP 侧使用的不透明 id。
	// cwd 是 IDE 侧工作目录（可为空，由宿主决定是否使用）。
	CreateSession(ctx context.Context, cwd string) (sessionID string, err error)
	// Prompt 执行一轮提示。emit 把增量文本交回桥（桥转成
	// agent_message_chunk 通知）；emit 返回错误说明写侧已断，宿主应尽快
	// 结束本轮。stopReason 为空时桥用 "end_turn"。
	Prompt(ctx context.Context, sessionID, text string, emit func(text string) error) (stopReason string, err error)
}

// Canceler 可选接口：宿主实现后 session/cancel 通知会转给它。
type Canceler interface {
	Cancel(ctx context.Context, sessionID string) error
}

// Server ACP stdio 桥。零值不可用；用 [NewServer] 构造。
type Server struct {
	Host Host
	In   io.Reader
	Out  io.Writer

	// MaxLineBytes 单行上限；<=0 用 4MB。
	MaxLineBytes int
	// AgentName / AgentVersion 写进 initialize 的 agentInfo。
	AgentName    string
	AgentVersion string
}

// NewServer 构造桥。
func NewServer(host Host, in io.Reader, out io.Writer) *Server {
	return &Server{Host: host, In: in, Out: out}
}

// Serve 便捷入口：构造桥并阻塞运行。
func Serve(ctx context.Context, host Host, in io.Reader, out io.Writer) error {
	return NewServer(host, in, out).Serve(ctx)
}

// rpcRequest JSON-RPC 请求/通知。ID 为 nil 表示通知。
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// RPCError JSON-RPC 错误对象（导出给宿主在自定义包装里复用）。
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("acpbridge: rpc error %d: %s", e.Code, e.Message)
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

type rpcNotification struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

// sessionUpdateParams session/update 通知参数（agent_message_chunk）。
type sessionUpdateParams struct {
	SessionID string `json:"sessionId"`
	Update    struct {
		SessionUpdate string `json:"sessionUpdate"`
		Content       struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	} `json:"update"`
}

func newChunkNotification(sessionID, text string) rpcNotification {
	var p sessionUpdateParams
	p.SessionID = sessionID
	p.Update.SessionUpdate = "agent_message_chunk"
	p.Update.Content.Type = "text"
	p.Update.Content.Text = text
	return rpcNotification{JSONRPC: "2.0", Method: "session/update", Params: p}
}

// Serve 逐行读 JSON-RPC 并写响应/通知；EOF 返回 nil。
func (s *Server) Serve(ctx context.Context) error {
	if s.In == nil || s.Out == nil {
		return errors.New("acpbridge: In/Out 未配置")
	}
	sc := bufio.NewScanner(s.In)
	max := s.MaxLineBytes
	if max <= 0 {
		max = 4 << 20
	}
	initial := max
	if initial > 64*1024 {
		initial = 64 * 1024
	}
	sc.Buffer(make([]byte, 0, initial), max)
	w := bufio.NewWriter(s.Out)
	defer func() { _ = w.Flush() }()

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil || req.Method == "" {
			// stdio 噪声/用户误用：跳过而不崩（IDE 会反复拉起桥进程）。
			continue
		}
		resp, err := s.dispatch(ctx, &req, w)
		if err != nil {
			return err
		}
		if resp != nil {
			if err := writeLine(w, resp); err != nil {
				return err
			}
		}
		if err := w.Flush(); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return sc.Err()
}

func writeLine(w *bufio.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("acpbridge: 帧编码失败: %w", err)
	}
	if _, err := w.Write(append(data, '\n')); err != nil {
		return err
	}
	return nil
}

// dispatch 方法分发：返回响应（通知为 nil）。流式通知经 emit 直接写
// w 并立即刷出；写侧错误冒泡为 Serve 的终止错误。
func (s *Server) dispatch(ctx context.Context, req *rpcRequest, w *bufio.Writer) (*rpcResponse, error) {
	isNotification := len(req.ID) == 0 || string(req.ID) == "null"
	switch req.Method {
	case "initialize":
		return s.ok(req, map[string]any{
			"protocolVersion": ProtocolVersion,
			"agentCapabilities": map[string]any{
				"loadSession":        false,
				"promptCapabilities": map[string]bool{},
			},
			"agentInfo": map[string]string{
				"name":    s.agentName(),
				"version": s.agentVersion(),
			},
			"authMethods": []any{},
		}), nil

	case "session/new":
		var p struct {
			Cwd        string `json:"cwd"`
			MCPServers any    `json:"mcpServers"`
		}
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &p); err != nil {
				return errResp(req, CodeInvalidParams, "params 非法: "+err.Error()), nil
			}
		}
		if s.Host == nil {
			return errResp(req, CodeInternalError, "宿主未装配"), nil
		}
		sid, err := s.Host.CreateSession(ctx, p.Cwd)
		if err != nil {
			return errResp(req, CodeInternalError, err.Error()), nil
		}
		if sid == "" {
			return errResp(req, CodeInternalError, "宿主返回空 sessionId"), nil
		}
		return s.ok(req, map[string]string{"sessionId": sid}), nil

	case "session/prompt":
		var p struct {
			SessionID string          `json:"sessionId"`
			Prompt    json.RawMessage `json:"prompt"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return errResp(req, CodeInvalidParams, "params 非法: "+err.Error()), nil
		}
		if strings.TrimSpace(p.SessionID) == "" {
			return errResp(req, CodeInvalidParams, "sessionId 必填"), nil
		}
		text, err := promptText(p.Prompt)
		if err != nil {
			return errResp(req, CodeInvalidParams, err.Error()), nil
		}
		if s.Host == nil {
			return errResp(req, CodeInternalError, "宿主未装配"), nil
		}
		emit := func(chunk string) error {
			if chunk == "" {
				return nil
			}
			// 立即写出并刷出：IDE 期待流式增量，不能等本轮结束才一起发。
			if err := writeLine(w, newChunkNotification(p.SessionID, chunk)); err != nil {
				return err
			}
			return w.Flush()
		}
		reason, err := s.Host.Prompt(ctx, p.SessionID, text, emit)
		if err != nil {
			return errResp(req, CodeInternalError, err.Error()), nil
		}
		if reason == "" {
			reason = StopEndTurn
		}
		return s.ok(req, map[string]string{"stopReason": reason}), nil

	case "session/cancel":
		var p struct {
			SessionID string `json:"sessionId"`
		}
		_ = json.Unmarshal(req.Params, &p)
		if c, ok := s.Host.(Canceler); ok && s.Host != nil && p.SessionID != "" {
			_ = c.Cancel(ctx, p.SessionID)
		}
		if isNotification {
			return nil, nil
		}
		return s.ok(req, map[string]any{}), nil

	default:
		if isNotification {
			return nil, nil // 未知通知静默忽略（JSON-RPC 规范）
		}
		return errResp(req, CodeMethodNotFound, "method not found: "+req.Method), nil
	}
}

// promptText 从 ACP prompt 参数提取文本：支持 ACP v1 的 content block
// 数组（取 type=text）与参考实现的裸字符串兼容形态。
func promptText(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", errors.New("prompt 不能为空")
	}
	var plain string
	if err := json.Unmarshal(raw, &plain); err == nil {
		plain = strings.TrimSpace(plain)
		if plain == "" {
			return "", errors.New("prompt 不能为空")
		}
		return plain, nil
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return "", errors.New("prompt 必须是字符串或 content block 数组")
	}
	var b strings.Builder
	for _, block := range blocks {
		if block.Type == "text" {
			b.WriteString(block.Text)
		}
	}
	out := strings.TrimSpace(b.String())
	if out == "" {
		return "", errors.New("prompt 不能为空")
	}
	return out, nil
}

func (s *Server) ok(req *rpcRequest, result any) *rpcResponse {
	return &rpcResponse{JSONRPC: "2.0", ID: idOrNull(req.ID), Result: result}
}

func errResp(req *rpcRequest, code int, msg string) *rpcResponse {
	return &rpcResponse{JSONRPC: "2.0", ID: idOrNull(req.ID), Error: &RPCError{Code: code, Message: msg}}
}

func idOrNull(id json.RawMessage) json.RawMessage {
	if len(id) == 0 {
		return json.RawMessage("null")
	}
	return id
}

func (s *Server) agentName() string {
	if s.AgentName != "" {
		return s.AgentName
	}
	return "gopkg acpbridge"
}

func (s *Server) agentVersion() string {
	if s.AgentVersion != "" {
		return s.AgentVersion
	}
	return "1"
}
