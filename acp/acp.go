package acp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// JSON-RPC 2.0 错误码（协议标准值，客户端按码分支）。
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
)

// 本包实现的方法名（ACP v1 子集）。
const (
	MethodInitialize    = "initialize"
	MethodSessionNew    = "session/new"
	MethodSessionPrompt = "session/prompt"
)

// ProtocolVersion initialize 回包的 ACP 协议版本（v1）。
const ProtocolVersion = 1

// DefaultMaxFrameBytes 单帧读上限（4 MiB：长提示/粘贴日志；与 bianque 桥一致）。
const DefaultMaxFrameBytes = 4 << 20

// Options 协议面配置（宿主产品词表在此注入，协议逻辑不内置产品名）。
type Options struct {
	// AgentName initialize 的 agentCard.name（空=「ACP Agent」）。
	AgentName string
	// AgentDescription initialize 的 agentCard.description（空=通用描述）。
	AgentDescription string
	// MaxFrameBytes 单帧读上限（<=0=DefaultMaxFrameBytes）。
	MaxFrameBytes int
}

func (o Options) maxFrameBytes() int {
	if o.MaxFrameBytes > 0 {
		return o.MaxFrameBytes
	}
	return DefaultMaxFrameBytes
}

func (o Options) agentName() string {
	if o.AgentName != "" {
		return o.AgentName
	}
	return "ACP Agent"
}

func (o Options) agentDescription() string {
	if o.AgentDescription != "" {
		return o.AgentDescription
	}
	return "Agent Client Protocol bridge"
}

// SessionRequest 首问建宿主会话的入参（钉专家/入口等宿主参数由 Host 实现
// 从自己的配置补齐，协议面只传首轮输入）。
type SessionRequest struct {
	Input string
}

// SessionResult 宿主会话终态。
type SessionResult struct {
	// Succeeded 终态是否成功（成功=有定稿报告可取）。
	Succeeded bool
	// Status 宿主终态名（仅用于错误文案，成功态可空）。
	Status string
	// FinalReport 定稿报告全文（可空）。
	FinalReport string
}

// Host 宿主交互缝：创建会话 / 多轮投递 / 轮询终态三个方法。实现方把自家
// HTTP API 或引擎接到这里（bianque 适配层打自家 /api/v1/sessions），协议面
// 不 import 任何宿主包。
type Host interface {
	// CreateSession 创建宿主会话并返回宿主会话号（首问调用一次）。
	CreateSession(ctx context.Context, req SessionRequest) (sessionID string, err error)
	// SendInput 向已有宿主会话投递追问文本。
	SendInput(ctx context.Context, sessionID, text string) error
	// WaitTerminal 阻塞/轮询直到会话进入终态并返回终态视图。
	WaitTerminal(ctx context.Context, sessionID string) (SessionResult, error)
}

// RPCError JSON-RPC 错误对象；方法处理器返回它即按指定 code 回错误帧，
// 返回普通 error 统一映射为 -32603。
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Error 实现 error。
func (e *RPCError) Error() string {
	return fmt.Sprintf("jsonrpc %d: %s", e.Code, e.Message)
}

// Errorf 构造 RPCError。
func Errorf(code int, format string, args ...any) *RPCError {
	return &RPCError{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Request JSON-RPC 请求/通知帧（id 缺省或为 null = 通知）。
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// IsNotification 无 id（缺省或 null）即通知：照常执行，永不回包。
func (r Request) IsNotification() bool {
	return len(r.ID) == 0 || bytes.Equal(bytes.TrimSpace(r.ID), []byte("null"))
}

// Response JSON-RPC 响应帧（result 与 error 二选一）。
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// Notification JSON-RPC 通知帧（服务端主动发 session/update）。
type Notification struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

// MethodHandler 可注册的方法处理器（返回值编码为 result；返回 *RPCError
// 保留其 code，其余 error 映射 -32603）。
type MethodHandler func(ctx context.Context, params json.RawMessage) (any, error)

// methodFunc 内部处理器（可携带需先于响应下发的通知）。
type methodFunc func(ctx context.Context, params json.RawMessage) (any, []Notification, error)

// Bridge ACP 桥状态：方法表 + ACP 会话号 → 宿主会话号映射。由 New 构造，
// Serve 串行处理帧。
type Bridge struct {
	host     Host
	opts     Options
	methods  map[string]methodFunc
	sessions map[string]string
	nextID   int
}

// New 构造桥。host 为 nil 时 initialize/session/new 可用，session/prompt
// 回 -32603（协议面可被探活而不强制宿主就绪）。
func New(host Host, opts Options) *Bridge {
	b := &Bridge{
		host:     host,
		opts:     opts,
		methods:  make(map[string]methodFunc, 3),
		sessions: make(map[string]string),
	}
	b.methods[MethodInitialize] = b.handleInitialize
	b.methods[MethodSessionNew] = b.handleSessionNew
	b.methods[MethodSessionPrompt] = b.handleSessionPrompt
	return b
}

// Handle 注册/覆盖方法处理器（宿主扩展方法；未注册方法回 -32601）。
func (b *Bridge) Handle(method string, h MethodHandler) {
	b.methods[method] = func(ctx context.Context, params json.RawMessage) (any, []Notification, error) {
		v, err := h(ctx, params)
		return v, nil, err
	}
}

// Serve 包级入口：构造一次性 Bridge 并处理 stdio（context.Background）。
// 返回 nil 于 EOF。
func Serve(in io.Reader, out io.Writer, host Host, opts Options) error {
	return New(host, opts).Serve(context.Background(), in, out)
}

// ServeContext 可取消版本：ctx 取消后，进行中的 host 调用随 ctx 收敛。
func ServeContext(ctx context.Context, in io.Reader, out io.Writer, host Host, opts Options) error {
	return New(host, opts).Serve(ctx, in, out)
}

// Serve 逐行读 JSON-RPC 帧、路由、逐行写响应/通知。返回 nil 于 EOF。
func (b *Bridge) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), b.opts.maxFrameBytes())
	w := bufio.NewWriter(out)
	defer func() { _ = w.Flush() }()
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		resp, notifications := b.handleFrame(ctx, line)
		for _, n := range notifications {
			if err := writeLine(w, n); err != nil {
				return err
			}
		}
		if resp != nil {
			if err := writeLine(w, resp); err != nil {
				return err
			}
		}
		if err := w.Flush(); err != nil {
			return err
		}
	}
	return sc.Err()
}

// handleFrame 单帧解析 + 路由（通知先于响应下发）。
func (b *Bridge) handleFrame(ctx context.Context, line []byte) (*Response, []Notification) {
	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		return errorResponse(nil, CodeParseError, "parse error: "+err.Error()), nil
	}
	if req.JSONRPC != "2.0" || req.Method == "" || !validID(req.ID) {
		return errorResponse(req.ID, CodeInvalidRequest, "invalid request"), nil
	}
	h, ok := b.methods[req.Method]
	if !ok {
		if req.IsNotification() {
			return nil, nil // 通知永不回包（含未知方法）
		}
		return errorResponse(req.ID, CodeMethodNotFound, "method not found: "+req.Method), nil
	}
	result, notifications, err := h(ctx, req.Params)
	if req.IsNotification() {
		return nil, notifications
	}
	if err != nil {
		var rpcErr *RPCError
		if errors.As(err, &rpcErr) {
			return &Response{JSONRPC: "2.0", ID: req.ID, Error: rpcErr}, notifications
		}
		return errorResponse(req.ID, CodeInternalError, err.Error()), notifications
	}
	return &Response{JSONRPC: "2.0", ID: req.ID, Result: result}, notifications
}

func errorResponse(id json.RawMessage, code int, msg string) *Response {
	return &Response{JSONRPC: "2.0", ID: id, Error: &RPCError{Code: code, Message: msg}}
}

// validID id 只允许字符串/数字（JSON-RPC 2.0）；对象/数组/布尔=非法请求。
func validID(raw json.RawMessage) bool {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return true
	}
	return raw[0] == '"' || raw[0] == '-' || (raw[0] >= '0' && raw[0] <= '9')
}

func writeLine(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(data, '\n'))
	return err
}
