package openaicompat

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// 缺省装配参数（与 bianque internal/openaicompat 的部署形态一致）。
const (
	DefaultAddr              = "127.0.0.1:8977"
	DefaultTurnTimeout       = 10 * time.Minute
	DefaultHeartbeatInterval = 15 * time.Second
	DefaultMaxBodyBytes      = int64(1 << 20)
)

// SessionResult 宿主会话终态视图。
type SessionResult struct {
	// Succeeded 终态是否成功（成功=final_report 可取）。
	Succeeded bool
	// Status 宿主终态名（失败说明/审计用；成功态可空）。
	Status string
	// FinalReport 定稿报告全文（可空）。
	FinalReport string
}

// Host 宿主会话缝：创建 / 等终态 / 取消三个方法。产品会话模型（gorm /
// 专家钉住 / policy 档位 / 鉴权策略）留在宿主适配层，协议面零依赖。
type Host interface {
	// CreateSession 为一次 chat/completions 请求创建一次性会话。
	CreateSession(ctx context.Context, turn Turn) (sessionID string, err error)
	// WaitTerminal 阻塞/轮询直到会话进入终态。
	WaitTerminal(ctx context.Context, sessionID string) (SessionResult, error)
	// Cancel 取消在途轮（客户端断连/超时收口，不留烧 LLM 的孤儿会话）。
	Cancel(ctx context.Context, sessionID string) error
}

// EventSource 事件总线缝：实现方注入 Subscribe。约定从会话起点投递
// （先回放缓冲/持久化事件，再接实时流）；返回的 unsub 必须可重复安全调用
// （包只调用一次）。通道关闭视为「实时侧结束」，本包随后走终态对账。
type EventSource interface {
	Subscribe(sessionID string) (<-chan Event, func())
}

// Authorizer 可选的宿主鉴权缝：Host 实现本接口时由宿主判定请求是否放行
// （JWT / 网关头 / 租户校验等产品策略）。未实现时回落到 Config.Token 的
// Bearer 常量时间比对；Token 为空且未实现本接口=恒 401（不提供裸奔模式）。
type Authorizer interface {
	Authorize(r *http.Request) bool
}

// Config 服务侧配置。
type Config struct {
	// Token Bearer 令牌（空=未实现 Authorizer 时 Handler 恒 401）。
	Token string
	// Addr 监听地址（空=DefaultAddr）。
	Addr string
	// TurnTimeout 单请求收敛上限（<=0=DefaultTurnTimeout）。
	TurnTimeout time.Duration
	// HeartbeatInterval SSE 心跳注释帧周期（<=0=DefaultHeartbeatInterval）。
	HeartbeatInterval time.Duration
	// MaxBodyBytes 请求体读上限（<=0=DefaultMaxBodyBytes）。
	MaxBodyBytes int64
}

// AddrOrDefault 监听地址（空=缺省 127.0.0.1:8977）。
func (c Config) AddrOrDefault() string {
	if c.Addr != "" {
		return c.Addr
	}
	return DefaultAddr
}

func (c Config) turnTimeout() time.Duration {
	if c.TurnTimeout > 0 {
		return c.TurnTimeout
	}
	return DefaultTurnTimeout
}

func (c Config) heartbeatInterval() time.Duration {
	if c.HeartbeatInterval > 0 {
		return c.HeartbeatInterval
	}
	return DefaultHeartbeatInterval
}

func (c Config) maxBodyBytes() int64 {
	if c.MaxBodyBytes > 0 {
		return c.MaxBodyBytes
	}
	return DefaultMaxBodyBytes
}

// Server OpenAI 兼容形态（host/events 注入；token 逐请求校验）。
type Server struct {
	host        Host
	events      EventSource
	token       string
	addr        string
	turnTimeout time.Duration
	heartbeat   time.Duration
	maxBody     int64
	// now 测试缝（帧头 created 取值）。
	now func() time.Time
}

// New 构造（token 空=装配侧拒绝启动；此处防御性降级为恒 401）。
func New(host Host, events EventSource, cfg Config) *Server {
	return &Server{
		host:        host,
		events:      events,
		token:       cfg.Token,
		addr:        cfg.AddrOrDefault(),
		turnTimeout: cfg.turnTimeout(),
		heartbeat:   cfg.heartbeatInterval(),
		maxBody:     cfg.maxBodyBytes(),
		now:         time.Now,
	}
}

// Handler 带鉴权的 HTTP 处理器（assembly 侧装进独立 net/http）。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/chat/completions", s.handleChatCompletions)
	mux.HandleFunc("GET /v1/models", s.handleModels)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="openai-compat"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// Start 阻塞监听（assembly 侧后台协程；端口占用=启动失败上抛）。超时/头部
// 上限对齐主服务面；不设 WriteTimeout——SSE 是长响应流，按响应起点计的写
// 超时会掐断正常流。
func (s *Server) Start() error {
	srv := &http.Server{
		Addr:              s.addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	return srv.ListenAndServe()
}

// authorized 鉴权：Host 实现 Authorizer 时交给宿主（产品策略）；否则常量
// 时间比对 Bearer token（时序侧信道防护）。Token 为空且无宿主鉴权=恒拒。
func (s *Server) authorized(r *http.Request) bool {
	if a, ok := s.host.(Authorizer); ok {
		return a.Authorize(r)
	}
	if s.token == "" {
		return false
	}
	bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || bearer == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(bearer), []byte(s.token)) == 1
}

// handleModels 最小清单面（部分 SDK 启动即探活 /v1/models；返回空清单不
// 误导——model 字段的语义是「专家 slug 或任意别名」，非静态模型目录）。
func (s *Server) handleModels(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"object":"list","data":[]}`)
}

// handleChatCompletions 主流程：解码 → 协议翻译 → 建宿主会话 → 流式/等待。
func (s *Server) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	if s.host == nil {
		writeAPIError(w, http.StatusInternalServerError, "host 未配置")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, s.maxBody))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req, err := DecodeChatRequest(body)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	turn, err := TranslateRequest(req)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.turnTimeout)
	defer cancel()
	sessionID, err := s.host.CreateSession(ctx, turn)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "建会话失败: "+err.Error())
		return
	}
	if req.Stream {
		s.serveStream(ctx, w, r, sessionID, req.Model)
		return
	}
	s.serveWait(ctx, w, sessionID, req.Model)
}

// serveStream SSE 投影：订阅事件 → chunk 帧 → turn 括号关闭收口 → 终态对账
// 兜底（通道提前关闭/丢帧时用终报全文或失败说明补齐）。心跳注释帧防中间层
// 空闲超时。
func (s *Server) serveStream(ctx context.Context, w http.ResponseWriter, r *http.Request,
	sessionID, modelName string) {
	fl, ok := w.(http.Flusher)
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "流式输出需要 ResponseWriter 支持 Flusher")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fl.Flush()

	p := NewProjector("chatcmpl-"+sessionID, modelName, s.now().Unix())
	var ch <-chan Event
	if s.events != nil {
		var unsub func()
		ch, unsub = s.events.Subscribe(sessionID)
		if unsub != nil {
			defer unsub()
		}
	}

	write := func(raw string) bool {
		if _, err := io.WriteString(w, raw); err != nil {
			return false
		}
		fl.Flush()
		return true
	}
	writeChunk := func(c Chunk) bool {
		b, err := EncodeChunk(c)
		if err != nil {
			return true // 帧结构固定，实际不可达；单帧失败不掐整条流
		}
		return write("data: " + string(b) + "\n\n")
	}

	var lastID uint64
	if ch != nil {
		ticker := time.NewTicker(s.heartbeat)
		defer ticker.Stop()
	loop:
		for !p.Done() {
			select {
			case <-ctx.Done():
				s.cancelQuietly(sessionID)
				return
			case <-r.Context().Done(): // 客户端断连
				s.cancelQuietly(sessionID)
				return
			case <-ticker.C:
				if !write(": keepalive\n\n") {
					s.cancelQuietly(sessionID)
					return
				}
			case ev, ok := <-ch:
				if !ok {
					break loop
				}
				if ev.ID != 0 { // 回放 + 实时重叠按 ID 幂等去重（0=未编号不过滤）
					if ev.ID <= lastID {
						continue
					}
					lastID = ev.ID
				}
				for _, c := range p.Project(ev) {
					if !writeChunk(c) {
						s.cancelQuietly(sessionID)
						return
					}
				}
			}
		}
	}

	// 终态对账：成功且一帧正文都没投影=终报全文兜底；非成功态补状态说明
	// （局部丢帧以事件流为准，这里只补终态语义）。
	if res, err := s.host.WaitTerminal(ctx, sessionID); err == nil {
		if !res.Succeeded {
			if !writeChunk(p.FailureChunk(res.Status)) {
				s.cancelQuietly(sessionID)
				return
			}
		} else if res.FinalReport != "" && !p.ContentEmitted() {
			if !writeChunk(p.ContentChunk(res.FinalReport)) {
				s.cancelQuietly(sessionID)
				return
			}
		}
	}
	if !writeChunk(p.Finish()) {
		s.cancelQuietly(sessionID)
		return
	}
	_ = write("data: [DONE]\n\n")
}

// cancelQuietly 断连/异常收口：取消在途轮（不留烧 LLM 的孤儿会话）。
func (s *Server) cancelQuietly(sessionID string) {
	if s.host == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.host.Cancel(ctx, sessionID)
}

// serveWait 非流式：等终态一次返回 chat.completion（content=终报全文，等价
// 流式累积）。
func (s *Server) serveWait(ctx context.Context, w http.ResponseWriter, sessionID, modelName string) {
	res, err := s.host.WaitTerminal(ctx, sessionID)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			writeAPIError(w, http.StatusGatewayTimeout, "会话未在时限内收敛")
			return
		}
		writeAPIError(w, http.StatusBadGateway, "会话查询失败: "+err.Error())
		return
	}
	content := res.FinalReport
	if !res.Succeeded {
		content += failureNote(res.Status)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(NewCompletion(
		"chatcmpl-"+sessionID, modelName, s.now().Unix(), content))
}

// writeAPIError OpenAI 风格错误体（{error:{message,type}}）。
func writeAPIError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"message": msg, "type": "invalid_request_error"},
	})
}
