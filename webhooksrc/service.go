package webhooksrc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Config Service 装配参数。零值字段取默认值；Sources/Sink 为必填
// （缺失时 Ingest 以 500 原因码显形，不静默丢事件）。
type Config struct {
	Sources SourceStore
	Events  EventStore
	Sink    Sink
	Clock   Clock

	MaxBodyBytes  int
	MaxInputBytes int
	PayloadCap    int
	RateWindow    time.Duration
	Retention     time.Duration
	// Snapshot 载荷快照钩子：宿主在此做脱敏/截断；nil 时原文截断。
	Snapshot func(body []byte) string
}

// Service 五段管道。
type Service struct {
	Sources SourceStore
	Events  EventStore
	Sink    Sink
	Clock   Clock

	MaxBodyBytes  int
	MaxInputBytes int
	PayloadCap    int
	RateWindow    time.Duration
	Retention     time.Duration
	Snapshot      func(body []byte) string

	rlMu    sync.Mutex
	windows map[string]*rateWindow
}

type rateWindow struct {
	limit int
	hits  []time.Time
}

// New 构造 Service 并填默认值。
func New(cfg Config) *Service {
	s := &Service{
		Sources: cfg.Sources, Events: cfg.Events, Sink: cfg.Sink, Clock: cfg.Clock,
		MaxBodyBytes: cfg.MaxBodyBytes, MaxInputBytes: cfg.MaxInputBytes,
		PayloadCap: cfg.PayloadCap, RateWindow: cfg.RateWindow, Retention: cfg.Retention,
		Snapshot: cfg.Snapshot, windows: map[string]*rateWindow{},
	}
	if s.MaxBodyBytes <= 0 {
		s.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if s.MaxInputBytes <= 0 {
		s.MaxInputBytes = DefaultMaxInputBytes
	}
	if s.PayloadCap <= 0 {
		s.PayloadCap = DefaultPayloadCap
	}
	if s.RateWindow <= 0 {
		s.RateWindow = DefaultRateWindow
	}
	if s.Retention <= 0 {
		s.Retention = DefaultRetention
	}
	if s.Clock == nil {
		s.Clock = realClock{}
	}
	return s
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// Ingest 接入主流程：源查找 → 启停 → 鉴权 → 限频 → 载荷 → 过滤 → 模板 →
// 投递，每步落留痕。硬拒绝返回 [Rejection]（含原因码与建议 HTTP 状态）；
// 过滤未命中返回 Accepted=false 且 error=nil（送达成功、平台选择不响应）。
func (s *Service) Ingest(ctx context.Context, name string, req Request) (*Result, error) {
	snap := s.snapshot(req.Body)
	if s.Sources == nil {
		s.record(ctx, name, ReasonSinkError, "", snap)
		return nil, reject(ReasonSinkError, http.StatusInternalServerError, "源存储未装配")
	}
	src, err := s.Sources.Get(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("webhooksrc: 读取事件源失败: %w", err)
	}
	if src == nil {
		s.record(ctx, name, ReasonUnknownSource, "", snap)
		return nil, reject(ReasonUnknownSource, http.StatusNotFound, "事件源不存在: %s", name)
	}
	if !src.Enabled {
		s.record(ctx, name, ReasonDisabled, "", snap)
		return nil, reject(ReasonDisabled, http.StatusForbidden, "事件源已停用: %s", name)
	}
	// 第一段：鉴权（按源强制二选一）。
	if err := s.authenticate(src, req); err != nil {
		reason, _ := RejectionReason(err)
		s.record(ctx, name, reason, "", snap)
		return nil, err
	}
	// 第二段：限频（每源滑动窗口）。
	if !s.allowRate(name, src.RatePerMin) {
		s.record(ctx, name, ReasonRateLimited, "", snap)
		return nil, reject(ReasonRateLimited, http.StatusTooManyRequests,
			"事件源触发超限（%d/分钟）", src.RatePerMin)
	}
	// 载荷前置：必须是 JSON 对象（点路径过滤/模板的根形态）。
	if len(req.Body) > s.MaxBodyBytes {
		s.record(ctx, name, ReasonBadPayload, "", snap)
		return nil, reject(ReasonBadPayload, http.StatusRequestEntityTooLarge,
			"请求体超限（%d > %d）", len(req.Body), s.MaxBodyBytes)
	}
	var payload map[string]any
	if err := json.Unmarshal(req.Body, &payload); err != nil || payload == nil {
		msg := "载荷必须是 JSON 对象"
		if err != nil {
			msg += ": " + err.Error()
		}
		s.record(ctx, name, ReasonBadPayload, "", snap)
		return nil, reject(ReasonBadPayload, http.StatusBadRequest, "%s", msg)
	}
	// 第三段：过滤（全条目 AND；不命中静默放行不动作）。
	if ok, op := MatchFilters(src.Filters, payload); !ok {
		s.record(ctx, name, ReasonFiltered, "", snap)
		return &Result{Accepted: false, Reason: "filtered: " + op + " 未命中"}, nil
	}
	// 第四段：模板渲染。
	input := renderTemplate(src.Template, src.Name, payload, s.MaxInputBytes)
	// 第五段：投递（建会话/入队/事实卡是宿主 Sink 决策）。
	if s.Sink == nil {
		s.record(ctx, name, ReasonSinkError, input, snap)
		return nil, reject(ReasonSinkError, http.StatusInternalServerError, "投递面未装配")
	}
	if err := s.Sink.Deliver(ctx, src.Name, input); err != nil {
		s.record(ctx, name, ReasonSinkError, input, snap)
		return nil, &Rejection{Reason: ReasonSinkError, Status: http.StatusInternalServerError,
			Message: "事件投递失败", Cause: err}
	}
	s.record(ctx, name, "", input, snap)
	return &Result{Accepted: true, Input: input}, nil
}

// authenticate 第一段：Bearer 或 HMAC 按源二选一。配置非法按 bad_config
// 硬拒绝（配置错误不降级放行）。
func (s *Service) authenticate(src *Source, req Request) error {
	switch src.Auth.Mode {
	case AuthHMAC:
		header := src.Auth.SignatureHeader
		if header == "" {
			header = DefaultSignatureHeader
		}
		if !VerifyHMAC(src.Auth.Secret, req.Header.Get(header), req.Body) {
			return reject(ReasonBadSignature, http.StatusUnauthorized,
				"签名校验失败（%s: sha256=<hex>）", header)
		}
		return nil
	case AuthBearer:
		header := src.Auth.TokenHeader
		if header == "" {
			header = DefaultTokenHeader
		}
		if !VerifyBearer(src.Auth.Secret, req.Header.Get("Authorization"), req.Header.Get(header)) {
			return reject(ReasonBadToken, http.StatusUnauthorized,
				"鉴权失败（Authorization: Bearer <secret> 或 %s）", header)
		}
		return nil
	default:
		return reject(ReasonBadConfig, http.StatusInternalServerError,
			"事件源鉴权模式非法: %q", src.Auth.Mode)
	}
}

// allowRate 每源滑动窗口（0=不限）；同一源限额变更即重建窗口。
func (s *Service) allowRate(name string, perMin int) bool {
	if perMin <= 0 {
		return true
	}
	now := s.Clock.Now()
	s.rlMu.Lock()
	defer s.rlMu.Unlock()
	w := s.windows[name]
	if w == nil || w.limit != perMin {
		w = &rateWindow{limit: perMin}
		s.windows[name] = w
	}
	cut := now.Add(-s.rateWindow())
	kept := w.hits[:0]
	for _, hit := range w.hits {
		if hit.After(cut) && !hit.After(now) {
			kept = append(kept, hit)
		}
	}
	w.hits = kept
	if len(w.hits) >= w.limit {
		return false
	}
	w.hits = append(w.hits, now)
	return true
}

func (s *Service) rateWindow() time.Duration {
	if s.RateWindow > 0 {
		return s.RateWindow
	}
	return DefaultRateWindow
}

// ResetRateLimit 丢弃某源的滑动窗口（源配置变更/手工解限时用）。
func (s *Service) ResetRateLimit(name string) {
	s.rlMu.Lock()
	delete(s.windows, name)
	s.rlMu.Unlock()
}

// record 触发留痕（失败不阻断主流程——观测有损原则）。
func (s *Service) record(ctx context.Context, source, reason, input, snap string) {
	if s.Events == nil {
		return
	}
	status := EventAccepted
	if reason != "" {
		status = EventRejected
	}
	_ = s.Events.Record(ctx, &Event{
		Source: source, Status: status, Reason: reason, Input: input,
		Payload: snap, CreatedAt: s.Clock.Now(),
	})
}

// snapshot 载荷快照：宿主钩子优先，否则原文截断到 PayloadCap。
func (s *Service) snapshot(body []byte) string {
	if s.Snapshot != nil {
		return s.Snapshot(body)
	}
	capN := s.PayloadCap
	if capN <= 0 {
		capN = DefaultPayloadCap
	}
	if len(body) > capN {
		return string(body[:capN])
	}
	return string(body)
}

// ResetSecret 轮换源密钥（旧密钥立即失效；新密钥只在本次返回）。要求
// SourceStore 实现 [MutableSourceStore]。
func (s *Service) ResetSecret(ctx context.Context, name string) (string, error) {
	store, ok := s.Sources.(MutableSourceStore)
	if !ok {
		return "", errors.New("webhooksrc: 源存储不支持 Save（无法轮换密钥）")
	}
	src, err := store.Get(ctx, name)
	if err != nil {
		return "", err
	}
	if src == nil {
		return "", fmt.Errorf("webhooksrc: 事件源不存在: %s", name)
	}
	secret, err := GenerateSecret()
	if err != nil {
		return "", err
	}
	src.Auth.Secret = secret
	if err := store.Save(ctx, src); err != nil {
		return "", err
	}
	return secret, nil
}

// PruneEvents 清扫保留窗口外的留痕。
func (s *Service) PruneEvents(ctx context.Context) (int64, error) {
	if s.Events == nil {
		return 0, nil
	}
	cut := s.Clock.Now().Add(-s.Retention)
	return s.Events.Prune(ctx, cut)
}

// HTTPStatus 建议的响应状态：Accepted=true 或无错误时为 200；过滤未命中
// （Accepted=false, err=nil）也是 200。
func HTTPStatus(_ *Result, err error) int {
	if err != nil {
		return RejectionStatus(err)
	}
	return http.StatusOK
}

// ReasonOf 便捷取错误原因码（无则空串）。
func ReasonOf(err error) string {
	reason, _ := RejectionReason(err)
	return reason
}
