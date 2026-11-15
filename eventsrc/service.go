package eventsrc

import (
	"context"
	"crypto"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/oekit/concurrency/ratelimit"
	oekitwebhook "github.com/oekit/pkg/webhook"
)

// SourceStore 事件源存取（宿主持久化；Get 未命中返回 ErrSourceNotFound）。
type SourceStore interface {
	Get(ctx context.Context, name string) (*Source, error)
	List(ctx context.Context) ([]Source, error)
	Create(ctx context.Context, src *Source) error
	Save(ctx context.Context, src *Source) error
	Delete(ctx context.Context, name string) (bool, error)
}

// EventStore 留痕存取（宿主表；Record 失败不阻断管道——观测有损原则）。
// Prune 的 source 为空串表示由宿主自行决定孤儿事件的清扫口径。
type EventStore interface {
	Record(ctx context.Context, ev Event) error
	List(ctx context.Context, source string, limit int) ([]Event, error)
	Prune(ctx context.Context, source string, before time.Time) (int64, error)
}

// Sink 第五段投递回调（建会话/事实卡/任何内部动作由宿主实现）。
// 返回的 deliveryID 写入留痕（宿主语义，本包不解释）。
type Sink func(ctx context.Context, source, input string) (deliveryID string, err error)

// Event 一次触发的留痕条目。
type Event struct {
	Source     string    `json:"source"`
	Status     string    `json:"status"` // accepted|rejected
	Reason     string    `json:"reason,omitempty"`
	DeliveryID string    `json:"delivery_id,omitempty"`
	Payload    string    `json:"payload,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// Request 一次入站 webhook 请求（handler 只负责把 header/body 交进来）。
type Request struct {
	Name   string
	Header http.Header
	Body   []byte
}

// Result 接入结果。filtered 也是成功送达（Accepted=false），硬拒绝走 error。
type Result struct {
	Accepted   bool   `json:"accepted"`
	Reason     string `json:"reason,omitempty"`
	FilterOp   string `json:"filter_op,omitempty"`
	DeliveryID string `json:"delivery_id,omitempty"`
}

// Option Service 构造选项。
type Option func(*Service)

// WithClock 注入时钟（限频/留痕时间/清扫测试缝）。
func WithClock(fn func() time.Time) Option {
	return func(s *Service) {
		if fn != nil {
			s.now = fn
		}
	}
}

// WithSnapshot 注入留痕快照函数（宿主可加 PII 脱敏；nil 忽略）。
func WithSnapshot(fn func([]byte) string) Option {
	return func(s *Service) {
		if fn != nil {
			s.snapshot = fn
		}
	}
}

// WithRateWindow 注入限频窗口（缺省 1 分钟；<=0 panic fail-fast）。
func WithRateWindow(d time.Duration) Option {
	return func(s *Service) {
		if d <= 0 {
			panic("eventsrc: 限频窗口必须为正")
		}
		s.rateWindow = d
	}
}

// Service 五段管道编排（无状态存储；并发安全）。
type Service struct {
	sources    SourceStore
	events     EventStore
	sink       Sink
	now        func() time.Time
	snapshot   func([]byte) string
	rateWindow time.Duration

	rlMu    sync.Mutex
	windows map[string]*rateWindow
}

// rateWindow 源限频档（limit 配置变更即重建窗口，表达每源动态 rate_per_min）。
type rateWindow struct {
	perMin int
	sw     *ratelimit.SlidingWindow
}

// New 装配管道。sources 可为 nil（仅用 CRUD 之外的纯函数），但 Ingest 会返回
// ErrStoreUnavailable；sink 为 nil 时接受分支返回 ErrSink。
func New(sources SourceStore, events EventStore, sink Sink, opts ...Option) *Service {
	s := &Service{
		sources:    sources,
		events:     events,
		sink:       sink,
		now:        time.Now,
		snapshot:   Snapshot,
		rateWindow: time.Minute,
		windows:    map[string]*rateWindow{},
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s
}

// Ingest 五段管道：源查找/启停 → 鉴权 → 限频 → 载荷解析 → 过滤 → 模板 → 投递。
// 每步拒绝写留痕；留痕写失败不阻断主流程。硬拒绝返回 *RejectError（含建议
// HTTP 状态码），filtered 走 Accepted=false 正常返回。
func (s *Service) Ingest(ctx context.Context, req Request) (*Result, error) {
	snap := s.snapshot(req.Body)
	if s.sources == nil {
		return nil, ErrStoreUnavailable
	}
	src, err := s.sources.Get(ctx, req.Name)
	if errors.Is(err, ErrSourceNotFound) || (err == nil && src == nil) {
		s.record(ctx, req.Name, ReasonUnknownSource, "", snap)
		return nil, ErrUnknownSource
	}
	if err != nil {
		return nil, fmt.Errorf("eventsrc: 读取事件源: %w", err)
	}
	if !src.Enabled {
		s.record(ctx, req.Name, ReasonDisabled, "", snap)
		return nil, ErrDisabled
	}

	// 第一段：鉴权。bearer/hmac 按源二选一；空模式按 bearer（存量兼容），
	// 未知模式 fail-closed。
	switch src.AuthMode {
	case AuthHMAC:
		if !verifyHMAC(src.Secret, req.Header, req.Body) {
			s.record(ctx, req.Name, ReasonBadSignature, "", snap)
			return nil, ErrBadSignature
		}
	case AuthBearer, "":
		if !tokenMatch(src.Secret, req.Header) {
			s.record(ctx, req.Name, ReasonBadToken, "", snap)
			return nil, ErrBadToken
		}
	default:
		s.record(ctx, req.Name, ReasonBadToken, "", snap)
		return nil, &RejectError{Reason: ReasonBadToken, Status: http.StatusUnauthorized,
			Message: fmt.Sprintf("事件源鉴权模式非法: %q", src.AuthMode)}
	}

	// 第二段：限频（超窗 429）。
	if !s.allowRate(src.Name, src.RatePerMin) {
		s.record(ctx, req.Name, ReasonRateLimited, "", snap)
		return nil, &RejectError{Reason: ReasonRateLimited, Status: http.StatusTooManyRequests,
			Message: fmt.Sprintf("事件源触发超限（%d/分钟）", src.RatePerMin)}
	}

	// 第三段前置：体量 + JSON 对象（点路径过滤/模板的根形态）。
	if len(req.Body) > MaxBodyBytes {
		s.record(ctx, req.Name, ReasonBadPayload, "", snap)
		return nil, &RejectError{Reason: ReasonBadPayload, Status: http.StatusRequestEntityTooLarge,
			Message: fmt.Sprintf("载荷超过上限（%d 字节）", MaxBodyBytes)}
	}
	var payload map[string]any
	if err := json.Unmarshal(req.Body, &payload); err != nil || payload == nil {
		s.record(ctx, req.Name, ReasonBadPayload, "", snap)
		return nil, ErrBadPayload
	}

	// 第三段：过滤未命中 = 送达成功、平台选择不响应（不是错误）。
	if ok, op := MatchFilters(src.Filters, payload); !ok {
		s.record(ctx, req.Name, ReasonFiltered, "", snap)
		return &Result{Accepted: false, Reason: ReasonFiltered, FilterOp: op}, nil
	}

	// 第四段：模板渲染。
	input := RenderTemplate(src.Template, src.Name, payload)

	// 第五段：投递回调。
	if s.sink == nil {
		s.record(ctx, req.Name, ReasonError, "", snap)
		return nil, &RejectError{Reason: ReasonError, Status: http.StatusInternalServerError,
			Message: "投递回调未装配"}
	}
	deliveryID, sinkErr := s.sink(ctx, src.Name, input)
	if sinkErr != nil {
		s.record(ctx, req.Name, ReasonError, "", snap)
		return nil, fmt.Errorf("%w: %w", ErrSink, sinkErr)
	}
	s.record(ctx, req.Name, "", deliveryID, snap)
	return &Result{Accepted: true, DeliveryID: deliveryID}, nil
}

// record 写一条留痕（失败不阻断主流程）。
func (s *Service) record(ctx context.Context, source, reason, deliveryID, payload string) {
	if s.events == nil {
		return
	}
	status := StatusAccepted
	if reason != "" {
		status = StatusRejected
	}
	_ = s.events.Record(ctx, Event{
		Source:     source,
		Status:     status,
		Reason:     reason,
		DeliveryID: deliveryID,
		Payload:    payload,
		CreatedAt:  s.now(),
	})
}

// allowRate 每源滑动窗口限频（0=不限；limit 变更即重建窗口；时钟走 Service 注入）。
func (s *Service) allowRate(name string, perMin int) bool {
	if perMin <= 0 {
		return true
	}
	s.rlMu.Lock()
	cur := s.windows[name]
	if cur == nil || cur.perMin != perMin {
		cur = &rateWindow{perMin: perMin, sw: ratelimit.NewSlidingWindow(s.rateWindow, perMin,
			ratelimit.WithSlidingWindowClock(s.now))}
		s.windows[name] = cur
	}
	s.rlMu.Unlock()
	return cur.sw.Allow()
}

// verifyHMAC HMAC-SHA256 验签（oekit 原语；头形态 sha256=<hex>）。
func verifyHMAC(secret string, header http.Header, body []byte) bool {
	if strings.TrimSpace(secret) == "" {
		return false
	}
	v := oekitwebhook.NewHMACValidator([]byte(secret), crypto.SHA256, HeaderSignature,
		oekitwebhook.WithSignaturePrefix(SignaturePrefix))
	return v.Validate(&http.Request{Header: header}, body) == nil
}

// tokenMatch 裸 token 双通道（Bearer 优先）恒时比较。
func tokenMatch(secret string, header http.Header) bool {
	if strings.TrimSpace(secret) == "" {
		return false
	}
	bearer := strings.TrimPrefix(header.Get(HeaderAuthorization), "Bearer ")
	return subtle.ConstantTimeCompare([]byte(secret), []byte(bearer)) == 1 ||
		subtle.ConstantTimeCompare([]byte(secret), []byte(header.Get(HeaderToken))) == 1
}

// ── 管理面原语（handler/团队作用域留宿主） ──

// Create 建源：校验 → 生成密钥（入参空）→ 查重 → 落库。
func (s *Service) Create(ctx context.Context, in SourceInput) (*Source, error) {
	if s.sources == nil {
		return nil, ErrStoreUnavailable
	}
	secret := strings.TrimSpace(in.Secret)
	if secret == "" {
		var err error
		secret, err = NewSecret()
		if err != nil {
			return nil, err
		}
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	src := &Source{
		Name:       strings.TrimSpace(in.Name),
		Enabled:    enabled,
		AuthMode:   in.AuthMode,
		Secret:     secret,
		RatePerMin: in.RatePerMin,
		Filters:    cloneFilters(in.Filters),
		Template:   in.Template,
		Retention:  in.Retention,
	}
	if err := ValidateSource(src); err != nil {
		return nil, err
	}
	if existing, err := s.sources.Get(ctx, src.Name); err == nil && existing != nil {
		return nil, fmt.Errorf("%w: %s", ErrSourceExists, src.Name)
	} else if err != nil && !errors.Is(err, ErrSourceNotFound) {
		return nil, fmt.Errorf("eventsrc: 查询事件源: %w", err)
	}
	if err := s.sources.Create(ctx, src); err != nil {
		return nil, fmt.Errorf("eventsrc: 创建事件源: %w", err)
	}
	return src, nil
}

// Update 改源（name/创建者不可变；Secret 传空=保持原密钥，显式非空=轮换）。
func (s *Service) Update(ctx context.Context, name string, in SourceInput) (*Source, error) {
	if s.sources == nil {
		return nil, ErrStoreUnavailable
	}
	existing, err := s.sources.Get(ctx, name)
	if errors.Is(err, ErrSourceNotFound) || (err == nil && existing == nil) {
		return nil, ErrSourceNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("eventsrc: 查询事件源: %w", err)
	}
	if n := strings.TrimSpace(in.Name); n != "" && n != existing.Name {
		return nil, fmt.Errorf("%w: 源名不可变", ErrInvalidSource)
	}
	src := *existing
	src.AuthMode = in.AuthMode
	if sec := strings.TrimSpace(in.Secret); sec != "" {
		src.Secret = sec
	}
	src.RatePerMin = in.RatePerMin
	src.Filters = cloneFilters(in.Filters)
	src.Template = in.Template
	src.Retention = in.Retention
	if in.Enabled != nil {
		src.Enabled = *in.Enabled
	}
	if err := ValidateSource(&src); err != nil {
		return nil, err
	}
	if err := s.sources.Save(ctx, &src); err != nil {
		return nil, fmt.Errorf("eventsrc: 保存事件源: %w", err)
	}
	return &src, nil
}

// Delete 删源（留痕保留——历史可溯源）。
func (s *Service) Delete(ctx context.Context, name string) (bool, error) {
	if s.sources == nil {
		return false, ErrStoreUnavailable
	}
	ok, err := s.sources.Delete(ctx, name)
	if errors.Is(err, ErrSourceNotFound) {
		return false, ErrSourceNotFound
	}
	if err != nil {
		return false, fmt.Errorf("eventsrc: 删除事件源: %w", err)
	}
	if !ok {
		return false, ErrSourceNotFound
	}
	return true, nil
}

// ResetSecret 轮换密钥（旧密钥立即失效；仅本次返回新密钥）。
func (s *Service) ResetSecret(ctx context.Context, name string) (string, error) {
	if s.sources == nil {
		return "", ErrStoreUnavailable
	}
	src, err := s.sources.Get(ctx, name)
	if errors.Is(err, ErrSourceNotFound) || (err == nil && src == nil) {
		return "", ErrSourceNotFound
	}
	if err != nil {
		return "", fmt.Errorf("eventsrc: 查询事件源: %w", err)
	}
	secret, err := NewSecret()
	if err != nil {
		return "", err
	}
	src.Secret = secret
	if err := s.sources.Save(ctx, src); err != nil {
		return "", fmt.Errorf("eventsrc: 保存事件源: %w", err)
	}
	return secret, nil
}

// ListSources 源名册（作用域过滤由宿主 handler 完成）。
func (s *Service) ListSources(ctx context.Context) ([]Source, error) {
	if s.sources == nil {
		return nil, ErrStoreUnavailable
	}
	rows, err := s.sources.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("eventsrc: 列出事件源: %w", err)
	}
	return rows, nil
}

// ListEvents 最近触发留痕。
func (s *Service) ListEvents(ctx context.Context, source string, limit int) ([]Event, error) {
	if s.events == nil {
		return nil, ErrStoreUnavailable
	}
	return s.events.List(ctx, source, limit)
}

// PruneEvents 按源保留窗口清扫留痕；单源失败不阻塞其他源（有损原则），
// 返回已清扫总数与聚合错误。已删除源的孤儿事件由宿主 EventStore 自行清扫
// （Prune 的 source 空串语义）。
func (s *Service) PruneEvents(ctx context.Context) (int64, error) {
	if s.events == nil || s.sources == nil {
		return 0, ErrStoreUnavailable
	}
	sources, err := s.sources.List(ctx)
	if err != nil {
		return 0, fmt.Errorf("eventsrc: 列出事件源: %w", err)
	}
	now := s.now()
	var total int64
	var errs []error
	for i := range sources {
		n, perr := s.events.Prune(ctx, sources[i].Name, now.Add(-RetentionOf(&sources[i])))
		total += n
		if perr != nil {
			errs = append(errs, fmt.Errorf("源 %s: %w", sources[i].Name, perr))
		}
	}
	return total, errors.Join(errs...)
}

func cloneFilters(in []Filter) []Filter {
	if len(in) == 0 {
		return nil
	}
	out := make([]Filter, len(in))
	copy(out, in)
	return out
}
