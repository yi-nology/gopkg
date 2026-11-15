package diagbundle

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"
)

// 支持包头部/审计键（保留名，分节名不得与之冲突）。
const (
	KeyGeneratedAt     = "generated_at"
	KeyVersion         = "version"
	KeyHostname        = "hostname"
	KeyGoVersion       = "go_version"
	KeyConfig          = "config"
	KeyAuditChain      = "audit_chain"
	KeyAuditChainError = "audit_chain_error"
)

// DefaultMaxPayload 事件 payload 缺省截断字节数（与 bianque hostdiag 生产口径
// 一致：300 字节 + 省略号）。
const DefaultMaxPayload = 300

// 分节注册错误（errors.Is 可判定）。
var (
	ErrInvalidSection   = errors.New("diagbundle: 分节名/provider 非法")
	ErrDuplicateSection = errors.New("diagbundle: 分节重复注册")
)

// reservedKeys 头部与审计保留键；分节名不得占用，也不得以 _error 结尾
// （分节故障落包键形如 <name>_error）。
var reservedKeys = map[string]struct{}{
	KeyGeneratedAt:     {},
	KeyVersion:         {},
	KeyHostname:        {},
	KeyGoVersion:       {},
	KeyConfig:          {},
	KeyAuditChain:      {},
	KeyAuditChainError: {},
}

// SectionProvider 分节 provider：返回 JSON 友好的分节内容。error/panic 只让
// 该节落成 <name>_error，不影响其他分节。
type SectionProvider func(ctx context.Context) (any, error)

// AuditVerifier 审计链校验钩子：宿主适配 audit.Verify（含 GenesisAnchored 参数）；
// 成功落 audit_chain、失败落 audit_chain_error。
type AuditVerifier func(ctx context.Context) (any, error)

// Option 构造选项。
type Option func(*Builder)

// WithHostname 注入主机名（缺省 os.Hostname；测试/容器场景可固定）。
func WithHostname(hostname string) Option {
	return func(b *Builder) { b.hostname = hostname }
}

// WithNow 注入时钟（缺省 time.Now；测试固定 generated_at）。nil 被忽略。
func WithNow(now func() time.Time) Option {
	return func(b *Builder) {
		if now != nil {
			b.now = now
		}
	}
}

// WithConfigSummary 注入配置摘要（装配期白名单字段；调用方保证脱敏）。
func WithConfigSummary(summary map[string]any) Option {
	return func(b *Builder) { b.SetConfigSummary(summary) }
}

// Builder 支持包装配器。注册在装配期完成；Build 只读，可并发调用（provider
// 自身须并发安全）。
type Builder struct {
	version  string
	hostname string
	now      func() time.Time
	config   map[string]any
	audit    AuditVerifier
	sections []section
}

type section struct {
	name string
	fn   SectionProvider
}

// New 构造装配器（version=宿主构建注入的版本号）。
func New(version string, opts ...Option) *Builder {
	b := &Builder{version: version, now: time.Now, config: map[string]any{}}
	for _, opt := range opts {
		if opt != nil {
			opt(b)
		}
	}
	return b
}

// SetConfigSummary 合并配置摘要（同键覆盖）：只接受宿主显式收集的白名单字段，
// **绝不要传整份配置**。map 复制进装配器，调用方后续改动不影响包体。
func (b *Builder) SetConfigSummary(summary map[string]any) {
	if b == nil || len(summary) == 0 {
		return
	}
	if b.config == nil {
		b.config = map[string]any{}
	}
	for k, v := range summary {
		b.config[k] = v
	}
}

// SetAuditChain 注入审计链校验钩子（nil=不产 audit_chain/audit_chain_error 两键）。
func (b *Builder) SetAuditChain(fn AuditVerifier) {
	if b == nil {
		return
	}
	b.audit = fn
}

// RegisterSection 注册分节（装配期调用；同名重复拒绝）。分节名为空、命中头部/
// 审计保留键、或以 _error 结尾均拒绝——这些名字会被骨架/错误落包键占用。
func (b *Builder) RegisterSection(name string, fn SectionProvider) error {
	if b == nil {
		return fmt.Errorf("%w: 装配器为 nil", ErrInvalidSection)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("%w: 分节名为空", ErrInvalidSection)
	}
	if _, reserved := reservedKeys[name]; reserved {
		return fmt.Errorf("%w: %q 是头部/审计保留键", ErrInvalidSection, name)
	}
	if strings.HasSuffix(name, "_error") {
		return fmt.Errorf("%w: %q 以 _error 结尾（与故障落包键冲突）", ErrInvalidSection, name)
	}
	if fn == nil {
		return fmt.Errorf("%w: %q provider 为 nil", ErrInvalidSection, name)
	}
	for _, s := range b.sections {
		if s.name == name {
			return fmt.Errorf("%w: %q", ErrDuplicateSection, name)
		}
	}
	b.sections = append(b.sections, section{name: name, fn: fn})
	return nil
}

// Build 组装支持包。ctx 只用于分节 provider 与审计钩子；ctx 在开始前已取消则
// 返回 ctx 错误，否则始终返回包体（分节故障落成 <name>_error，不整体失败）。
func (b *Builder) Build(ctx context.Context) (map[string]any, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := b.now
	if now == nil {
		now = time.Now
	}
	hostname := b.hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	config := maps.Clone(b.config)
	if config == nil {
		config = map[string]any{}
	}
	out := map[string]any{
		KeyGeneratedAt: now().UTC().Format(time.RFC3339),
		KeyVersion:     b.version,
		KeyHostname:    hostname,
		KeyGoVersion:   runtime.Version(),
		KeyConfig:      config,
	}
	for _, s := range b.sections {
		v, err := runSection(ctx, s.fn)
		if err != nil {
			out[s.name+"_error"] = err.Error()
			continue
		}
		out[s.name] = v
	}
	if b.audit != nil {
		v, err := runSection(ctx, b.audit)
		if err != nil {
			out[KeyAuditChainError] = err.Error()
		} else {
			out[KeyAuditChain] = v
		}
	}
	return out, nil
}

// runSection 执行分节/审计钩子并隔离 panic：支持包不能因单节故障整体不可用。
func runSection(ctx context.Context, fn func(context.Context) (any, error)) (v any, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return fn(ctx)
}

// WhitelistSummary 白名单摘要：只保留 allowed 中且 src 存在的键（浅拷贝）。
// 调用方必须先显式收集候选字段，**不得先整份序列化配置再修剪**；嵌套敏感值
// （URL/token/密钥引用）由宿主保证不进入 src。
func WhitelistSummary(src map[string]any, allowed ...string) map[string]any {
	out := make(map[string]any, len(allowed))
	for _, k := range allowed {
		if v, ok := src[k]; ok {
			out[k] = v
		}
	}
	return out
}

// URLPresent URL/地址配置的存在性布尔：去空白后非空即 true。包内只记录
// 「配了没有」，不暴露目标（webhook URL/DNS token 一律不进包）。
func URLPresent(raw string) bool {
	return strings.TrimSpace(raw) != ""
}

// TruncatePayload 截断事件 payload：超过 maxPayload 字节时截到不超过该值的
// rune 边界并追加「…」；未超长原样返回。maxPayload <= 0 时用
// [DefaultMaxPayload]。返回串的 payload 部分不超过 maxPayload 字节且保持合法
// UTF-8（省略号额外 3 字节）。
func TruncatePayload(payload string, maxPayload int) string {
	if maxPayload <= 0 {
		maxPayload = DefaultMaxPayload
	}
	if len(payload) <= maxPayload {
		return payload
	}
	cut := maxPayload
	for cut > 0 && !utf8.RuneStart(payload[cut]) {
		cut--
	}
	return payload[:cut] + "…"
}

// Event 支持包中的事件最小形态（宿主把 model.Event 映射到此，领域字段不入包）。
type Event struct {
	ID        uint64
	SessionID string
	Type      string
	Level     string
	CreatedAt time.Time
	Payload   string
}

// CompactEvents 事件瘦身：id/session_id/type/level/created_at + 截断后的 payload
// 字符串。返回非 nil 切片（空输入 = 空数组，不是 null）。
func CompactEvents(events []Event, maxPayload int) []map[string]any {
	out := make([]map[string]any, 0, len(events))
	for _, e := range events {
		out = append(out, map[string]any{
			"id":         e.ID,
			"session_id": e.SessionID,
			"type":       e.Type,
			"level":      e.Level,
			"created_at": e.CreatedAt,
			"payload":    TruncatePayload(e.Payload, maxPayload),
		})
	}
	return out
}
