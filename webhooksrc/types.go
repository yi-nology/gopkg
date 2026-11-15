package webhooksrc

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// 鉴权模式：按源强制二选一（不存在「不鉴权」的源）。
const (
	AuthBearer = "bearer"
	AuthHMAC   = "hmac"
)

// 默认头名与限制。
const (
	DefaultSignatureHeader = "X-Webhook-Signature"
	DefaultTokenHeader     = "X-Webhook-Token"

	DefaultMaxBodyBytes  = 512 * 1024 // 请求体上限
	DefaultMaxInputBytes = 16000      // 渲染后投递内容上限
	DefaultPayloadCap    = 2000       // 留痕载荷快照上限
	DefaultRetention     = 7 * 24 * time.Hour
	DefaultRateWindow    = time.Minute
)

// AuthConfig 源鉴权配置。Mode=hmac 时校验签名头（默认
// X-Webhook-Signature，形态 sha256=<hex>）；Mode=bearer 时接受
// Authorization: Bearer <secret> 或 X-Webhook-Token: <secret>。
type AuthConfig struct {
	Mode            string `json:"mode"`
	Secret          string `json:"-"`
	SignatureHeader string `json:"signature_header,omitempty"`
	TokenHeader     string `json:"token_header,omitempty"`
}

// Filter 过滤条目：payload 按 path 取值做确定性匹配，全部条目命中才放行
// （AND）。Op ∈ eq|ne|contains|exists|regex。
type Filter struct {
	Path  string `json:"path"`
	Op    string `json:"op"`
	Value string `json:"value,omitempty"`
}

// Source 事件源配置形态（宿主存储行的投影）。
type Source struct {
	Name       string        `json:"name"`
	Enabled    bool          `json:"enabled"`
	Auth       AuthConfig    `json:"auth"`
	RatePerMin int           `json:"rate_per_min"` // 0=不限
	Filters    []Filter      `json:"filters"`
	Template   string        `json:"template"`
	Retention  time.Duration `json:"retention,omitempty"` // 0=Service 默认
}

// SourceStore 源配置读取面（宿主实现）。
type SourceStore interface {
	Get(ctx context.Context, name string) (*Source, error)
}

// MutableSourceStore 可选：支持密钥轮换的存储。Service.ResetSecret 只在
// 存储实现此接口时可用。
type MutableSourceStore interface {
	SourceStore
	Save(ctx context.Context, src *Source) error
}

// EventStore 留痕写入与清扫面（表是宿主资产）。
type EventStore interface {
	Record(ctx context.Context, ev *Event) error
	Prune(ctx context.Context, before time.Time) (int64, error)
}

// Sink 第五段动作：宿主把渲染后的输入接到自家会话/队列/事实卡。
type Sink interface {
	Deliver(ctx context.Context, source, input string) error
}

// SinkFunc 函数适配器。
type SinkFunc func(ctx context.Context, source, input string) error

// Deliver 实现 Sink。
func (f SinkFunc) Deliver(ctx context.Context, source, input string) error {
	return f(ctx, source, input)
}

// Clock 时间注入点（限频窗口/留痕时间；测试用假时钟）。
type Clock interface {
	Now() time.Time
}

// Request 一次接入请求：Header 可为 nil；Body 是原始字节（鉴权对原文
// 计算 HMAC，解析在鉴权之后）。
type Request struct {
	Header http.Header
	Body   []byte
}

// Result 接入结果。Accepted=false 且 err=nil 表示「送达成功但平台选择不
// 响应」（过滤未命中）——HTTP 层通常回 200。
type Result struct {
	Accepted bool   `json:"accepted"`
	Reason   string `json:"reason,omitempty"`
	Input    string `json:"input,omitempty"`
}

// Rejection 硬拒绝：Reason 是稳定的原因码（见 Reason* 常量），Status 是
// 建议 HTTP 状态码，Message 供人读。errors.As/Unwrap 可取出 Cause。
type Rejection struct {
	Reason  string
	Status  int
	Message string
	Cause   error
}

func (r *Rejection) Error() string {
	if r.Cause != nil {
		return fmt.Sprintf("webhooksrc: %s: %s: %v", r.Reason, r.Message, r.Cause)
	}
	return fmt.Sprintf("webhooksrc: %s: %s", r.Reason, r.Message)
}

func (r *Rejection) Unwrap() error { return r.Cause }

// RejectionReason 从错误链取原因码（非 Rejection 返回空串,false）。
func RejectionReason(err error) (string, bool) {
	var r *Rejection
	if errors.As(err, &r) {
		return r.Reason, true
	}
	return "", false
}

// RejectionStatus 从错误链取建议 HTTP 状态；非 Rejection 返回 500。
func RejectionStatus(err error) int {
	var r *Rejection
	if errors.As(err, &r) && r.Status > 0 {
		return r.Status
	}
	return http.StatusInternalServerError
}

func reject(reason string, status int, format string, args ...any) *Rejection {
	return &Rejection{Reason: reason, Status: status, Message: fmt.Sprintf(format, args...)}
}

// VerifyHMAC 校验 HMAC-SHA256 签名：头形态 `sha256=<hex>`，对原始 body
// 计算，常数时间比对。
func VerifyHMAC(secret, header string, body []byte) bool {
	const prefix = "sha256="
	if secret == "" || !strings.HasPrefix(header, prefix) {
		return false
	}
	got, err := hex.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil || len(got) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return hmac.Equal(got, mac.Sum(nil))
}

// VerifyBearer 校验裸 token：Authorization Bearer（scheme 大小写不敏感）
// 或自定义 token 头，任一命中即可；常数时间比对。
func VerifyBearer(secret, authorization, token string) bool {
	if secret == "" {
		return false
	}
	bearer := ""
	if len(authorization) >= 7 && strings.EqualFold(authorization[:7], "bearer ") {
		bearer = authorization[7:]
	}
	return subtle.ConstantTimeCompare([]byte(secret), []byte(bearer)) == 1 ||
		subtle.ConstantTimeCompare([]byte(secret), []byte(token)) == 1
}

// GenerateSecret 生成 32 位十六进制接入密钥（16 字节随机）。
func GenerateSecret() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("webhooksrc: 生成密钥失败: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// webhookNameRe 源名 slug：小写字母数字连字符，3-64 位，字母或数字开头。
var webhookNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,63}$`)

// ValidateSource 源配置校验：slug/鉴权模式/密钥/速率/过滤算子与正则/模板
// 长度。返回逐条错误组成的 error（nil=合法）。
func ValidateSource(src *Source) error {
	if src == nil {
		return errors.New("webhooksrc: source 为空")
	}
	var errs []error
	if !webhookNameRe.MatchString(src.Name) {
		errs = append(errs, fmt.Errorf("源名非法（小写字母数字连字符，3-64 位）: %q", src.Name))
	}
	switch src.Auth.Mode {
	case AuthBearer, AuthHMAC:
	default:
		errs = append(errs, fmt.Errorf("鉴权模式非法（bearer|hmac）: %q", src.Auth.Mode))
	}
	if strings.TrimSpace(src.Auth.Secret) == "" {
		errs = append(errs, errors.New("鉴权密钥不能为空"))
	}
	if src.RatePerMin < 0 || src.RatePerMin > 10000 {
		errs = append(errs, fmt.Errorf("rate_per_min 越界（0=不限，上限 10000）: %d", src.RatePerMin))
	}
	for _, f := range src.Filters {
		if strings.TrimSpace(f.Path) == "" {
			errs = append(errs, errors.New("过滤 path 必填"))
		}
		if !ValidFilterOp(f.Op) {
			errs = append(errs, fmt.Errorf("过滤 op 非法（eq|ne|contains|exists|regex）: %q", f.Op))
		}
		if f.Op == "regex" {
			if _, err := regexp.Compile(f.Value); err != nil {
				errs = append(errs, fmt.Errorf("过滤 regex 编译失败: %w", err))
			}
		}
	}
	if len(src.Template) > DefaultMaxInputBytes {
		errs = append(errs, fmt.Errorf("template 过长（上限 %d）", DefaultMaxInputBytes))
	}
	return errors.Join(errs...)
}
