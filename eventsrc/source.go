package eventsrc

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// 源名 slug（小写字母数字连字符，3-64 位，字母或数字开头）。
var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,63}$`)

// 体量与保留窗口口径。
const (
	// MaxBodyBytes 请求体上限（截断即拒，不静默剪）。
	MaxBodyBytes = 512 * 1024
	// PayloadCap 留痕载荷快照上限。
	PayloadCap = 2000
	// InputCap 渲染后投递输入上限（模板膨胀在此收口）。
	InputCap = 16000
	// DefaultRetention 留痕保留窗口（源未声明 Retention 时）。
	DefaultRetention = 7 * 24 * time.Hour
	// MaxRatePerMin 每源每分钟触发上限的配置上界（0=不限）。
	MaxRatePerMin = 10000
)

// AuthMode 源鉴权模式（按源二选一强制）。
type AuthMode string

const (
	// AuthBearer Authorization: Bearer <secret> 或 X-Webhook-Token 命中其一即可。
	AuthBearer AuthMode = "bearer"
	// AuthHMAC 对原始 body 计算 HMAC-SHA256，头形态 sha256=<hex>。
	AuthHMAC AuthMode = "hmac"
)

// 鉴权头约定（验签族/裸 token 双通道）。
const (
	HeaderAuthorization = "Authorization"
	HeaderToken         = "X-Webhook-Token"
	HeaderSignature     = "X-Webhook-Signature"
	// SignaturePrefix HMAC 签名值前缀（小写 hex）。
	SignaturePrefix = "sha256="
)

// Filter 过滤条目：payload 按 Path 取值做确定性匹配，全部条目命中才放行（AND）。
// Op ∈ eq|ne|contains|exists|regex。
type Filter struct {
	Path  string `json:"path"`
	Op    string `json:"op"`
	Value string `json:"value,omitempty"`
}

// Source webhook 事件源配置形态（宿主持久化；Secret 是验签/Bearer 密钥）。
type Source struct {
	Name       string        `json:"name"`
	Enabled    bool          `json:"enabled"`
	AuthMode   AuthMode      `json:"auth_mode"`
	Secret     string        `json:"secret,omitempty"`
	RatePerMin int           `json:"rate_per_min"`
	Filters    []Filter      `json:"filters,omitempty"`
	Template   string        `json:"template,omitempty"`
	Retention  time.Duration `json:"retention,omitempty"` // 0=DefaultRetention
}

// SourceInput 建源/改源入参。布尔用指针三态：nil=Create 缺省 true / Update 保持
// 不变——「不带字段」绝不隐含 false（部分提交会静默停用源）。
type SourceInput struct {
	Name       string
	AuthMode   AuthMode
	Secret     string // Create 空=自动生成；Update 空=保持原密钥
	RatePerMin int
	Filters    []Filter
	Template   string
	Retention  time.Duration
	Enabled    *bool
}

// ValidateSource 源配置校验（slug/鉴权模式/限频域/过滤词表与 regex/模板长度/保留窗口）。
func ValidateSource(src *Source) error {
	if src == nil {
		return fmt.Errorf("%w: 源为 nil", ErrInvalidSource)
	}
	if !nameRe.MatchString(strings.TrimSpace(src.Name)) {
		return fmt.Errorf("%w: 源名非法（小写字母数字连字符，3-64 位，字母或数字开头）: %q", ErrInvalidSource, src.Name)
	}
	switch src.AuthMode {
	case AuthBearer, AuthHMAC:
	default:
		return fmt.Errorf("%w: 鉴权模式非法（bearer|hmac）: %q", ErrInvalidSource, src.AuthMode)
	}
	if strings.TrimSpace(src.Secret) == "" {
		return fmt.Errorf("%w: 密钥为空", ErrInvalidSource)
	}
	if src.RatePerMin < 0 || src.RatePerMin > MaxRatePerMin {
		return fmt.Errorf("%w: rate_per_min 越界（0=不限，上限 %d）", ErrInvalidSource, MaxRatePerMin)
	}
	if src.Retention < 0 {
		return fmt.Errorf("%w: retention 不能为负", ErrInvalidSource)
	}
	if err := validateFilters(src.Filters); err != nil {
		return err
	}
	if len(src.Template) > InputCap {
		return fmt.Errorf("%w: template 过长（上限 %d 字节）", ErrInvalidSource, InputCap)
	}
	return nil
}

// validateFilters 过滤条目校验（词表/regex 可编译/path 必填）。
func validateFilters(fs []Filter) error {
	for _, f := range fs {
		if !FilterOps[f.Op] {
			return fmt.Errorf("%w: 过滤 op 非法（%s）: %q", ErrInvalidSource, strings.Join(FilterOpList(), "|"), f.Op)
		}
		if strings.TrimSpace(f.Path) == "" {
			return fmt.Errorf("%w: 过滤 path 必填", ErrInvalidSource)
		}
		if f.Op == "regex" {
			if _, err := regexp.Compile(f.Value); err != nil {
				return fmt.Errorf("%w: 过滤 regex 编译失败: %v", ErrInvalidSource, err)
			}
		}
	}
	return nil
}

// NewSecret 生成 32 hex 字符接入密钥（16 字节系统熵）。
func NewSecret() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("eventsrc: 系统熵源不可用: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// RetentionOf 源的实际保留窗口（0=DefaultRetention）。
func RetentionOf(src *Source) time.Duration {
	if src == nil || src.Retention <= 0 {
		return DefaultRetention
	}
	return src.Retention
}
