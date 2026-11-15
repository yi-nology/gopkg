package gdpr

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// defaultSensitiveFragments 凭证类字段名片段（小写、子串匹配）。
// 宁严勿松：命中即剔除，字段名本身不导出，避免「字段名泄露存在性」。
var defaultSensitiveFragments = []string{
	"password", "passwd", "secret", "token", "credential",
	"apikey", "api_key", "private_key", "session_key",
	"authorization", "cookie", "salt",
}

// DenyListRedactor 默认导出脱敏器：按字段名片段（大小写不敏感、'-' 归一
// 为 '_'）递归剔除凭证类字段；嵌套 map/slice 同样处理。无法安全判定的
// 值类型直接报错（fail-closed），不做原样透出。
type DenyListRedactor struct {
	fragments []string
}

// NewRedactor 构造脱敏器。extraKeys 是宿主追加的敏感字段名片段（如
// "mfa_seed"）；空片段拒绝（配置错误应启动期暴露）。默认片段始终生效，
// 无法关闭。
func NewRedactor(extraKeys ...string) (*DenyListRedactor, error) {
	fragments := append([]string(nil), defaultSensitiveFragments...)
	seen := make(map[string]struct{}, len(fragments))
	for _, f := range fragments {
		seen[f] = struct{}{}
	}
	for i, key := range extraKeys {
		norm := normalizeKeyFragment(key)
		if norm == "" {
			return nil, fmt.Errorf("gdpr: 第 %d 个追加敏感片段为空", i)
		}
		if _, dup := seen[norm]; dup {
			continue
		}
		seen[norm] = struct{}{}
		fragments = append(fragments, norm)
	}
	return &DenyListRedactor{fragments: fragments}, nil
}

func normalizeKeyFragment(s string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(s)), "-", "_")
}

// sensitive 字段名是否命中凭证类片段。
func (d *DenyListRedactor) sensitive(key string) bool {
	norm := normalizeKeyFragment(key)
	for _, f := range d.fragments {
		if strings.Contains(norm, f) {
			return true
		}
	}
	return false
}

// Redact 返回脱敏副本（不修改入参）。敏感字段整键剔除——凭证类数据不
// 属于「关于主体的信息」。
func (d *DenyListRedactor) Redact(record Record) (Record, error) {
	if record == nil {
		return nil, nil
	}
	out := make(Record, len(record))
	for key, val := range record {
		if d.sensitive(key) {
			continue
		}
		redacted, err := d.redactValue(val)
		if err != nil {
			return nil, fmt.Errorf("字段 %q: %w", key, err)
		}
		out[key] = redacted
	}
	return out, nil
}

func (d *DenyListRedactor) redactValue(val any) (any, error) {
	switch v := val.(type) {
	case nil:
		return nil, nil
	case string, bool,
		float32, float64,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		json.Number, time.Time:
		return v, nil
	case Record:
		return d.Redact(v)
	case map[string]any:
		return d.Redact(Record(v))
	case map[string]string:
		m := make(Record, len(v))
		for k, s := range v {
			if d.sensitive(k) {
				continue
			}
			m[k] = s
		}
		return m, nil
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			redacted, err := d.redactValue(item)
			if err != nil {
				return nil, fmt.Errorf("[%d]: %w", i, err)
			}
			out[i] = redacted
		}
		return out, nil
	case []Record:
		out := make([]any, len(v))
		for i, item := range v {
			redacted, err := d.Redact(item)
			if err != nil {
				return nil, fmt.Errorf("[%d]: %w", i, err)
			}
			out[i] = redacted
		}
		return out, nil
	case []map[string]any:
		out := make([]any, len(v))
		for i, item := range v {
			redacted, err := d.Redact(Record(item))
			if err != nil {
				return nil, fmt.Errorf("[%d]: %w", i, err)
			}
			out[i] = redacted
		}
		return out, nil
	case []string:
		return append([]string(nil), v...), nil
	case []bool:
		return append([]bool(nil), v...), nil
	case []int:
		return append([]int(nil), v...), nil
	case []int64:
		return append([]int64(nil), v...), nil
	case []float64:
		return append([]float64(nil), v...), nil
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedValue, val)
	}
}
