package eventsrc

import (
	"encoding/json"
	"regexp"
	"strings"
	"unicode/utf8"
)

// 留痕快照脱敏：快照是入站请求体原文，任何分支（未知源/停用/鉴权失败/
// 限频/坏载荷）都会把它写进 Event.Payload。外部系统推来的凭据不能明文落库。
//
// 口径：JSON body 按敏感键名递归打码（键名子串、大小写不敏感）后重新序列化；
// 非 JSON 回落文本级 key=value / key: value 值模式；最后统一截断到 PayloadCap。
// 刻意保守：命中敏感词元的整段值（含对象/数组）一律替换为 "***"，宁可少留
// 排障信息，不可留明文凭据。
var sensitiveKeyTokens = []string{
	"password", "passwd", "secret", "token", "api_key", "apikey",
	"access_key", "private_key", "authorization", "credential", "cookie",
}

// 非 JSON 文本的键值对脱敏（password=xxx / "token": "xxx" 等常见形态）。
var textSecretRe = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|authorization)\s*([=:])\s*("[^"]*"|'[^']*'|[^\s&,;}]+)`)

// Snapshot 生成留痕载荷快照（脱敏 + 截断）。宿主可用 WithSnapshot 注入自己的
// 脱敏面（PII 等）；默认实现只做凭据键名/值模式打码。
func Snapshot(body []byte) string {
	if len(body) > MaxBodyBytes {
		body = body[:MaxBodyBytes] // 防超大 body 在快照阶段先打爆内存
	}
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return truncate(RedactText(body), PayloadCap)
	}
	out := redactValue(v)
	b, err := json.Marshal(out)
	if err != nil {
		return truncate(RedactText(body), PayloadCap)
	}
	return truncate(string(b), PayloadCap)
}

// redactValue 递归按敏感键名打码（键命中即整值替换，含容器）。
func redactValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if sensitiveKey(k) {
				out[k] = "***"
				continue
			}
			out[k] = redactValue(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = redactValue(val)
		}
		return out
	default:
		return v
	}
}

func sensitiveKey(key string) bool {
	l := strings.ToLower(key)
	for _, tok := range sensitiveKeyTokens {
		if strings.Contains(l, tok) {
			return true
		}
	}
	return false
}

// RedactText 非 JSON 文本脱敏（保留原文结构，只替换敏感值）。
func RedactText(body []byte) string {
	return textSecretRe.ReplaceAllString(string(body), "${1}${2}***")
}

func truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	// 不切断 UTF-8 字符（事件表是文本列，半个 rune 会变成非法编码）。
	for max > 0 && !utf8.RuneStart(s[max]) {
		max--
	}
	return s[:max]
}
