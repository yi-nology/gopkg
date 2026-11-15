package webhooksrc

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// tmplPlaceholderRe 模板占位：{{path}} / {{_raw}} / {{_source}}（路径段
// 字母数字._-）。
var tmplPlaceholderRe = regexp.MustCompile(`\{\{\s*([A-Za-z0-9_.\-]+)\s*\}\}`)

// RenderTemplate 模板渲染：{{path}} 从 payload 点路径取值，预留
// {{_raw}}（载荷紧凑 JSON）与 {{_source}}（源名）。占位未知路径替换为空串
// ——不报错不阻断（模板是运维配置，不该因一个字段缺失让整条事件丢失）。
// 空模板回退缺省形态：来源 + 载荷紧凑 JSON（模板未配时事件仍有完整信息量）。
func RenderTemplate(tmpl, source string, payload map[string]any) string {
	return renderTemplate(tmpl, source, payload, DefaultMaxInputBytes)
}

func renderTemplate(tmpl, source string, payload map[string]any, max int) string {
	raw := compactJSON(payload)
	if strings.TrimSpace(tmpl) == "" {
		return fmt.Sprintf("收到外部事件（webhook 源: %s）。事件载荷：\n%s", source, raw)
	}
	out := tmplPlaceholderRe.ReplaceAllStringFunc(tmpl, func(m string) string {
		path := tmplPlaceholderRe.FindStringSubmatch(m)[1]
		switch path {
		case "_raw":
			return raw
		case "_source":
			return source
		}
		if v, ok := LookupPath(payload, path); ok {
			return Stringify(v)
		}
		return ""
	})
	if max > 0 && len(out) > max {
		out = out[:max] + "\n…（模板渲染结果超限截断）"
	}
	return out
}

// compactJSON 载荷紧凑 JSON（保持 map 键字典序，输出稳定）。
func compactJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}
