package eventsrc

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// tmplPlaceholderRe 模板占位：{{path}} / {{_raw}} / {{_source}}（路径段字母数字._-）。
// 刻意不用 text/template：本契约要求未知路径替换为空串而不是渲染错误，且
// payload 的键可以带点（{{a.b.c}}）——这是确定性占位替换，不是模板语言。
var tmplPlaceholderRe = regexp.MustCompile(`\{\{\s*([A-Za-z0-9_.\-]+)\s*\}\}`)

// RenderTemplate 模板渲染（确定性替换，未知路径替换为空串——不报错不阻断）。
// 空模板回退缺省形态：来源+载荷紧凑 JSON（模板未配时事件文本仍有完整信息量）。
// _raw 为载荷紧凑 JSON，_source 为源名。
func RenderTemplate(tmpl, source string, payload map[string]any) string {
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
			return stringify(v)
		}
		return ""
	})
	if len(out) > InputCap {
		out = truncate(out, InputCap) + "\n…（模板渲染结果超限截断）"
	}
	return out
}

func compactJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}
