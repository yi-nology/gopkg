package eventsrc

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// FilterBuilders op→判定策略表（校验词表由本表键派生，校验与执行永不分叉）。
// has 门槛由各算子自表：取值缺失时仅 exists 与 ne 可命中。
var FilterBuilders = map[string]func(f Filter, v any, has bool) bool{
	"exists": func(f Filter, _ any, has bool) bool {
		return has == (f.Value == "true" || f.Value == "")
	},
	"ne": func(f Filter, v any, has bool) bool { return has && stringify(v) != f.Value },
	"eq": func(f Filter, v any, has bool) bool { return has && stringify(v) == f.Value },
	"contains": func(f Filter, v any, has bool) bool {
		return has && strings.Contains(stringify(v), f.Value)
	},
	"regex": func(f Filter, v any, has bool) bool {
		if !has {
			return false
		}
		re, err := regexp.Compile(f.Value)
		return err == nil && re.MatchString(stringify(v))
	},
}

// FilterOps 合法算子词表（由策略表键派生）。
var FilterOps = func() map[string]bool {
	ops := make(map[string]bool, len(FilterBuilders))
	for op := range FilterBuilders {
		ops[op] = true
	}
	return ops
}()

// FilterOpList 算子词表的有序展开（错误文案/文档用）。
func FilterOpList() []string { return []string{"eq", "ne", "contains", "exists", "regex"} }

// MatchFilters 全条目 AND 匹配；返回未命中条目的 op 供留痕定位。
// raw filters 未经校验时也安全：未登记 op 恒不命中（deny by default）。
func MatchFilters(fs []Filter, payload map[string]any) (bool, string) {
	for _, f := range fs {
		v, has := LookupPath(payload, f.Path)
		if !FilterHit(f, v, has) {
			return false, f.Op
		}
	}
	return true, ""
}

// FilterHit 单条目判定：未登记 op 恒 false。
func FilterHit(f Filter, v any, has bool) bool {
	build, ok := FilterBuilders[f.Op]
	return ok && build(f, v, has)
}

// LookupPath 点分路径取值：map 逐层下钻 + 数组数字下标；返回 (值, 是否存在)。
func LookupPath(payload map[string]any, path string) (any, bool) {
	if path == "" {
		return nil, false
	}
	var cur any = payload
	for _, seg := range strings.Split(path, ".") {
		switch node := cur.(type) {
		case map[string]any:
			v, ok := node[seg]
			if !ok {
				return nil, false
			}
			cur = v
		case []any:
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(node) {
				return nil, false
			}
			cur = node[idx]
		default:
			return nil, false
		}
	}
	return cur, true
}

// stringify 标量原样、容器紧凑 JSON（过滤/模板共用一个字符串化口径）。
func stringify(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return fmt.Sprintf("%v", t)
		}
		return string(b)
	}
}

// ParseFilters 解析宿主以 JSON 列存储的过滤条目（空串=无过滤）。
func ParseFilters(raw string) ([]Filter, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var fs []Filter
	if err := json.Unmarshal([]byte(raw), &fs); err != nil {
		return nil, fmt.Errorf("%w: filters 必须是 JSON 数组: %v", ErrInvalidSource, err)
	}
	return fs, nil
}

// FormatFilters 过滤条目序列化为 JSON 列文本（宿主持久化用）。
func FormatFilters(fs []Filter) (string, error) {
	if len(fs) == 0 {
		return "", nil
	}
	b, err := json.Marshal(fs)
	if err != nil {
		return "", fmt.Errorf("eventsrc: filters 序列化失败: %w", err)
	}
	return string(b), nil
}
