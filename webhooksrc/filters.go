package webhooksrc

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// FilterBuilders 过滤算子策略表：op → 判定函数。has 门槛由各算子自表
// （取值缺失时仅 exists 与 ne 的 false 分支可命中）。新增算子只加一行，
// 校验与执行永不分叉。
var FilterBuilders = map[string]func(f Filter, v any, has bool) bool{
	"exists": func(f Filter, _ any, has bool) bool {
		want := f.Value == "true" || f.Value == ""
		return has == want
	},
	"ne": func(f Filter, v any, has bool) bool {
		return has && Stringify(v) != f.Value
	},
	"eq": func(f Filter, v any, has bool) bool {
		return has && Stringify(v) == f.Value
	},
	"contains": func(f Filter, v any, has bool) bool {
		return has && strings.Contains(Stringify(v), f.Value)
	},
	"regex": func(f Filter, v any, has bool) bool {
		if !has {
			return false
		}
		re, err := regexp.Compile(f.Value)
		return err == nil && re.MatchString(Stringify(v))
	},
}

// ValidFilterOp 算子是否登记（未登记 op 一律不命中，deny by default）。
func ValidFilterOp(op string) bool {
	_, ok := FilterBuilders[op]
	return ok
}

// FilterHit 单条目判定。
func FilterHit(f Filter, v any, has bool) bool {
	build, ok := FilterBuilders[f.Op]
	return ok && build(f, v, has)
}

// MatchFilters 全条目 AND 匹配；返回未命中条目的 op 供留痕定位（全命中
// 返回空串）。
func MatchFilters(filters []Filter, payload map[string]any) (bool, string) {
	for _, f := range filters {
		v, has := LookupPath(payload, f.Path)
		if !FilterHit(f, v, has) {
			return false, f.Op
		}
	}
	return true, ""
}

// LookupPath 点分路径取值：map 逐层下钻 + 数组数字下标；返回（值, 是否
// 存在）。路径段不支持转义，键名本身含 "." 的载荷无法用点路径表达。
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

// Stringify 标量原样、容器紧凑 JSON（过滤/模板共用一个字符串化口径）。
func Stringify(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case json.Number:
		return t.String()
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return fmt.Sprintf("%v", t)
		}
		return string(b)
	}
}
