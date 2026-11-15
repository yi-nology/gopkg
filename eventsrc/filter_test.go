package eventsrc

import (
	"strings"
	"testing"
)

func TestMatchFiltersAND(t *testing.T) {
	payload := map[string]any{
		"a": map[string]any{"b": "x"},
		"n": float64(1),
	}
	ok, op := MatchFilters(nil, payload)
	if !ok || op != "" {
		t.Fatalf("空过滤器应放行: ok=%v op=%q", ok, op)
	}
	ok, op = MatchFilters([]Filter{
		{Path: "a.b", Op: "eq", Value: "x"},
		{Path: "n", Op: "eq", Value: "1"},
	}, payload)
	if !ok {
		t.Fatalf("全命中应放行: op=%q", op)
	}
	ok, op = MatchFilters([]Filter{
		{Path: "a.b", Op: "eq", Value: "x"},
		{Path: "n", Op: "eq", Value: "2"},
	}, payload)
	if ok || op != "eq" {
		t.Fatalf("未命中应拒绝并回报 op: ok=%v op=%q", ok, op)
	}
}

func TestLookupPathEdgeCases(t *testing.T) {
	payload := map[string]any{"a": map[string]any{"b": map[string]any{"c": "v"}}}
	tests := []struct {
		path string
		ok   bool
		val  string
	}{
		{"a.b.c", true, "v"},
		{"a.b", true, `{"c":"v"}`},
		{"", false, ""},
		{"a.x", false, ""},
		{"a.b.c.d", false, ""},
	}
	for _, tc := range tests {
		v, ok := LookupPath(payload, tc.path)
		if ok != tc.ok {
			t.Fatalf("LookupPath(%q) ok=%v, want %v", tc.path, ok, tc.ok)
		}
		if ok && stringify(v) != tc.val {
			t.Fatalf("LookupPath(%q)=%q, want %q", tc.path, stringify(v), tc.val)
		}
	}
}

func TestParseFormatFilters(t *testing.T) {
	raw := `[{"path":"a","op":"eq","value":"1"}]`
	fs, err := ParseFilters(raw)
	if err != nil || len(fs) != 1 || fs[0].Path != "a" {
		t.Fatalf("fs=%+v err=%v", fs, err)
	}
	out, err := FormatFilters(fs)
	if err != nil || out != `[{"path":"a","op":"eq","value":"1"}]` {
		t.Fatalf("out=%q err=%v", out, err)
	}
	if _, err := ParseFilters(`{}`); err == nil {
		t.Fatal("非数组应报错")
	}
	if fs, err := ParseFilters("  "); err != nil || fs != nil {
		t.Fatalf("空串 fs=%+v err=%v", fs, err)
	}
	if s, err := FormatFilters(nil); err != nil || s != "" {
		t.Fatalf("s=%q err=%v", s, err)
	}
}

func TestRenderTemplate(t *testing.T) {
	payload := map[string]any{
		"event": map[string]any{"action": "opened", "count": float64(3)},
		"list":  []any{"a", "b"},
	}
	tests := []struct {
		name string
		tmpl string
		want string
	}{
		{"未知路径为空", "x={{nope}} y={{event.missing}}", "x= y="},
		{"嵌套路径", "{{event.action}}", "opened"},
		{"数字", "{{event.count}}", "3"},
		{"数组下标", "{{list.1}}", "b"},
		{"下划线变量", "{{_source}}", "src"},
		{"空白容忍", "{{ event.action }}", "opened"},
		{"非占位保留", "{{ bad path }}", "{{ bad path }}"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := RenderTemplate(tc.tmpl, "src", payload); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
	raw := RenderTemplate("{{_raw}}", "src", payload)
	if !strings.Contains(raw, `"action":"opened"`) {
		t.Fatalf("_raw=%q", raw)
	}
	def := RenderTemplate("", "src", payload)
	if !strings.Contains(def, "src") || !strings.Contains(def, `"action":"opened"`) {
		t.Fatalf("缺省模板=%q", def)
	}
	long := RenderTemplate(strings.Repeat("x", InputCap+10), "", payload)
	if len(long) <= InputCap || !strings.Contains(long, "超限截断") {
		t.Fatalf("超限截断未生效: len=%d", len(long))
	}
}

func TestSnapshotRedacts(t *testing.T) {
	body := []byte(`{"password":"P@SSVALUE","user":"bob","nested":{"api_token":"TOKENVALUE"},"list":[{"secret":"SECRETVALUE"}]}`)
	snap := Snapshot(body)
	for _, leak := range []string{"P@SSVALUE", "TOKENVALUE", "SECRETVALUE"} {
		if strings.Contains(snap, leak) {
			t.Fatalf("快照泄漏 %q: %s", leak, snap)
		}
	}
	if !strings.Contains(snap, "bob") {
		t.Fatalf("非敏感字段应保留: %s", snap)
	}
	if !strings.Contains(snap, `"***"`) {
		t.Fatalf("敏感值应打码: %s", snap)
	}

	text := Snapshot([]byte(`password=hunter2&user=bob token: abc`))
	if strings.Contains(text, "hunter2") || strings.Contains(text, "abc") {
		t.Fatalf("文本级脱敏失败: %s", text)
	}
	if !strings.Contains(text, "user=bob") {
		t.Fatalf("文本级非敏感字段应保留: %s", text)
	}

	long := Snapshot([]byte(`{"k":"` + strings.Repeat("x", PayloadCap+100) + `"}`))
	if len(long) > PayloadCap {
		t.Fatalf("快照未截断: len=%d", len(long))
	}

	huge := make([]byte, MaxBodyBytes+100)
	for i := range huge {
		huge[i] = 'a'
	}
	if got := Snapshot(huge); len(got) > PayloadCap {
		t.Fatalf("超大 body 快照未截断: len=%d", len(got))
	}
}

func TestFilterOpListStable(t *testing.T) {
	got := strings.Join(FilterOpList(), "|")
	if got != "eq|ne|contains|exists|regex" {
		t.Fatalf("got %q", got)
	}
	if len(FilterOps) != len(FilterOpList()) {
		t.Fatalf("FilterOps 与列表不一致")
	}
}
