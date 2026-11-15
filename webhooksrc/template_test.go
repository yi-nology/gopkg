package webhooksrc

import (
	"strings"
	"testing"
)

func TestRenderTemplate(t *testing.T) {
	t.Parallel()
	p := map[string]any{
		"alert": map[string]any{"name": "cpu-high", "value": float64(91)},
		"tags":  []any{"a", "b"},
		"ok":    true,
		"empty": "",
	}
	tests := []struct {
		name   string
		tmpl   string
		source string
		want   string
	}{
		{"placeholders", "{{alert.name}} value={{alert.value}} ok={{ok}}", "src", "cpu-high value=91 ok=true"},
		{"spaced placeholder", "{{ alert.name }}", "src", "cpu-high"},
		{"unknown path empty", "x{{alert.missing}}y", "src", "xy"},
		{"source", "from {{_source}}", "hook-1", "from hook-1"},
		{"container value", "{{tags}}", "src", `["a","b"]`},
		{"nil/empty", "{{empty}}", "src", ""},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := RenderTemplate(tt.tmpl, tt.source, p); got != tt.want {
				t.Fatalf("RenderTemplate = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRenderTemplateRawAndDefault(t *testing.T) {
	t.Parallel()
	p := map[string]any{"b": "2", "a": "1"}
	raw := RenderTemplate("{{_raw}}", "src", p)
	if raw != `{"a":"1","b":"2"}` {
		t.Fatalf("_raw = %q（键序应稳定）", raw)
	}
	def := RenderTemplate("   ", "hook-x", p)
	if !strings.Contains(def, "hook-x") || !strings.Contains(def, `{"a":"1","b":"2"}`) {
		t.Fatalf("默认模板 = %q", def)
	}
}

func TestRenderTemplateTruncation(t *testing.T) {
	t.Parallel()
	out := renderTemplate(strings.Repeat("x", 20), "src", map[string]any{}, 5)
	if !strings.HasPrefix(out, "xxxxx") || !strings.Contains(out, "超限截断") {
		t.Fatalf("截断输出 = %q", out)
	}
}
