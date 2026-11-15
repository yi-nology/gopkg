package webhooksrc

import (
	"encoding/json"
	"testing"
)

func testPayload() map[string]any {
	return map[string]any{
		"alert": map[string]any{
			"name":   "cpu-high",
			"labels": map[string]any{"env": "prod", "team": "sre"},
		},
		"count": float64(3),
		"items": []any{map[string]any{"id": "a"}, map[string]any{"id": "b"}},
		"ok":    true,
	}
}

func TestLookupPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		path   string
		want   any
		wantOK bool
	}{
		{"simple", "count", float64(3), true},
		{"nested", "alert.name", "cpu-high", true},
		{"array index", "items.1.id", "b", true},
		{"missing key", "alert.missing", nil, false},
		{"array out of range", "items.9", nil, false},
		{"array non numeric", "items.x", nil, false},
		{"traverse scalar", "count.x", nil, false},
		{"empty path", "", nil, false},
		{"nil value exists", "alert.labels", map[string]any{"env": "prod", "team": "sre"}, true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := LookupPath(testPayload(), tt.path)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if tt.wantOK {
				gj, _ := json.Marshal(got)
				wj, _ := json.Marshal(tt.want)
				if string(gj) != string(wj) {
					t.Fatalf("got %s, want %s", gj, wj)
				}
			}
		})
	}
}

func TestStringify(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   any
		want string
	}{
		{nil, ""},
		{"x", "x"},
		{true, "true"},
		{float64(3.5), "3.5"},
		{json.Number("42"), "42"},
		{map[string]any{"a": "b"}, `{"a":"b"}`},
		{[]any{1.0, "x"}, `[1,"x"]`},
	}
	for _, tt := range tests {
		if got := Stringify(tt.in); got != tt.want {
			t.Fatalf("Stringify(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestFilterHit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		f    Filter
		v    any
		has  bool
		want bool
	}{
		{"eq hit", Filter{Op: "eq", Value: "prod"}, "prod", true, true},
		{"eq miss", Filter{Op: "eq", Value: "prod"}, "dev", true, false},
		{"eq missing", Filter{Op: "eq", Value: "prod"}, nil, false, false},
		{"ne hit", Filter{Op: "ne", Value: "prod"}, "dev", true, true},
		{"ne missing", Filter{Op: "ne", Value: "prod"}, nil, false, false},
		{"contains hit", Filter{Op: "contains", Value: "cpu"}, "cpu-high", true, true},
		{"contains miss", Filter{Op: "contains", Value: "mem"}, "cpu-high", true, false},
		{"regex hit", Filter{Op: "regex", Value: `^cpu-`}, "cpu-high", true, true},
		{"regex miss", Filter{Op: "regex", Value: `^mem-`}, "cpu-high", true, false},
		{"regex invalid", Filter{Op: "regex", Value: `[`}, "x", true, false},
		{"exists true", Filter{Op: "exists", Value: "true"}, "x", true, true},
		{"exists empty value", Filter{Op: "exists"}, "x", true, true},
		{"exists missing", Filter{Op: "exists", Value: "true"}, nil, false, false},
		{"not exists", Filter{Op: "exists", Value: "false"}, nil, false, true},
		{"not exists but present", Filter{Op: "exists", Value: "false"}, "x", true, false},
		{"unknown op", Filter{Op: "gt", Value: "1"}, "2", true, false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := FilterHit(tt.f, tt.v, tt.has); got != tt.want {
				t.Fatalf("FilterHit(%+v,%v,%v) = %v, want %v", tt.f, tt.v, tt.has, got, tt.want)
			}
		})
	}
}

func TestMatchFilters(t *testing.T) {
	t.Parallel()
	p := testPayload()
	tests := []struct {
		name       string
		filters    []Filter
		wantOK     bool
		wantFailed string
	}{
		{"empty", nil, true, ""},
		{"all match", []Filter{
			{Path: "alert.name", Op: "eq", Value: "cpu-high"},
			{Path: "alert.labels.env", Op: "eq", Value: "prod"},
			{Path: "count", Op: "ne", Value: "0"},
		}, true, ""},
		{"one fails reports op", []Filter{
			{Path: "alert.name", Op: "eq", Value: "cpu-high"},
			{Path: "alert.labels.env", Op: "eq", Value: "dev"},
		}, false, "eq"},
		{"regex path", []Filter{{Path: "alert.labels.team", Op: "regex", Value: `^s`}}, true, ""},
		{"array path", []Filter{{Path: "items.0.id", Op: "eq", Value: "a"}}, true, ""},
		{"unknown op denies", []Filter{{Path: "count", Op: "gt", Value: "1"}}, false, "gt"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ok, failed := MatchFilters(tt.filters, p)
			if ok != tt.wantOK || failed != tt.wantFailed {
				t.Fatalf("MatchFilters = (%v,%q), want (%v,%q)", ok, failed, tt.wantOK, tt.wantFailed)
			}
		})
	}
}

func TestValidFilterOp(t *testing.T) {
	t.Parallel()
	for _, op := range []string{"eq", "ne", "contains", "exists", "regex"} {
		if !ValidFilterOp(op) {
			t.Fatalf("%q 应合法", op)
		}
	}
	for _, op := range []string{"", "gt", "EQ"} {
		if ValidFilterOp(op) {
			t.Fatalf("%q 应非法", op)
		}
	}
}
