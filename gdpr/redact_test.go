package gdpr

import (
	"errors"
	"testing"
	"time"
)

// TestDenyListRedactor 默认脱敏规则：字段名片段大小写/连字符不敏感、
// 嵌套 map/slice/map[string]string 逐层剔除、普通字段保留、入参不变。
func TestDenyListRedactor(t *testing.T) {
	r, err := NewRedactor()
	if err != nil {
		t.Fatalf("NewRedactor: %v", err)
	}
	in := Record{
		"id":            7,
		"username":      "alice",
		"email":         "alice@example.com",
		"password":      "p",
		"PASSWORD_HASH": "h",
		"api-key":       "k",
		"api_key":       "k2",
		"session_token": "t",
		"private_key":   "pk",
		"authorization": "Bearer x",
		"cookie":        "c",
		"password_salt": "s",
		"active":        true,
		"score":         1.5,
		"nested": map[string]any{
			"note": "ok",
			"mfa":  map[string]any{"secret": "s", "enabled": true},
		},
		"dict": map[string]string{"team": "ops", "client_secret": "cs"},
		"list": []any{
			map[string]any{"id": 1, "refresh_token": "rt"},
			"plain",
			[]any{map[string]any{"credential_id": "c"}},
		},
		"records": []Record{{"id": 2, "token": "t"}},
		"maps":    []map[string]any{{"id": 3, "cookie": "c"}},
		"when":    time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}

	got, err := r.Redact(in)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	// 顶层敏感字段全部剔除。
	for _, key := range []string{
		"password", "PASSWORD_HASH", "api-key", "api_key", "session_token",
		"private_key", "authorization", "cookie", "password_salt",
	} {
		if _, exists := got[key]; exists {
			t.Fatalf("敏感字段 %q 未剔除", key)
		}
	}
	// 普通字段与类型保留。
	if got["id"] != 7 || got["username"] != "alice" || got["active"] != true || got["score"] != 1.5 {
		t.Fatalf("普通字段失真: %+v", got)
	}
	nested := got["nested"].(Record)
	if nested["note"] != "ok" {
		t.Fatalf("嵌套普通字段失真: %+v", nested)
	}
	if _, exists := findKey(nested, "secret"); exists {
		t.Fatalf("嵌套敏感字段未剔除: %+v", nested)
	}
	dict := got["dict"].(Record)
	if dict["team"] != "ops" {
		t.Fatalf("map[string]string 普通字段失真: %+v", dict)
	}
	if _, exists := findKey(dict, "client_secret"); exists {
		t.Fatalf("map[string]string 敏感字段未剔除: %+v", dict)
	}
	if _, exists := findKey(got["list"], "refresh_token"); exists {
		t.Fatalf("slice 内敏感字段未剔除: %+v", got["list"])
	}
	if _, exists := findKey(got["records"], "token"); exists {
		t.Fatalf("[]Record 内敏感字段未剔除: %+v", got["records"])
	}
	if _, exists := findKey(got["maps"], "cookie"); exists {
		t.Fatalf("[]map 内敏感字段未剔除: %+v", got["maps"])
	}
	// 入参未被修改。
	if in["password"] != "p" || in["PASSWORD_HASH"] != "h" {
		t.Fatal("Redact 不得修改入参")
	}
}

// TestRedactorAdditiveAndErrors 追加敏感片段、nil 记录、空片段拒绝、
// 不可安全判定类型 fail-closed。
func TestRedactorAdditiveAndErrors(t *testing.T) {
	if _, err := NewRedactor("  "); err == nil {
		t.Fatal("追加空片段应拒绝")
	}
	r, err := NewRedactor("mfa_seed", "MFA-SEED")
	if err != nil {
		t.Fatalf("NewRedactor: %v", err)
	}
	got, err := r.Redact(Record{"mfa_seed": "x", "mfa-seed_backup": "y", "keep": "z"})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if len(got) != 1 || got["keep"] != "z" {
		t.Fatalf("追加片段未生效: %+v", got)
	}

	if got, err := r.Redact(nil); err != nil || got != nil {
		t.Fatalf("nil 记录应原样 nil: %+v / %v", got, err)
	}

	type hostStruct struct{ ID int }
	bad := []struct {
		name string
		val  any
	}{
		{"struct", hostStruct{ID: 1}},
		{"指针", &hostStruct{ID: 1}},
		{"bytes", []byte("raw")},
		{"raw json", []byte(`{"token":"x"}`)},
		{"通道", make(chan int)},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			_, err := r.Redact(Record{"field": c.val})
			if !errors.Is(err, ErrUnsupportedValue) {
				t.Fatalf("应 ErrUnsupportedValue，got %v", err)
			}
		})
	}

	// 嵌套里的坏类型同样 fail-closed（不是只查顶层）。
	if _, err := r.Redact(Record{"list": []any{map[string]any{"x": hostStruct{}}}}); !errors.Is(err, ErrUnsupportedValue) {
		t.Fatalf("嵌套坏类型应 ErrUnsupportedValue，got %v", err)
	}
}
