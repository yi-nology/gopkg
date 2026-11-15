package alertroute

import (
	"errors"
	"testing"
	"time"
)

// TestRouteLabelsMatch 契约：空路由全匹配、坏 JSON 不命中、规则全键值命中、
// 缺失标签按空串比较（Prometheus matcher 同族语义）。
func TestRouteLabelsMatch(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		in   map[string]string
		want bool
	}{
		{"空串=全匹配", "", map[string]string{"env": "prod"}, true},
		{"纯空白=全匹配", " \t\n ", nil, true},
		{"空对象=全匹配", "{}", map[string]string{"env": "prod"}, true},
		{"null=空路由全匹配", "null", map[string]string{"env": "prod"}, true},
		{"单键命中", `{"env":"prod"}`, map[string]string{"env": "prod"}, true},
		{"入站多余标签不影响", `{"env":"prod"}`, map[string]string{"env": "prod", "host": "h1"}, true},
		{"值不符", `{"env":"prod"}`, map[string]string{"env": "dev"}, false},
		{"键缺失", `{"env":"prod"}`, map[string]string{"host": "h1"}, false},
		{"多键全命中", `{"env":"prod","cluster":"c1"}`, map[string]string{"env": "prod", "cluster": "c1"}, true},
		{"多键一值不符", `{"env":"prod","cluster":"c1"}`, map[string]string{"env": "prod", "cluster": "c2"}, false},
		{"多键一缺失", `{"env":"prod","cluster":"c1"}`, map[string]string{"env": "prod"}, false},
		{"空值规则命中缺失键", `{"env":""}`, map[string]string{"host": "h1"}, true},
		{"空值规则命中空值", `{"env":""}`, map[string]string{"env": ""}, true},
		{"坏 JSON 不命中", `{"env":`, map[string]string{"env": "prod"}, false},
		{"JSON 数组不命中", `["env","prod"]`, map[string]string{"env": "prod"}, false},
		{"非 string 值不命中", `{"n":1}`, map[string]string{"n": "1"}, false},
		{"nil 入站 + 非空规则", `{"env":"prod"}`, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := RouteLabelsMatch(c.raw, c.in); got != c.want {
				t.Errorf("RouteLabelsMatch(%q, %v)=%v want %v", c.raw, c.in, got, c.want)
			}
		})
	}
}

// TestNormalizeFingerprint 契约：去空白；空值拒绝（类型化哨兵）。
func TestNormalizeFingerprint(t *testing.T) {
	got, err := NormalizeFingerprint("  fp-abc \t")
	if err != nil || got != "fp-abc" {
		t.Fatalf("NormalizeFingerprint=%q err=%v want fp-abc", got, err)
	}
	for _, in := range []string{"", "   ", "\t\n"} {
		if _, err := NormalizeFingerprint(in); !errors.Is(err, ErrFingerprintRequired) {
			t.Errorf("NormalizeFingerprint(%q) err=%v want ErrFingerprintRequired", in, err)
		}
	}
}

// TestNormalizeStartsAt 契约：空值补 now 的 UTC RFC3339；非空原样保留（含时区）。
func TestNormalizeStartsAt(t *testing.T) {
	now := time.Date(2026, 11, 15, 8, 9, 10, 123, time.FixedZone("CST", 8*3600))
	if got, want := NormalizeStartsAt("", now), "2026-11-15T00:09:10Z"; got != want {
		t.Errorf("空 starts_at=%q want %q", got, want)
	}
	if got, want := NormalizeStartsAt("  ", now), "2026-11-15T00:09:10Z"; got != want {
		t.Errorf("空白 starts_at=%q want %q", got, want)
	}
	const given = "2026-11-15T10:00:00+08:00"
	if got := NormalizeStartsAt(" "+given+" ", now); got != given {
		t.Errorf("非空 starts_at 应原样保留: %q want %q", got, given)
	}
	if got := NormalizeStartsAt("not-a-timestamp", now); got != "not-a-timestamp" {
		t.Errorf("非空 starts_at 不解析不重格式化: %q", got)
	}
}

// TestNewDedupeKey 契约：同输入构造幂等；fingerprint 去空白；空 fingerprint 拒绝。
func TestNewDedupeKey(t *testing.T) {
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	k1, err := NewDedupeKey(" fp-1 ", "", now)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := NewDedupeKey("fp-1", "2026-11-15T00:00:00Z", now)
	if err != nil {
		t.Fatal(err)
	}
	if k1 != k2 {
		t.Fatalf("同锚点构造应相同: %+v vs %+v", k1, k2)
	}
	if _, err := NewDedupeKey("   ", "2026-11-15T00:00:00Z", now); !errors.Is(err, ErrFingerprintRequired) {
		t.Fatalf("空 fingerprint err=%v want ErrFingerprintRequired", err)
	}
}

// TestDedupeKeyMatches 契约：两字段逐字相等才算同一次受理；starts_at 空值无锚点，
// 不同 now 视为新事件（文档化的产品语义）。
func TestDedupeKeyMatches(t *testing.T) {
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	later := now.Add(time.Minute)
	k, _ := NewDedupeKey("fp", "2026-11-15T00:00:00Z", now)

	same := DedupeKey{Fingerprint: "fp", StartsAt: "2026-11-15T00:00:00Z"}
	if !k.Matches(same) {
		t.Errorf("%+v 应命中 %+v", k, same)
	}
	if k.Matches(DedupeKey{Fingerprint: "fp", StartsAt: "2026-11-15T00:01:00Z"}) {
		t.Error("starts_at 不同是新一轮告警，不得去重")
	}
	if k.Matches(DedupeKey{Fingerprint: "fp-other", StartsAt: k.StartsAt}) {
		t.Error("fingerprint 不同不得去重")
	}

	auto, _ := NewDedupeKey("fp", "", now)
	autoLater, _ := NewDedupeKey("fp", "", later)
	if auto.Matches(autoLater) {
		t.Error("空 starts_at 每次补当前时刻，重投应视为新事件（要幂等必须回传 starts_at）")
	}

	// 可比较：直接作 map 键（宿主可用作进程内收口表）。
	seen := map[DedupeKey]struct{}{k: {}}
	if _, ok := seen[same]; !ok {
		t.Error("DedupeKey 应可直接作 map 键")
	}
}
