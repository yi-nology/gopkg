package diagbundle

import (
	"context"
	"errors"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// TestBuildHeader 契约：头部五键齐全；generated_at UTC RFC3339；config 恒为
// 非 nil map；hostname/version 由装配注入。
func TestBuildHeader(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.FixedZone("CST", 8*3600))
	b := New("v1.2.3",
		WithHostname("diag-host"),
		WithNow(func() time.Time { return now }),
		WithConfigSummary(map[string]any{"mode": "standalone"}),
	)
	out, err := b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{KeyGeneratedAt, KeyVersion, KeyHostname, KeyGoVersion, KeyConfig} {
		if _, ok := out[k]; !ok {
			t.Fatalf("支持包缺头部键 %s", k)
		}
	}
	if got, want := out[KeyGeneratedAt], "2026-11-15T04:00:00Z"; got != want {
		t.Errorf("generated_at=%v want %v", got, want)
	}
	if out[KeyVersion] != "v1.2.3" {
		t.Errorf("version=%v", out[KeyVersion])
	}
	if out[KeyHostname] != "diag-host" {
		t.Errorf("hostname=%v", out[KeyHostname])
	}
	if out[KeyGoVersion] != runtime.Version() {
		t.Errorf("go_version=%v want %v", out[KeyGoVersion], runtime.Version())
	}
	cfg, ok := out[KeyConfig].(map[string]any)
	if !ok || cfg["mode"] != "standalone" {
		t.Errorf("config=%#v", out[KeyConfig])
	}

	// 未注入摘要：config 是空 map（JSON {}），不是 null。
	plain, err := New("v0").Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	empty, ok := plain[KeyConfig].(map[string]any)
	if !ok || empty == nil || len(empty) != 0 {
		t.Errorf("空配置摘要应为非 nil 空 map: %#v", plain[KeyConfig])
	}
}

// TestBuildSections 契约：分节按注册结果逐节入包，provider 收到 ctx。
func TestBuildSections(t *testing.T) {
	type ctxKey struct{}
	b := New("v1")
	ctx := context.WithValue(context.Background(), ctxKey{}, "seen")
	if err := b.RegisterSection("storage", func(c context.Context) (any, error) {
		if c.Value(ctxKey{}) != "seen" {
			t.Error("分节未收到 ctx")
		}
		return map[string]any{"dialect": "sqlite", "tables": 3}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.RegisterSection("migrations", func(context.Context) (any, error) {
		return []string{"0001", "0002"}, nil
	}); err != nil {
		t.Fatal(err)
	}
	out, err := b.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	storage, ok := out["storage"].(map[string]any)
	if !ok || storage["dialect"] != "sqlite" {
		t.Errorf("storage=%#v", out["storage"])
	}
	if mig, ok := out["migrations"].([]string); !ok || len(mig) != 2 {
		t.Errorf("migrations=%#v", out["migrations"])
	}
}

// TestSectionFailureIsolated 契约：分节 error/panic 只落 <name>_error，其他分节
// 照常入包，Build 不整体失败。
func TestSectionFailureIsolated(t *testing.T) {
	b := New("v1")
	if err := b.RegisterSection("ok", func(context.Context) (any, error) {
		return "fine", nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.RegisterSection("bad", func(context.Context) (any, error) {
		return nil, errors.New("boom")
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.RegisterSection("panicky", func(context.Context) (any, error) {
		panic("section exploded")
	}); err != nil {
		t.Fatal(err)
	}
	out, err := b.Build(context.Background())
	if err != nil {
		t.Fatalf("分节故障不应整体失败: %v", err)
	}
	if out["ok"] != "fine" {
		t.Errorf("正常分节丢失: %#v", out["ok"])
	}
	if out["bad_error"] != "boom" {
		t.Errorf("bad_error=%#v", out["bad_error"])
	}
	if p, _ := out["panicky_error"].(string); !strings.Contains(p, "panic: section exploded") {
		t.Errorf("panic 未隔离: %#v", out["panicky_error"])
	}
}

// TestRegisterSectionValidation 契约：空名/保留键/_error 后缀/nil provider/重复
// 注册都 fail-fast。
func TestRegisterSectionValidation(t *testing.T) {
	b := New("v1")
	noop := func(context.Context) (any, error) { return nil, nil }
	for _, name := range []string{"", "   ", KeyGeneratedAt, KeyVersion, KeyHostname,
		KeyGoVersion, KeyConfig, KeyAuditChain, KeyAuditChainError, "storage_error"} {
		if err := b.RegisterSection(name, noop); !errors.Is(err, ErrInvalidSection) {
			t.Errorf("RegisterSection(%q) err=%v want ErrInvalidSection", name, err)
		}
	}
	if err := b.RegisterSection("storage", nil); !errors.Is(err, ErrInvalidSection) {
		t.Errorf("nil provider err=%v want ErrInvalidSection", err)
	}
	if err := b.RegisterSection(" storage ", noop); err != nil {
		t.Fatalf("合法分节注册失败: %v", err)
	}
	if err := b.RegisterSection("storage", noop); !errors.Is(err, ErrDuplicateSection) {
		t.Errorf("重复注册 err=%v want ErrDuplicateSection", err)
	}
}

// TestAuditChainHook 契约：成功落 audit_chain、失败落 audit_chain_error；nil 钩子
// 两键都不产；panic 也按错误落包。
func TestAuditChainHook(t *testing.T) {
	b := New("v1")
	if err := b.RegisterSection("storage", func(context.Context) (any, error) {
		return map[string]any{"tables": 1}, nil
	}); err != nil {
		t.Fatal(err)
	}
	b.SetAuditChain(func(context.Context) (any, error) {
		return map[string]any{"checked": 42, "broken": 0}, nil
	})
	out, err := b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	chain, ok := out[KeyAuditChain].(map[string]any)
	if !ok || chain["checked"] != 42 {
		t.Errorf("audit_chain=%#v", out[KeyAuditChain])
	}
	if _, ok := out[KeyAuditChainError]; ok {
		t.Error("成功时不应产 audit_chain_error")
	}

	b.SetAuditChain(func(context.Context) (any, error) {
		return nil, errors.New("chain broken at id=7")
	})
	out, err = b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out[KeyAuditChainError] != "chain broken at id=7" {
		t.Errorf("audit_chain_error=%#v", out[KeyAuditChainError])
	}
	if _, ok := out[KeyAuditChain]; ok {
		t.Error("失败时不应产 audit_chain")
	}

	b.SetAuditChain(func(context.Context) (any, error) { panic("verify boom") })
	out, _ = b.Build(context.Background())
	if p, _ := out[KeyAuditChainError].(string); !strings.Contains(p, "panic: verify boom") {
		t.Errorf("审计钩子 panic 未隔离: %#v", out[KeyAuditChainError])
	}

	// nil 钩子：两键都不产（与 bianque audit 未开启同形态）。
	b.SetAuditChain(nil)
	out, _ = b.Build(context.Background())
	if _, ok := out[KeyAuditChain]; ok {
		t.Error("nil 钩子不应产 audit_chain")
	}
	if _, ok := out[KeyAuditChainError]; ok {
		t.Error("nil 钩子不应产 audit_chain_error")
	}
}

// TestConfigSummaryCopied 契约：摘要复制进装配器、Build 再复制——调用方或前一次
// 包体的改动都不影响下一次构建；SetConfigSummary 合并同键覆盖。
func TestConfigSummaryCopied(t *testing.T) {
	src := map[string]any{"mode": "standalone", "audit_enabled": true}
	b := New("v1", WithConfigSummary(src))
	src["mode"] = "tampered"
	src["secret"] = "leaked"
	b.SetConfigSummary(map[string]any{"mode": "ha", "storage_mode": "postgres"})
	first, err := b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cfg := first[KeyConfig].(map[string]any)
	if cfg["mode"] != "ha" || cfg["storage_mode"] != "postgres" || cfg["audit_enabled"] != true {
		t.Fatalf("摘要合并/复制异常: %#v", cfg)
	}
	if _, ok := cfg["secret"]; ok {
		t.Fatal("调用方后置写入泄漏进了包")
	}
	cfg["mode"] = "mutated-bundle"
	second, _ := b.Build(context.Background())
	if second[KeyConfig].(map[string]any)["mode"] != "ha" {
		t.Error("前一次包体的改动污染了下一次构建")
	}
}

// TestWhitelistSummary 契约：只保留显式键，缺失/未列出的键丢弃；源 map 不变。
func TestWhitelistSummary(t *testing.T) {
	src := map[string]any{"mode": "standalone", "secret": "s3cr3t", "port": 8080}
	got := WhitelistSummary(src, "mode", "port", "missing")
	want := map[string]any{"mode": "standalone", "port": 8080}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("WhitelistSummary=%#v want %#v", got, want)
	}
	if _, ok := src["mode"]; !ok || len(src) != 3 {
		t.Errorf("源 map 被改动: %#v", src)
	}
	if len(WhitelistSummary(src)) != 0 {
		t.Error("空白名单应返回空摘要")
	}
}

// TestURLPresent 契约：只记非空布尔，去空白；目标本身不出现在返回值里。
func TestURLPresent(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"   \t\n", false},
		{"https://hooks.example.com/x?token=abc", true},
		{"  https://hooks.example.com/x  ", true},
		{"127.0.0.1:514", true},
	}
	for _, c := range cases {
		if got := URLPresent(c.in); got != c.want {
			t.Errorf("URLPresent(%q)=%v want %v", c.in, got, c.want)
		}
	}
}

// TestTruncatePayload 契约：超长截到 max 字节的 rune 边界 + 省略号；未超长原样；
// max<=0 用缺省 300。
func TestTruncatePayload(t *testing.T) {
	if got := TruncatePayload("short", 10); got != "short" {
		t.Errorf("未超长不应截断: %q", got)
	}
	long := strings.Repeat("y", 400)
	got := TruncatePayload(long, 300)
	if !strings.HasSuffix(got, "…") {
		t.Fatal("截断后应带省略号")
	}
	if n := len(strings.TrimSuffix(got, "…")); n != 300 {
		t.Errorf("payload 部分=%d bytes want 300", n)
	}

	// 多字节字符：不得截出半个 rune（合法 UTF-8、无替换符）。
	zh := strings.Repeat("故", 200) // 600 bytes
	got = TruncatePayload(zh, 10)
	if !utf8.ValidString(got) {
		t.Errorf("截断产生非法 UTF-8: %q", got)
	}
	if strings.ContainsRune(got, utf8.RuneError) {
		t.Errorf("截断产生 U+FFFD: %q", got)
	}
	body := strings.TrimSuffix(got, "…")
	if len(body) > 10 || !strings.HasPrefix(zh, body) {
		t.Errorf("截断结果=%q (%d bytes)", got, len(body))
	}

	// max<=0：按缺省 300 截断。
	if n := len(strings.TrimSuffix(TruncatePayload(long, 0), "…")); n != DefaultMaxPayload {
		t.Errorf("max<=0 未走缺省: %d", n)
	}
	if TruncatePayload("", 0) != "" {
		t.Error("空 payload 应原样返回")
	}
}

// TestCompactEvents 契约：事件瘦身为固定键集合，payload 截断，时间保留，空输入
// 返回非 nil 空切片。
func TestCompactEvents(t *testing.T) {
	at := time.Date(2026, 11, 15, 1, 2, 3, 0, time.UTC)
	rows := CompactEvents([]Event{
		{ID: 7, SessionID: "s1", Type: "step_failed", Level: "error", CreatedAt: at,
			Payload: strings.Repeat("z", 400)},
		{ID: 8, SessionID: "s2", Type: "note", Level: "info", CreatedAt: at, Payload: "ok"},
	}, 300)
	if len(rows) != 2 {
		t.Fatalf("rows=%d want 2", len(rows))
	}
	first := rows[0]
	if first["id"] != uint64(7) || first["session_id"] != "s1" || first["type"] != "step_failed" ||
		first["level"] != "error" || first["created_at"] != at {
		t.Errorf("事件字段异常: %#v", first)
	}
	p, _ := first["payload"].(string)
	if n := len(strings.TrimSuffix(p, "…")); n != 300 {
		t.Errorf("payload 未截断: %d bytes", n)
	}
	if rows[1]["payload"] != "ok" {
		t.Errorf("短 payload 被改动: %#v", rows[1]["payload"])
	}

	empty := CompactEvents(nil, 300)
	if empty == nil || len(empty) != 0 {
		t.Errorf("空输入应返回非 nil 空切片: %#v", empty)
	}
}

// TestBuildCanceledContext 契约：开始前已取消的 ctx 直接报错（不产半成品包）。
func TestBuildCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New("v1").Build(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("err=%v want context.Canceled", err)
	}
}

// TestBuildConcurrent Build 只读：多 goroutine 并发构建（-race 下验证无共享写）。
func TestBuildConcurrent(t *testing.T) {
	b := New("v1", WithConfigSummary(map[string]any{"mode": "standalone"}))
	if err := b.RegisterSection("storage", func(context.Context) (any, error) {
		return map[string]any{"tables": 3}, nil
	}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := b.Build(context.Background())
			if err != nil {
				t.Errorf("并发 Build: %v", err)
				return
			}
			if out[KeyVersion] != "v1" {
				t.Errorf("并发 Build 包体异常: %#v", out[KeyVersion])
			}
		}()
	}
	wg.Wait()
}
