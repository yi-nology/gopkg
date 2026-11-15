package eventsrc

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── 测试替身 ──

type memSources struct {
	mu sync.Mutex
	m  map[string]*Source
	// getErr 非 nil 时 Get 直接返回该错误（存储故障路径）。
	getErr error
}

func newMemSources() *memSources { return &memSources{m: map[string]*Source{}} }

func (f *memSources) Get(_ context.Context, name string) (*Source, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, f.getErr
	}
	src, ok := f.m[name]
	if !ok {
		return nil, ErrSourceNotFound
	}
	cp := *src
	cp.Filters = cloneFilters(src.Filters)
	return &cp, nil
}

func (f *memSources) List(_ context.Context) ([]Source, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Source, 0, len(f.m))
	for _, src := range f.m {
		cp := *src
		cp.Filters = cloneFilters(src.Filters)
		out = append(out, cp)
	}
	return out, nil
}

func (f *memSources) Create(_ context.Context, src *Source) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *src
	f.m[src.Name] = &cp
	return nil
}

func (f *memSources) Save(_ context.Context, src *Source) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *src
	f.m[src.Name] = &cp
	return nil
}

func (f *memSources) Delete(_ context.Context, name string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.m[name]; !ok {
		return false, nil
	}
	delete(f.m, name)
	return true, nil
}

type memEvents struct {
	mu    sync.Mutex
	rows  []Event
	prune []pruneCall
	// recordErr 非 nil 时 Record 失败（必须不阻断管道）。
	recordErr error
	// pruneErr 非 nil 时 Prune 失败。
	pruneErr error
}

type pruneCall struct {
	source string
	before time.Time
}

func (f *memEvents) Record(_ context.Context, ev Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.recordErr != nil {
		return f.recordErr
	}
	f.rows = append(f.rows, ev)
	return nil
}

func (f *memEvents) List(_ context.Context, source string, limit int) ([]Event, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Event, 0, len(f.rows))
	for i := len(f.rows) - 1; i >= 0; i-- {
		if source != "" && f.rows[i].Source != source {
			continue
		}
		out = append(out, f.rows[i])
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (f *memEvents) Prune(_ context.Context, source string, before time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prune = append(f.prune, pruneCall{source: source, before: before})
	if f.pruneErr != nil {
		return 0, f.pruneErr
	}
	return 3, nil
}

func (f *memEvents) last(t *testing.T) Event {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.rows) == 0 {
		t.Fatal("期望至少一条留痕")
	}
	return f.rows[len(f.rows)-1]
}

func signHMAC(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return SignaturePrefix + hex.EncodeToString(mac.Sum(nil))
}

func bearerHeader(secret string) http.Header {
	h := http.Header{}
	h.Set(HeaderAuthorization, "Bearer "+secret)
	return h
}

// ── 鉴权段 ──

func TestBearerAuth(t *testing.T) {
	const secret = "s3cret"
	body := []byte(`{"event":{"action":"opened"}}`)
	tests := []struct {
		name    string
		header  http.Header
		wantErr error
	}{
		{"Bearer 命中", bearerHeader(secret), nil},
		{"X-Webhook-Token 命中", http.Header{HeaderToken: []string{secret}}, nil},
		{"无凭据", http.Header{}, ErrBadToken},
		{"Bearer 错", bearerHeader("nope"), ErrBadToken},
		{"裸 token 错", http.Header{HeaderToken: []string{"nope"}}, ErrBadToken},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sources := newMemSources()
			events := &memEvents{}
			var delivered int
			svc := New(sources, events, func(context.Context, string, string) (string, error) {
				delivered++
				return "sess-1", nil
			})
			_ = sources.Create(context.Background(), &Source{
				Name: "src", Enabled: true, AuthMode: AuthBearer, Secret: secret,
			})
			res, err := svc.Ingest(context.Background(), Request{Name: "src", Header: tc.header, Body: body})
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err=%v, want %v", err, tc.wantErr)
				}
				if res != nil {
					t.Fatalf("拒绝分支不应返回 Result: %+v", res)
				}
				if delivered != 0 {
					t.Fatalf("拒绝分支不应投递，got %d", delivered)
				}
				ev := events.last(t)
				if ev.Status != StatusRejected || ev.Reason != ReasonBadToken {
					t.Fatalf("留痕=%+v, want reason=%s", ev, ReasonBadToken)
				}
				return
			}
			if err != nil {
				t.Fatalf("Ingest: %v", err)
			}
			if !res.Accepted || res.DeliveryID != "sess-1" {
				t.Fatalf("res=%+v", res)
			}
			if delivered != 1 {
				t.Fatalf("delivered=%d", delivered)
			}
			ev := events.last(t)
			if ev.Status != StatusAccepted || ev.Reason != "" || ev.DeliveryID != "sess-1" {
				t.Fatalf("留痕=%+v", ev)
			}
		})
	}
}

func TestHMACAuth(t *testing.T) {
	const secret = "hmac-secret"
	body := []byte(`{"hello":"world"}`)
	good := signHMAC(secret, body)
	tests := []struct {
		name   string
		header http.Header
		want   bool
	}{
		{"正确签名", http.Header{HeaderSignature: []string{good}}, true},
		{"签名错误", http.Header{HeaderSignature: []string{signHMAC("other", body)}}, false},
		{"body 篡改", http.Header{HeaderSignature: []string{good}}, false},
		{"缺签名", http.Header{}, false},
		{"前缀错", http.Header{HeaderSignature: []string{strings.Replace(good, "sha256=", "sha1=", 1)}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sources := newMemSources()
			events := &memEvents{}
			svc := New(sources, events, func(context.Context, string, string) (string, error) { return "sess", nil })
			_ = sources.Create(context.Background(), &Source{
				Name: "src", Enabled: true, AuthMode: AuthHMAC, Secret: secret,
			})
			reqBody := body
			if tc.name == "body 篡改" {
				reqBody = []byte(`{"hello":"tampered"}`)
			}
			_, err := svc.Ingest(context.Background(), Request{Name: "src", Header: tc.header, Body: reqBody})
			if tc.want {
				if err != nil {
					t.Fatalf("Ingest: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrBadSignature) {
				t.Fatalf("err=%v, want ErrBadSignature", err)
			}
			if ev := events.last(t); ev.Reason != ReasonBadSignature {
				t.Fatalf("留痕=%+v", ev)
			}
		})
	}
}

func TestUnknownAuthModeFailsClosed(t *testing.T) {
	sources := newMemSources()
	svc := New(sources, &memEvents{}, nil)
	_ = sources.Create(context.Background(), &Source{Name: "src", Enabled: true, AuthMode: "nope", Secret: "x"})
	_, err := svc.Ingest(context.Background(), Request{Name: "src", Body: []byte(`{}`)})
	if !errors.Is(err, ErrBadToken) {
		t.Fatalf("err=%v, want ErrBadToken", err)
	}
}

// ── 限频段 ──

func TestRateLimitPerSource(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	sources := newMemSources()
	events := &memEvents{}
	svc := New(sources, events, func(context.Context, string, string) (string, error) { return "id", nil },
		WithClock(func() time.Time { return now }))
	_ = sources.Create(context.Background(), &Source{Name: "a", Enabled: true, AuthMode: AuthBearer, Secret: "x", RatePerMin: 2})
	_ = sources.Create(context.Background(), &Source{Name: "b", Enabled: true, AuthMode: AuthBearer, Secret: "x", RatePerMin: 2})
	h := bearerHeader("x")

	for i := 0; i < 2; i++ {
		if _, err := svc.Ingest(context.Background(), Request{Name: "a", Header: h, Body: []byte(`{}`)}); err != nil {
			t.Fatalf("第 %d 次应放行: %v", i+1, err)
		}
	}
	_, err := svc.Ingest(context.Background(), Request{Name: "a", Header: h, Body: []byte(`{}`)})
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err=%v, want ErrRateLimited", err)
	}
	if HTTPStatus(err) != http.StatusTooManyRequests {
		t.Fatalf("status=%d", HTTPStatus(err))
	}
	if ev := events.last(t); ev.Reason != ReasonRateLimited {
		t.Fatalf("留痕=%+v", ev)
	}
	// 每源独立窗口。
	if _, err := svc.Ingest(context.Background(), Request{Name: "b", Header: h, Body: []byte(`{}`)}); err != nil {
		t.Fatalf("源 b 不应受源 a 影响: %v", err)
	}
	// 窗口滚动后放行。
	now = now.Add(61 * time.Second)
	if _, err := svc.Ingest(context.Background(), Request{Name: "a", Header: h, Body: []byte(`{}`)}); err != nil {
		t.Fatalf("窗口滚动后应放行: %v", err)
	}
}

func TestRateLimitConcurrent(t *testing.T) {
	const max = 10
	sources := newMemSources()
	var mu sync.Mutex
	delivered := 0
	svc := New(sources, nil, func(context.Context, string, string) (string, error) {
		mu.Lock()
		delivered++
		mu.Unlock()
		return "id", nil
	})
	_ = sources.Create(context.Background(), &Source{Name: "src", Enabled: true, AuthMode: AuthBearer, Secret: "x", RatePerMin: max})
	h := bearerHeader("x")
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = svc.Ingest(context.Background(), Request{Name: "src", Header: h, Body: []byte(`{}`)})
		}()
	}
	wg.Wait()
	if delivered != max {
		t.Fatalf("delivered=%d, want %d", delivered, max)
	}
}

// ── 过滤段 ──

func TestMatchFiltersOps(t *testing.T) {
	payload := map[string]any{
		"event": map[string]any{"action": "opened", "labels": []any{"p1", "p2"}},
		"n":     float64(42),
		"ok":    true,
	}
	tests := []struct {
		name string
		f    Filter
		want bool
	}{
		{"eq 命中", Filter{Path: "event.action", Op: "eq", Value: "opened"}, true},
		{"eq 未中", Filter{Path: "event.action", Op: "eq", Value: "closed"}, false},
		{"ne 命中", Filter{Path: "event.action", Op: "ne", Value: "closed"}, true},
		{"ne 缺字段恒 false", Filter{Path: "event.missing", Op: "ne", Value: "x"}, false},
		{"contains 命中", Filter{Path: "event.action", Op: "contains", Value: "pen"}, true},
		{"contains 未中", Filter{Path: "event.action", Op: "contains", Value: "zzz"}, false},
		{"exists true", Filter{Path: "event.action", Op: "exists", Value: "true"}, true},
		{"exists 缺省即 true", Filter{Path: "event.action", Op: "exists"}, true},
		{"exists 未中", Filter{Path: "event.nope", Op: "exists", Value: "true"}, false},
		{"exists false 对缺字段", Filter{Path: "event.nope", Op: "exists", Value: "false"}, true},
		{"exists false 对在场字段", Filter{Path: "event.action", Op: "exists", Value: "false"}, false},
		{"regex 命中", Filter{Path: "event.action", Op: "regex", Value: "^open"}, true},
		{"regex 未中", Filter{Path: "event.action", Op: "regex", Value: "^close"}, false},
		{"regex 坏模式恒 false", Filter{Path: "event.action", Op: "regex", Value: "["}, false},
		{"未知 op 恒 false", Filter{Path: "event.action", Op: "gt", Value: "1"}, false},
		{"数字标量", Filter{Path: "n", Op: "eq", Value: "42"}, true},
		{"布尔标量", Filter{Path: "ok", Op: "eq", Value: "true"}, true},
		{"数组下标", Filter{Path: "event.labels.1", Op: "eq", Value: "p2"}, true},
		{"数组越界", Filter{Path: "event.labels.9", Op: "exists", Value: "true"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, has := LookupPath(payload, tc.f.Path)
			if got := FilterHit(tc.f, v, has); got != tc.want {
				t.Fatalf("FilterHit(%+v)=%v, want %v", tc.f, got, tc.want)
			}
		})
	}
}

func TestFilteredPipeline(t *testing.T) {
	sources := newMemSources()
	events := &memEvents{}
	delivered := 0
	svc := New(sources, events, func(context.Context, string, string) (string, error) {
		delivered++
		return "id", nil
	})
	_ = sources.Create(context.Background(), &Source{
		Name: "src", Enabled: true, AuthMode: AuthBearer, Secret: "x",
		Filters: []Filter{
			{Path: "event.action", Op: "eq", Value: "opened"},
			{Path: "repository.private", Op: "eq", Value: "false"},
		},
	})
	h := bearerHeader("x")
	res, err := svc.Ingest(context.Background(), Request{Name: "src", Header: h,
		Body: []byte(`{"event":{"action":"closed"},"repository":{"private":false}}`)})
	if err != nil {
		t.Fatalf("filtered 不应是 error: %v", err)
	}
	if res.Accepted || res.Reason != ReasonFiltered || res.FilterOp != "eq" {
		t.Fatalf("res=%+v", res)
	}
	if delivered != 0 {
		t.Fatalf("过滤未命中不应投递")
	}
	if ev := events.last(t); ev.Status != StatusRejected || ev.Reason != ReasonFiltered {
		t.Fatalf("留痕=%+v", ev)
	}
}

// ── 载荷/模板/投递段 ──

func TestBadPayload(t *testing.T) {
	big := make([]byte, MaxBodyBytes+1)
	for i := range big {
		big[i] = 'a'
	}
	tests := []struct {
		name string
		body []byte
	}{
		{"非 JSON", []byte(`not-json`)},
		{"JSON null", []byte(`null`)},
		{"JSON 数组", []byte(`[1,2]`)},
		{"JSON 标量", []byte(`"x"`)},
		{"超体量", big},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sources := newMemSources()
			events := &memEvents{}
			svc := New(sources, events, func(context.Context, string, string) (string, error) { return "id", nil })
			_ = sources.Create(context.Background(), &Source{Name: "src", Enabled: true, AuthMode: AuthBearer, Secret: "x"})
			_, err := svc.Ingest(context.Background(), Request{Name: "src", Header: bearerHeader("x"), Body: tc.body})
			if !errors.Is(err, ErrBadPayload) {
				t.Fatalf("err=%v, want ErrBadPayload", err)
			}
			if ev := events.last(t); ev.Reason != ReasonBadPayload {
				t.Fatalf("留痕=%+v", ev)
			}
		})
	}
}

func TestTemplateRenderedIntoDelivery(t *testing.T) {
	sources := newMemSources()
	var got string
	svc := New(sources, nil, func(_ context.Context, source, input string) (string, error) {
		got = source + "|" + input
		return "id", nil
	})
	_ = sources.Create(context.Background(), &Source{
		Name: "src", Enabled: true, AuthMode: AuthBearer, Secret: "x",
		Template: "源={{_source}} 动作={{event.action}} 未知={{nope.x}} 原始={{_raw}}",
	})
	body := []byte(`{"event":{"action":"opened"}}`)
	if _, err := svc.Ingest(context.Background(), Request{Name: "src", Header: bearerHeader("x"), Body: body}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	want := `src|源=src 动作=opened 未知= 原始={"event":{"action":"opened"}}`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSinkErrorRecorded(t *testing.T) {
	sources := newMemSources()
	events := &memEvents{}
	svc := New(sources, events, func(context.Context, string, string) (string, error) {
		return "", errors.New("downstream down")
	})
	_ = sources.Create(context.Background(), &Source{Name: "src", Enabled: true, AuthMode: AuthBearer, Secret: "x"})
	_, err := svc.Ingest(context.Background(), Request{Name: "src", Header: bearerHeader("x"), Body: []byte(`{}`)})
	if !errors.Is(err, ErrSink) {
		t.Fatalf("err=%v, want ErrSink", err)
	}
	ev := events.last(t)
	if ev.Status != StatusRejected || ev.Reason != ReasonError {
		t.Fatalf("留痕=%+v", ev)
	}
}

func TestRecordFailureDoesNotBlock(t *testing.T) {
	sources := newMemSources()
	events := &memEvents{recordErr: errors.New("db down")}
	svc := New(sources, events, func(context.Context, string, string) (string, error) { return "id", nil })
	_ = sources.Create(context.Background(), &Source{Name: "src", Enabled: true, AuthMode: AuthBearer, Secret: "x"})
	res, err := svc.Ingest(context.Background(), Request{Name: "src", Header: bearerHeader("x"), Body: []byte(`{}`)})
	if err != nil || !res.Accepted {
		t.Fatalf("留痕失败不应阻断: res=%+v err=%v", res, err)
	}
}

func TestUnknownAndDisabledSource(t *testing.T) {
	sources := newMemSources()
	events := &memEvents{}
	svc := New(sources, events, func(context.Context, string, string) (string, error) { return "id", nil })
	_, err := svc.Ingest(context.Background(), Request{Name: "missing", Header: bearerHeader("x"), Body: []byte(`{}`)})
	if !errors.Is(err, ErrUnknownSource) {
		t.Fatalf("err=%v, want ErrUnknownSource", err)
	}
	if ev := events.last(t); ev.Reason != ReasonUnknownSource {
		t.Fatalf("留痕=%+v", ev)
	}
	_ = sources.Create(context.Background(), &Source{Name: "off", Enabled: false, AuthMode: AuthBearer, Secret: "x"})
	_, err = svc.Ingest(context.Background(), Request{Name: "off", Header: bearerHeader("x"), Body: []byte(`{}`)})
	if !errors.Is(err, ErrDisabled) {
		t.Fatalf("err=%v, want ErrDisabled", err)
	}
	if ev := events.last(t); ev.Reason != ReasonDisabled {
		t.Fatalf("留痕=%+v", ev)
	}
}

func TestStorageErrorIsNotReject(t *testing.T) {
	sources := newMemSources()
	sources.getErr = errors.New("db down")
	svc := New(sources, nil, nil)
	_, err := svc.Ingest(context.Background(), Request{Name: "src", Body: []byte(`{}`)})
	if err == nil || ReasonOf(err) != "" {
		t.Fatalf("存储故障不应映射成拒绝原因: %v", err)
	}
}

// ── 管理面原语 ──

func TestCRUDAndSecretRotation(t *testing.T) {
	ctx := context.Background()
	sources := newMemSources()
	svc := New(sources, nil, nil)

	_, err := svc.Create(ctx, SourceInput{
		Name: "My-Source", AuthMode: AuthBearer, RatePerMin: 10,
		Filters: []Filter{{Path: "a", Op: "exists", Value: "true"}},
	})
	if err == nil {
		t.Fatal("大写源名应被拒")
	}
	if !errors.Is(err, ErrInvalidSource) {
		t.Fatalf("err=%v", err)
	}

	src, err := svc.Create(ctx, SourceInput{Name: "my-source", AuthMode: AuthBearer, RatePerMin: 10,
		Filters: []Filter{{Path: "a", Op: "exists", Value: "true"}}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(src.Secret) != 32 {
		t.Fatalf("secret=%q, want 32 hex", src.Secret)
	}
	oldSecret := src.Secret
	if src.Enabled != true {
		t.Fatal("Create 缺省应启用")
	}
	if _, err := svc.Create(ctx, SourceInput{Name: "my-source", AuthMode: AuthBearer}); !errors.Is(err, ErrSourceExists) {
		t.Fatalf("重复建源 err=%v", err)
	}

	// Update 空 Secret 保持原密钥。
	upd, err := svc.Update(ctx, "my-source", SourceInput{AuthMode: AuthHMAC, RatePerMin: 5})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if upd.Secret != oldSecret || upd.AuthMode != AuthHMAC || upd.RatePerMin != 5 {
		t.Fatalf("upd=%+v", upd)
	}
	if len(upd.Filters) != 0 {
		t.Fatalf("整对象更新应清空 filters: %+v", upd.Filters)
	}

	// Update 显式 Secret 即轮换。
	upd, err = svc.Update(ctx, "my-source", SourceInput{AuthMode: AuthHMAC, Secret: "new-secret"})
	if err != nil || upd.Secret != "new-secret" {
		t.Fatalf("upd=%+v err=%v", upd, err)
	}

	// ResetSecret 与旧值不同。
	rotated, err := svc.ResetSecret(ctx, "my-source")
	if err != nil || rotated == "" || rotated == "new-secret" {
		t.Fatalf("rotated=%q err=%v", rotated, err)
	}

	if _, err := svc.Update(ctx, "my-source", SourceInput{Name: "other", AuthMode: AuthBearer}); !errors.Is(err, ErrInvalidSource) {
		t.Fatalf("改名应被拒: %v", err)
	}
	if _, err := svc.Update(ctx, "missing", SourceInput{AuthMode: AuthBearer}); !errors.Is(err, ErrSourceNotFound) {
		t.Fatalf("err=%v", err)
	}
	if _, err := svc.ResetSecret(ctx, "missing"); !errors.Is(err, ErrSourceNotFound) {
		t.Fatalf("err=%v", err)
	}
	ok, err := svc.Delete(ctx, "my-source")
	if err != nil || !ok {
		t.Fatalf("Delete: %v %v", ok, err)
	}
	if _, err := svc.Delete(ctx, "my-source"); !errors.Is(err, ErrSourceNotFound) {
		t.Fatalf("重复删除 err=%v", err)
	}
}

func TestValidateSource(t *testing.T) {
	base := func() *Source {
		return &Source{Name: "src", AuthMode: AuthBearer, Secret: "x", RatePerMin: 10}
	}
	tests := []struct {
		name string
		mod  func(*Source)
		ok   bool
	}{
		{"合法", func(*Source) {}, true},
		{"空名", func(s *Source) { s.Name = "" }, false},
		{"大写名", func(s *Source) { s.Name = "SRC" }, false},
		{"两字符名", func(s *Source) { s.Name = "ab" }, false},
		{"空模式", func(s *Source) { s.AuthMode = "" }, false},
		{"坏模式", func(s *Source) { s.AuthMode = "basic" }, false},
		{"空密钥", func(s *Source) { s.Secret = " " }, false},
		{"负限频", func(s *Source) { s.RatePerMin = -1 }, false},
		{"超限频", func(s *Source) { s.RatePerMin = MaxRatePerMin + 1 }, false},
		{"负保留", func(s *Source) { s.Retention = -time.Second }, false},
		{"坏 op", func(s *Source) { s.Filters = []Filter{{Path: "a", Op: "gt"}} }, false},
		{"空 path", func(s *Source) { s.Filters = []Filter{{Op: "eq", Value: "1"}} }, false},
		{"坏 regex", func(s *Source) { s.Filters = []Filter{{Path: "a", Op: "regex", Value: "["}} }, false},
		{"模板超长", func(s *Source) { s.Template = strings.Repeat("x", InputCap+1) }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := base()
			tc.mod(src)
			err := ValidateSource(src)
			if tc.ok && err != nil {
				t.Fatalf("应合法: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("应非法")
			}
		})
	}
}

func TestPruneEventsUsesRetention(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	sources := newMemSources()
	events := &memEvents{}
	svc := New(sources, events, nil, WithClock(func() time.Time { return now }))
	_ = sources.Create(context.Background(), &Source{Name: "short", Retention: time.Hour})
	_ = sources.Create(context.Background(), &Source{Name: "default"})
	n, err := svc.PruneEvents(context.Background())
	if err != nil {
		t.Fatalf("PruneEvents: %v", err)
	}
	if n != 6 {
		t.Fatalf("n=%d, want 6", n)
	}
	if len(events.prune) != 2 {
		t.Fatalf("prune calls=%d", len(events.prune))
	}
	got := map[string]time.Time{}
	for _, c := range events.prune {
		got[c.source] = c.before
	}
	if !got["short"].Equal(now.Add(-time.Hour)) {
		t.Fatalf("short cutoff=%v", got["short"])
	}
	if !got["default"].Equal(now.Add(-DefaultRetention)) {
		t.Fatalf("default cutoff=%v", got["default"])
	}
}

func TestPruneEventsJoinsErrors(t *testing.T) {
	sources := newMemSources()
	events := &memEvents{pruneErr: errors.New("db down")}
	svc := New(sources, events, nil)
	_ = sources.Create(context.Background(), &Source{Name: "a"})
	_ = sources.Create(context.Background(), &Source{Name: "b"})
	_, err := svc.PruneEvents(context.Background())
	if err == nil || !strings.Contains(err.Error(), "源 a") || !strings.Contains(err.Error(), "源 b") {
		t.Fatalf("err=%v", err)
	}
}

func TestListEventsAndSources(t *testing.T) {
	ctx := context.Background()
	sources := newMemSources()
	events := &memEvents{}
	svc := New(sources, events, nil)
	if _, err := svc.ListEvents(ctx, "", 10); err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	_ = events.Record(ctx, Event{Source: "a", Status: StatusAccepted})
	_ = events.Record(ctx, Event{Source: "b", Status: StatusRejected})
	rows, err := svc.ListEvents(ctx, "a", 10)
	if err != nil || len(rows) != 1 || rows[0].Source != "a" {
		t.Fatalf("rows=%+v err=%v", rows, err)
	}
	_ = sources.Create(ctx, &Source{Name: "a"})
	if list, err := svc.ListSources(ctx); err != nil || len(list) != 1 {
		t.Fatalf("list=%+v err=%v", list, err)
	}
	empty := New(nil, nil, nil)
	if _, err := empty.ListSources(ctx); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("err=%v", err)
	}
	if _, err := empty.ListEvents(ctx, "", 1); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("err=%v", err)
	}
	if _, err := empty.PruneEvents(ctx); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("err=%v", err)
	}
	if _, err := empty.Ingest(ctx, Request{}); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("err=%v", err)
	}
}

func TestRejectErrorMapping(t *testing.T) {
	err := &RejectError{Reason: ReasonRateLimited, Status: 429, Message: "动态文案"}
	if !errors.Is(err, ErrRateLimited) {
		t.Fatal("按 Reason 判类失败")
	}
	if err.Error() != "动态文案" || ReasonOf(err) != ReasonRateLimited || HTTPStatus(err) != 429 {
		t.Fatalf("err=%v reason=%s status=%d", err, ReasonOf(err), HTTPStatus(err))
	}
	if ReasonOf(errors.New("x")) != "" || HTTPStatus(errors.New("x")) != 500 {
		t.Fatal("非拒绝错误映射错误")
	}
	var nilErr *RejectError
	if nilErr.Error() != "<nil>" {
		t.Fatalf("nil Error()=%q", nilErr.Error())
	}
}
