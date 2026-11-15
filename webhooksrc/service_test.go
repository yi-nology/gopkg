package webhooksrc

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

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock {
	return &testClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

type recSink struct {
	mu    sync.Mutex
	calls []string
	err   error
}

func (s *recSink) Deliver(_ context.Context, source, input string) error {
	if s.err != nil {
		return s.err
	}
	s.mu.Lock()
	s.calls = append(s.calls, source+"\x00"+input)
	s.mu.Unlock()
	return nil
}

func (s *recSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func hmacSig(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func baseSource() *Source {
	return &Source{
		Name: "hook-1", Enabled: true,
		Auth: AuthConfig{Mode: AuthBearer, Secret: "sek"},
	}
}

func bearerReq(body string) Request {
	return Request{Header: http.Header{"Authorization": {"Bearer sek"}}, Body: []byte(body)}
}

func TestIngestAccepted(t *testing.T) {
	t.Parallel()
	clock := newTestClock()
	events := &MemoryEventStore{}
	sink := &recSink{}
	src := baseSource()
	src.Template = "alert={{alert.name}} host={{host}}"
	s := New(Config{
		Sources: NewMemorySourceStore(src), Events: events, Sink: sink, Clock: clock,
	})
	body := `{"alert":{"name":"cpu-high"},"host":"h1"}`
	res, err := s.Ingest(t.Context(), "hook-1", bearerReq(body))
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if !res.Accepted || res.Input != "alert=cpu-high host=h1" {
		t.Fatalf("res = %+v", res)
	}
	if sink.count() != 1 || sink.calls[0] != "hook-1\x00alert=cpu-high host=h1" {
		t.Fatalf("sink calls = %+v", sink.calls)
	}
	evs := events.Events()
	if len(evs) != 1 || evs[0].Status != EventAccepted || evs[0].Reason != "" ||
		evs[0].Source != "hook-1" || evs[0].Payload != body || !evs[0].CreatedAt.Equal(clock.Now()) {
		t.Fatalf("events = %+v", evs)
	}
}

func TestIngestUnknownAndDisabled(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		sources    SourceStore
		wantReason string
		wantStatus int
	}{
		{"unknown", NewMemorySourceStore(), ReasonUnknownSource, http.StatusNotFound},
		{"disabled", NewMemorySourceStore(&Source{Name: "hook-1", Enabled: false, Auth: AuthConfig{Mode: AuthBearer, Secret: "s"}}), ReasonDisabled, http.StatusForbidden},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			events := &MemoryEventStore{}
			s := New(Config{Sources: tt.sources, Events: events, Sink: &recSink{}})
			_, err := s.Ingest(t.Context(), "hook-1", bearerReq(`{"a":1}`))
			if err == nil {
				t.Fatal("应拒绝")
			}
			reason, ok := RejectionReason(err)
			if !ok || reason != tt.wantReason || RejectionStatus(err) != tt.wantStatus {
				t.Fatalf("err = %v (reason=%q status=%d)", err, reason, RejectionStatus(err))
			}
			evs := events.Events()
			if len(evs) != 1 || evs[0].Reason != tt.wantReason || evs[0].Status != EventRejected {
				t.Fatalf("events = %+v", evs)
			}
		})
	}
}

func TestIngestAuth(t *testing.T) {
	t.Parallel()
	body := `{"a":1}`
	tests := []struct {
		name       string
		src        *Source
		header     http.Header
		wantReason string
		wantStatus int
	}{
		{"bearer authorization", baseSource(), http.Header{"Authorization": {"Bearer sek"}}, "", 0},
		{"bearer lowercase scheme", baseSource(), http.Header{"Authorization": {"bearer sek"}}, "", 0},
		{"bearer token header", baseSource(), http.Header{"X-Webhook-Token": {"sek"}}, "", 0},
		{"bearer custom token header", &Source{Name: "hook-1", Enabled: true, Auth: AuthConfig{Mode: AuthBearer, Secret: "sek", TokenHeader: "X-Tok"}}, http.Header{"X-Tok": {"sek"}}, "", 0},
		{"bearer wrong", baseSource(), http.Header{"Authorization": {"Bearer nope"}}, ReasonBadToken, http.StatusUnauthorized},
		{"bearer missing", baseSource(), nil, ReasonBadToken, http.StatusUnauthorized},
		{"hmac ok", &Source{Name: "hook-1", Enabled: true, Auth: AuthConfig{Mode: AuthHMAC, Secret: "sek"}}, http.Header{"X-Webhook-Signature": {hmacSig("sek", []byte(body))}}, "", 0},
		{"hmac custom header", &Source{Name: "hook-1", Enabled: true, Auth: AuthConfig{Mode: AuthHMAC, Secret: "sek", SignatureHeader: "X-Sig"}}, http.Header{"X-Sig": {hmacSig("sek", []byte(body))}}, "", 0},
		{"hmac wrong", &Source{Name: "hook-1", Enabled: true, Auth: AuthConfig{Mode: AuthHMAC, Secret: "sek"}}, http.Header{"X-Webhook-Signature": {hmacSig("other", []byte(body))}}, ReasonBadSignature, http.StatusUnauthorized},
		{"hmac missing prefix", &Source{Name: "hook-1", Enabled: true, Auth: AuthConfig{Mode: AuthHMAC, Secret: "sek"}}, http.Header{"X-Webhook-Signature": {"deadbeef"}}, ReasonBadSignature, http.StatusUnauthorized},
		{"invalid mode", &Source{Name: "hook-1", Enabled: true, Auth: AuthConfig{Mode: "none", Secret: "sek"}}, nil, ReasonBadConfig, http.StatusInternalServerError},
		{"empty secret", &Source{Name: "hook-1", Enabled: true, Auth: AuthConfig{Mode: AuthBearer}}, nil, ReasonBadToken, http.StatusUnauthorized},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			events := &MemoryEventStore{}
			s := New(Config{Sources: NewMemorySourceStore(tt.src), Events: events, Sink: &recSink{}})
			_, err := s.Ingest(t.Context(), "hook-1", Request{Header: tt.header, Body: []byte(body)})
			if tt.wantReason == "" {
				if err != nil {
					t.Fatalf("Ingest: %v", err)
				}
				return
			}
			reason, ok := RejectionReason(err)
			if !ok || reason != tt.wantReason || RejectionStatus(err) != tt.wantStatus {
				t.Fatalf("err = %v, want reason=%q status=%d", err, tt.wantReason, tt.wantStatus)
			}
			evs := events.Events()
			if len(evs) != 1 || evs[0].Reason != tt.wantReason {
				t.Fatalf("events = %+v", evs)
			}
		})
	}
}

func TestIngestRateLimit(t *testing.T) {
	t.Parallel()
	clock := newTestClock()
	src := baseSource()
	src.RatePerMin = 2
	events := &MemoryEventStore{}
	s := New(Config{Sources: NewMemorySourceStore(src), Events: events, Sink: &recSink{}, Clock: clock})

	for i := 0; i < 2; i++ {
		if _, err := s.Ingest(t.Context(), "hook-1", bearerReq(`{"a":1}`)); err != nil {
			t.Fatalf("第 %d 次: %v", i+1, err)
		}
	}
	_, err := s.Ingest(t.Context(), "hook-1", bearerReq(`{"a":1}`))
	if reason, _ := RejectionReason(err); reason != ReasonRateLimited || RejectionStatus(err) != http.StatusTooManyRequests {
		t.Fatalf("第三次 err = %v", err)
	}
	// 恰好一个窗口后旧命中过期。
	clock.Advance(time.Minute)
	if _, err := s.Ingest(t.Context(), "hook-1", bearerReq(`{"a":1}`)); err != nil {
		t.Fatalf("窗口滚动后应放行: %v", err)
	}
	// ResetRateLimit 立即解限。
	_, _ = s.Ingest(t.Context(), "hook-1", bearerReq(`{"a":1}`))
	if _, err := s.Ingest(t.Context(), "hook-1", bearerReq(`{"a":1}`)); err == nil {
		t.Fatal("未重置前应继续限频")
	}
	s.ResetRateLimit("hook-1")
	if _, err := s.Ingest(t.Context(), "hook-1", bearerReq(`{"a":1}`)); err != nil {
		t.Fatalf("重置后应放行: %v", err)
	}
}

func TestIngestRateZeroUnlimited(t *testing.T) {
	t.Parallel()
	src := baseSource()
	s := New(Config{Sources: NewMemorySourceStore(src), Sink: &recSink{}})
	for i := 0; i < 50; i++ {
		if _, err := s.Ingest(t.Context(), "hook-1", bearerReq(`{"a":1}`)); err != nil {
			t.Fatalf("第 %d 次: %v", i+1, err)
		}
	}
}

func TestIngestBadPayload(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		maxBody    int
		body       string
		wantStatus int
	}{
		{"invalid json", 0, `{`, http.StatusBadRequest},
		{"null root", 0, `null`, http.StatusBadRequest},
		{"array root", 0, `[1,2]`, http.StatusBadRequest},
		{"too large", 8, `{"a":"0123456789"}`, http.StatusRequestEntityTooLarge},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			events := &MemoryEventStore{}
			s := New(Config{Sources: NewMemorySourceStore(baseSource()), Events: events, Sink: &recSink{}, MaxBodyBytes: tt.maxBody})
			_, err := s.Ingest(t.Context(), "hook-1", bearerReq(tt.body))
			if reason, _ := RejectionReason(err); reason != ReasonBadPayload || RejectionStatus(err) != tt.wantStatus {
				t.Fatalf("err = %v (status=%d)", err, RejectionStatus(err))
			}
			if len(events.Events()) != 1 {
				t.Fatalf("events = %+v", events.Events())
			}
		})
	}
}

func TestIngestFiltered(t *testing.T) {
	t.Parallel()
	src := baseSource()
	src.Filters = []Filter{{Path: "alert.name", Op: "eq", Value: "mem-high"}}
	sink := &recSink{}
	events := &MemoryEventStore{}
	s := New(Config{Sources: NewMemorySourceStore(src), Events: events, Sink: sink})
	res, err := s.Ingest(t.Context(), "hook-1", bearerReq(`{"alert":{"name":"cpu-high"}}`))
	if err != nil {
		t.Fatalf("过滤未命中应正常返回: %v", err)
	}
	if res.Accepted || !strings.Contains(res.Reason, "eq") {
		t.Fatalf("res = %+v", res)
	}
	if sink.count() != 0 {
		t.Fatalf("sink 不应被调用: %+v", sink.calls)
	}
	evs := events.Events()
	if len(evs) != 1 || evs[0].Status != EventRejected || evs[0].Reason != ReasonFiltered {
		t.Fatalf("events = %+v", evs)
	}
}

func TestIngestSinkAndStoreErrors(t *testing.T) {
	t.Parallel()
	t.Run("sink error", func(t *testing.T) {
		t.Parallel()
		sentinel := errors.New("session down")
		events := &MemoryEventStore{}
		s := New(Config{Sources: NewMemorySourceStore(baseSource()), Events: events, Sink: &recSink{err: sentinel}})
		_, err := s.Ingest(t.Context(), "hook-1", bearerReq(`{"a":1}`))
		if reason, _ := RejectionReason(err); reason != ReasonSinkError || RejectionStatus(err) != http.StatusInternalServerError {
			t.Fatalf("err = %v", err)
		}
		if !errors.Is(err, sentinel) {
			t.Fatalf("Cause 未保留: %v", err)
		}
		evs := events.Events()
		if len(evs) != 1 || evs[0].Reason != ReasonSinkError || evs[0].Input == "" {
			t.Fatalf("events = %+v", evs)
		}
	})
	t.Run("source store error", func(t *testing.T) {
		t.Parallel()
		s := New(Config{Sources: errStore{}, Sink: &recSink{}})
		_, err := s.Ingest(t.Context(), "hook-1", bearerReq(`{"a":1}`))
		if err == nil || ReasonOf(err) != "" {
			t.Fatalf("存储错误应原样上抛: %v", err)
		}
	})
	t.Run("nil sink", func(t *testing.T) {
		t.Parallel()
		s := New(Config{Sources: NewMemorySourceStore(baseSource())})
		_, err := s.Ingest(t.Context(), "hook-1", bearerReq(`{"a":1}`))
		if reason, _ := RejectionReason(err); reason != ReasonSinkError {
			t.Fatalf("err = %v", err)
		}
	})
}

type errStore struct{}

func (errStore) Get(context.Context, string) (*Source, error) {
	return nil, errors.New("db down")
}

func TestSnapshotHookAndCap(t *testing.T) {
	t.Parallel()
	t.Run("custom", func(t *testing.T) {
		t.Parallel()
		events := &MemoryEventStore{}
		s := New(Config{
			Sources: NewMemorySourceStore(baseSource()), Events: events, Sink: &recSink{},
			Snapshot: func([]byte) string { return "[redacted]" },
		})
		if _, err := s.Ingest(t.Context(), "hook-1", bearerReq(`{"secret":"x"}`)); err != nil {
			t.Fatal(err)
		}
		if got := events.Events()[0].Payload; got != "[redacted]" {
			t.Fatalf("payload = %q", got)
		}
	})
	t.Run("default cap", func(t *testing.T) {
		t.Parallel()
		events := &MemoryEventStore{}
		s := New(Config{
			Sources: NewMemorySourceStore(baseSource()), Events: events, Sink: &recSink{},
			PayloadCap: 5,
		})
		if _, err := s.Ingest(t.Context(), "hook-1", bearerReq(`{"a":12345}`)); err != nil {
			t.Fatal(err)
		}
		if got := events.Events()[0].Payload; got != `{"a":` {
			t.Fatalf("payload = %q", got)
		}
	})
}

func TestResetSecret(t *testing.T) {
	t.Parallel()
	store := NewMemorySourceStore(baseSource())
	s := New(Config{Sources: store, Sink: &recSink{}})
	newSecret, err := s.ResetSecret(t.Context(), "hook-1")
	if err != nil {
		t.Fatalf("ResetSecret: %v", err)
	}
	if newSecret == "" || newSecret == "sek" {
		t.Fatalf("新密钥 = %q", newSecret)
	}
	if _, err := s.Ingest(t.Context(), "hook-1", bearerReq(`{"a":1}`)); reasonOf(err) != ReasonBadToken {
		t.Fatalf("旧密钥应失效: %v", err)
	}
	if _, err := s.Ingest(t.Context(), "hook-1", Request{Header: http.Header{"Authorization": {"Bearer " + newSecret}}, Body: []byte(`{"a":1}`)}); err != nil {
		t.Fatalf("新密钥应可用: %v", err)
	}

	getOnly := struct{ SourceStore }{store}
	s2 := New(Config{Sources: getOnly, Sink: &recSink{}})
	if _, err := s2.ResetSecret(t.Context(), "hook-1"); err == nil {
		t.Fatal("不可变存储应拒绝轮换")
	}
	if _, err := s.ResetSecret(t.Context(), "missing"); err == nil {
		t.Fatal("未知源应报错")
	}
}

func reasonOf(err error) string {
	reason, _ := RejectionReason(err)
	return reason
}

func TestPruneEvents(t *testing.T) {
	t.Parallel()
	clock := newTestClock()
	events := &MemoryEventStore{}
	s := New(Config{Sources: NewMemorySourceStore(baseSource()), Events: events, Sink: &recSink{}, Clock: clock})
	if _, err := s.Ingest(t.Context(), "hook-1", bearerReq(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	if n, err := s.PruneEvents(t.Context()); err != nil || n != 0 {
		t.Fatalf("窗口内 prune = %d, %v", n, err)
	}
	clock.Advance(DefaultRetention + time.Second)
	n, err := s.PruneEvents(t.Context())
	if err != nil || n != 1 || len(events.Events()) != 0 {
		t.Fatalf("窗口外 prune = %d, %v, events=%+v", n, err, events.Events())
	}
	// Events 未装配时返回 0,nil。
	s2 := New(Config{Sources: NewMemorySourceStore(baseSource()), Sink: &recSink{}})
	if n, err := s2.PruneEvents(t.Context()); err != nil || n != 0 {
		t.Fatalf("无留痕面 prune = %d, %v", n, err)
	}
}

func TestValidateSource(t *testing.T) {
	t.Parallel()
	valid := baseSource()
	if err := ValidateSource(valid); err != nil {
		t.Fatalf("valid source: %v", err)
	}
	tests := []struct {
		name    string
		mutate  func(*Source)
		wantSub string
	}{
		{"nil", nil, "为空"},
		{"bad name", func(s *Source) { s.Name = "A" }, "源名非法"},
		{"bad mode", func(s *Source) { s.Auth.Mode = "none" }, "鉴权模式非法"},
		{"empty secret", func(s *Source) { s.Auth.Secret = "" }, "密钥不能为空"},
		{"rate high", func(s *Source) { s.RatePerMin = 10001 }, "rate_per_min 越界"},
		{"rate negative", func(s *Source) { s.RatePerMin = -1 }, "rate_per_min 越界"},
		{"filter path", func(s *Source) { s.Filters = []Filter{{Path: "", Op: "eq"}} }, "path 必填"},
		{"filter op", func(s *Source) { s.Filters = []Filter{{Path: "a", Op: "gt"}} }, "op 非法"},
		{"filter regex", func(s *Source) { s.Filters = []Filter{{Path: "a", Op: "regex", Value: "["}} }, "regex 编译失败"},
		{"template too long", func(s *Source) { s.Template = strings.Repeat("x", DefaultMaxInputBytes+1) }, "template 过长"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.mutate == nil {
				if err := ValidateSource(nil); err == nil || !strings.Contains(err.Error(), tt.wantSub) {
					t.Fatalf("err = %v", err)
				}
				return
			}
			cp := *valid
			cp.Auth = valid.Auth
			cp.Filters = append([]Filter(nil), valid.Filters...)
			tt.mutate(&cp)
			err := ValidateSource(&cp)
			if err == nil || !strings.Contains(err.Error(), tt.wantSub) {
				t.Fatalf("err = %v, want contains %q", err, tt.wantSub)
			}
		})
	}
}

func TestHTTPStatusAndReasonOf(t *testing.T) {
	t.Parallel()
	if got := HTTPStatus(&Result{Accepted: true}, nil); got != http.StatusOK {
		t.Fatalf("HTTPStatus = %d", got)
	}
	if got := HTTPStatus(nil, reject(ReasonBadToken, http.StatusUnauthorized, "x")); got != http.StatusUnauthorized {
		t.Fatalf("HTTPStatus = %d", got)
	}
	if got := HTTPStatus(nil, errors.New("raw")); got != http.StatusInternalServerError {
		t.Fatalf("HTTPStatus = %d", got)
	}
	if got := ReasonOf(reject(ReasonRateLimited, 429, "x")); got != ReasonRateLimited {
		t.Fatalf("ReasonOf = %q", got)
	}
}

func TestVerifyHMACAndBearer(t *testing.T) {
	t.Parallel()
	body := []byte(`{"x":1}`)
	sig := hmacSig("s3", body)
	if !VerifyHMAC("s3", sig, body) {
		t.Fatal("正确签名应通过")
	}
	if VerifyHMAC("", sig, body) || VerifyHMAC("s3", "", body) || VerifyHMAC("s3", "sha256=zz", body) {
		t.Fatal("非法签名应拒绝")
	}
	if !VerifyBearer("tok", "Bearer tok", "") || !VerifyBearer("tok", "bearer tok", "") || !VerifyBearer("tok", "", "tok") {
		t.Fatal("合法 token 应通过")
	}
	if VerifyBearer("", "Bearer ", "") || VerifyBearer("tok", "Bearer bad", "bad") {
		t.Fatal("非法 token 应拒绝")
	}
}
