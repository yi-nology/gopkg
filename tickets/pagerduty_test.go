package tickets

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// pdServer 起 httptest 服务并构造 PagerDuty Client。
func pdServer(t *testing.T, handler http.HandlerFunc, source string) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	client, err := NewClient(
		Target{
			Adapter:       AdapterPagerDuty,
			BaseURL:       srv.URL + "/v2/enqueue",
			CredentialRef: "vault://ops/pd",
			Source:        source,
		},
		staticCreds(Credentials{RoutingKey: "rk-1"}),
		srv.Client(),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

func testPDHandler(t *testing.T, check func(map[string]any)) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v2/enqueue" {
			t.Errorf("请求 = %s %s", r.Method, r.URL.Path)
		}
		body := decodeBody(t, r)
		check(body)
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"status":"success","message":"Event processed","dedup_key":"d-1"}`)
	}
}

// TestPagerDutyTrigger trigger 成功面：routing key、payload、custom_details
// 位置、默认 severity/source 兜底、links/images。
func TestPagerDutyTrigger(t *testing.T) {
	client := pdServer(t, testPDHandler(t, func(body map[string]any) {
		if body["routing_key"] != "rk-1" || body["event_action"] != "trigger" || body["dedup_key"] != "d-1" {
			t.Errorf("事件信封失真: %+v", body)
		}
		payload, ok := body["payload"].(map[string]any)
		if !ok {
			t.Fatalf("payload 形态失真: %+v", body)
		}
		if payload["summary"] != "磁盘 inode 耗尽" || payload["source"] != "diag-svc" {
			t.Errorf("payload = %+v", payload)
		}
		if payload["severity"] != "error" {
			t.Errorf("severity 应默认 error，got %v", payload["severity"])
		}
		if payload["timestamp"] != "2026-11-15T10:00:00Z" || payload["component"] != "storage" {
			t.Errorf("payload 可选字段失真: %+v", payload)
		}
		details, ok := payload["custom_details"].(map[string]any)
		if !ok || details["diagnosis"] != "inode 100%" {
			t.Errorf("custom_details 应在 payload 内: %+v", body)
		}
		links, ok := body["links"].([]any)
		if !ok || len(links) != 1 {
			t.Errorf("links = %+v", body["links"])
		}
		images, ok := body["images"].([]any)
		if !ok || len(images) != 1 {
			t.Errorf("images = %+v", body["images"])
		}
	}), "diag-svc")

	got, err := client.SendPagerDutyEvent(context.Background(), PagerDutyEvent{
		Action:   PagerDutyTrigger,
		DedupKey: "d-1",
		Payload: PagerDutyPayload{
			Summary:   "磁盘 inode 耗尽",
			Timestamp: "2026-11-15T10:00:00Z",
			Component: "storage",
		},
		CustomDetails: map[string]any{"diagnosis": "inode 100%"},
		Links:         []PagerDutyLink{{Href: "https://ops.example.com/case/1", Text: "case"}},
		Images:        []PagerDutyImage{{Src: "https://ops.example.com/chart.png", Alt: "chart"}},
	})
	if err != nil {
		t.Fatalf("SendPagerDutyEvent: %v", err)
	}
	if got.Status != "success" || got.DedupKey != "d-1" {
		t.Fatalf("回执失真: %+v", got)
	}

	// 显式 source/severity 不被覆盖。
	client = pdServer(t, testPDHandler(t, func(body map[string]any) {
		payload := body["payload"].(map[string]any)
		if payload["source"] != "explicit" || payload["severity"] != "critical" {
			t.Errorf("显式字段被覆盖: %+v", payload)
		}
	}), "fallback")
	if _, err := client.SendPagerDutyEvent(context.Background(), PagerDutyEvent{
		Action:  PagerDutyTrigger,
		Payload: PagerDutyPayload{Summary: "s", Source: "explicit", Severity: PagerDutySeverityCritical},
	}); err != nil {
		t.Fatalf("SendPagerDutyEvent: %v", err)
	}
}

// TestPagerDutyAckResolve acknowledge/resolve 只带 dedup_key，不带 payload。
func TestPagerDutyAckResolve(t *testing.T) {
	for _, action := range []PagerDutyAction{PagerDutyAcknowledge, PagerDutyResolve} {
		t.Run(string(action), func(t *testing.T) {
			client := pdServer(t, testPDHandler(t, func(body map[string]any) {
				if body["event_action"] != string(action) || body["dedup_key"] != "d-9" {
					t.Errorf("信封失真: %+v", body)
				}
				if _, hasPayload := body["payload"]; hasPayload {
					t.Errorf("%s 不应带 payload: %+v", action, body)
				}
				if body["routing_key"] != "rk-1" {
					t.Errorf("routing key 缺失: %+v", body)
				}
			}), "diag-svc")
			if _, err := client.SendPagerDutyEvent(context.Background(), PagerDutyEvent{
				Action: action, DedupKey: "d-9",
			}); err != nil {
				t.Fatalf("SendPagerDutyEvent: %v", err)
			}
		})
	}
}

// TestPagerDutyValidationFailClosed 事件校验失败面全部不发网络请求。
func TestPagerDutyValidationFailClosed(t *testing.T) {
	doer, calls := failIfCalledDoer(t)
	client, err := NewClient(Target{Adapter: AdapterPagerDuty, BaseURL: "https://pd.example.com", Source: "svc"},
		staticCreds(Credentials{RoutingKey: "rk"}), doer)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	cases := []struct {
		name string
		ev   PagerDutyEvent
	}{
		{"未知 action", PagerDutyEvent{Action: "page"}},
		{"trigger 缺 summary", PagerDutyEvent{Action: PagerDutyTrigger, Payload: PagerDutyPayload{Source: "s"}}},
		{"trigger summary 超长", PagerDutyEvent{Action: PagerDutyTrigger, Payload: PagerDutyPayload{
			Summary: strings.Repeat("诊", MaxPagerDutySummaryLen+1), Source: "s"}}},
		{"trigger 未知 severity", PagerDutyEvent{Action: PagerDutyTrigger, Payload: PagerDutyPayload{
			Summary: "s", Source: "s", Severity: "panic"}}},
		{"trigger 坏 timestamp", PagerDutyEvent{Action: PagerDutyTrigger, Payload: PagerDutyPayload{
			Summary: "s", Source: "s", Timestamp: "2026-11-15 10:00"}}},
		{"ack 缺 dedup", PagerDutyEvent{Action: PagerDutyAcknowledge}},
		{"ack 带 payload", PagerDutyEvent{Action: PagerDutyAcknowledge, DedupKey: "d", Payload: PagerDutyPayload{Summary: "s"}}},
		{"ack 带 custom_details", PagerDutyEvent{Action: PagerDutyAcknowledge, DedupKey: "d", CustomDetails: map[string]any{"x": 1}}},
		{"dedup 超长", PagerDutyEvent{Action: PagerDutyAcknowledge, DedupKey: strings.Repeat("d", MaxPagerDutyDedupKeyLen+1)}},
		{"link 缺 href", PagerDutyEvent{Action: PagerDutyTrigger, Payload: PagerDutyPayload{Summary: "s", Source: "s"},
			Links: []PagerDutyLink{{Text: "x"}}}},
		{"image 缺 src", PagerDutyEvent{Action: PagerDutyTrigger, Payload: PagerDutyPayload{Summary: "s", Source: "s"},
			Images: []PagerDutyImage{{Alt: "x"}}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := client.SendPagerDutyEvent(context.Background(), c.ev); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("应 ErrInvalidArgument，got %v", err)
			}
		})
	}
	if *calls != 0 {
		t.Fatalf("校验失败不应发请求，got %d 次", *calls)
	}

	// source 无兜底且 payload 未给：拒绝。
	noSource, err := NewClient(Target{Adapter: AdapterPagerDuty, BaseURL: "https://pd.example.com"},
		staticCreds(Credentials{RoutingKey: "rk"}), doer)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := noSource.SendPagerDutyEvent(context.Background(), PagerDutyEvent{
		Action: PagerDutyTrigger, Payload: PagerDutyPayload{Summary: "s"},
	}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("缺 source 应 ErrInvalidArgument，got %v", err)
	}
	if *calls != 0 {
		t.Fatalf("校验失败不应发请求，got %d 次", *calls)
	}
}

// TestPagerDutyCredentialAndHTTPFailures 凭证缺字段/解析失败、非 2xx、
// 2xx 但 status 非 success、缺 dedup_key、传输错误。
func TestPagerDutyCredentialAndHTTPFailures(t *testing.T) {
	doer, calls := failIfCalledDoer(t)
	missing, err := NewClient(Target{Adapter: AdapterPagerDuty, BaseURL: "https://pd.example.com", Source: "svc"},
		staticCreds(Credentials{}), doer)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ev := PagerDutyEvent{Action: PagerDutyTrigger, Payload: PagerDutyPayload{Summary: "s"}}
	if _, err := missing.SendPagerDutyEvent(context.Background(), ev); !errors.Is(err, ErrMissingCredentials) {
		t.Fatalf("缺 routing key 应 ErrMissingCredentials，got %v", err)
	}
	credBoom := errors.New("vault sealed")
	credFail, err := NewClient(Target{Adapter: AdapterPagerDuty, BaseURL: "https://pd.example.com", Source: "svc"},
		func(context.Context, string) (Credentials, error) { return Credentials{}, credBoom }, doer)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := credFail.SendPagerDutyEvent(context.Background(), ev); !errors.Is(err, ErrCredential) {
		t.Fatalf("凭证解析失败应 ErrCredential，got %v", err)
	}
	if *calls != 0 {
		t.Fatalf("凭证错误不应发请求，got %d 次", *calls)
	}

	client400 := pdServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"status":"invalid event"}`)
	}, "svc")
	if _, err := client400.SendPagerDutyEvent(context.Background(), ev); !errors.Is(err, ErrHTTPStatus) {
		t.Fatalf("400 应 ErrHTTPStatus，got %v", err)
	}

	clientBadStatus := pdServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"status":"invalid event","message":"bad"}`)
	}, "svc")
	if _, err := clientBadStatus.SendPagerDutyEvent(context.Background(), ev); !errors.Is(err, ErrBadResponse) {
		t.Fatalf("status 非 success 应 ErrBadResponse，got %v", err)
	}

	clientNoDedup := pdServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"status":"success","message":"ok"}`)
	}, "svc")
	if _, err := clientNoDedup.SendPagerDutyEvent(context.Background(), ev); !errors.Is(err, ErrBadResponse) {
		t.Fatalf("缺 dedup_key 应 ErrBadResponse，got %v", err)
	}

	clientTransport, err := NewClient(Target{Adapter: AdapterPagerDuty, BaseURL: "https://pd.example.com", Source: "svc"},
		staticCreds(Credentials{RoutingKey: "rk"}),
		doerFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("dial tcp: refused") }))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := clientTransport.SendPagerDutyEvent(context.Background(), ev); !errors.Is(err, ErrTransport) {
		t.Fatalf("传输错误应 ErrTransport，got %v", err)
	}
}

// TestPagerDutyPostComment PostComment 对 PD 映射为 trigger 事件；长正文
// 拒绝（要求调用方显式用 CustomDetails）。
func TestPagerDutyPostComment(t *testing.T) {
	client := pdServer(t, testPDHandler(t, func(body map[string]any) {
		if body["event_action"] != "trigger" || body["dedup_key"] != "INC-7" {
			t.Errorf("信封失真: %+v", body)
		}
		payload := body["payload"].(map[string]any)
		if payload["summary"] != "诊断结论" || payload["source"] != "diag-svc" || payload["severity"] != "error" {
			t.Errorf("payload 失真: %+v", payload)
		}
	}), "diag-svc")

	got, err := client.PostComment(context.Background(), "INC-7", "诊断结论")
	if err != nil {
		t.Fatalf("PostComment: %v", err)
	}
	if got.ID != "d-1" {
		t.Fatalf("回执 id 应为 dedup_key: %+v", got)
	}

	doer, calls := failIfCalledDoer(t)
	long, err := NewClient(Target{Adapter: AdapterPagerDuty, BaseURL: "https://pd.example.com", Source: "svc"},
		staticCreds(Credentials{RoutingKey: "rk"}), doer)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := long.PostComment(context.Background(), "INC-7", strings.Repeat("x", MaxPagerDutySummaryLen+1)); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("超长正文应 ErrInvalidArgument，got %v", err)
	}
	if *calls != 0 {
		t.Fatalf("超长正文不应发请求: %d", *calls)
	}
}
