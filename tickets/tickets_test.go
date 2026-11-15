package tickets

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// doerFunc 把函数适配成 Doer。
type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

// staticCreds 固定凭证提供者。
func staticCreds(c Credentials) CredentialProvider {
	return func(context.Context, string) (Credentials, error) { return c, nil }
}

// failIfCalledDoer 断言「参数校验失败时不发网络请求」。
func failIfCalledDoer(t *testing.T) (Doer, *int) {
	t.Helper()
	calls := 0
	return doerFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("不应发起请求")
	}), &calls
}

// TestNormalizeBaseURL 基准地址归一：Jira context path/API 后缀、PagerDuty
// 端点后缀、userinfo/query/fragment/非 http(s) 拒绝。
func TestNormalizeBaseURL(t *testing.T) {
	cases := []struct {
		name    string
		adapter Adapter
		raw     string
		want    string
		wantErr error
	}{
		{"jira 根", AdapterJira, "https://jira.example.com", "https://jira.example.com", nil},
		{"jira 尾斜杠", AdapterJira, "https://jira.example.com/", "https://jira.example.com", nil},
		{"jira context path", AdapterJira, "https://jira.example.com/jira/", "https://jira.example.com/jira", nil},
		{"jira api v2 后缀", AdapterJira, "https://jira.example.com/jira/rest/api/2", "https://jira.example.com/jira", nil},
		{"jira api v3 后缀归一 v2", AdapterJira, "https://jira.example.com/rest/api/3", "https://jira.example.com", nil},
		{"jira 非法 API 子路径", AdapterJira, "https://jira.example.com/rest/api/2/issue", "", ErrBadTarget},
		{"jira 空地址", AdapterJira, "  ", "", ErrBadTarget},
		{"jira 非 http", AdapterJira, "ftp://jira.example.com", "", ErrBadTarget},
		{"jira userinfo", AdapterJira, "https://bot:tok@jira.example.com", "", ErrBadTarget},
		{"jira query", AdapterJira, "https://jira.example.com?x=1", "", ErrBadTarget},
		{"jira fragment", AdapterJira, "https://jira.example.com/#f", "", ErrBadTarget},
		{"jira 缺 host", AdapterJira, "https:///jira", "", ErrBadTarget},

		{"pd 默认端点", AdapterPagerDuty, "", "https://events.pagerduty.com", nil},
		{"pd enqueue 后缀", AdapterPagerDuty, "https://events.pagerduty.com/v2/enqueue", "https://events.pagerduty.com", nil},
		{"pd v2 后缀", AdapterPagerDuty, "https://events.pagerduty.com/v2", "https://events.pagerduty.com", nil},
		{"pd 非法子路径", AdapterPagerDuty, "https://events.pagerduty.com/v2/enqueue/x", "", ErrBadTarget},
		{"pd query", AdapterPagerDuty, "https://events.pagerduty.com/?x=1", "", ErrBadTarget},
		{"未知平台", Adapter("zk"), "https://x.example.com", "", ErrBadAdapter},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := NormalizeBaseURL(c.adapter, c.raw)
			if c.wantErr != nil {
				if !errors.Is(err, c.wantErr) {
					t.Fatalf("错误 = %v，应 %v", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("不应出错: %v", err)
			}
			if got != c.want {
				t.Fatalf("归一结果 = %q，应 %q", got, c.want)
			}
		})
	}
}

// TestNewClientValidation 构造期 fail-closed：缺凭证提供者/Doer、坏目标。
func TestNewClientValidation(t *testing.T) {
	creds := staticCreds(Credentials{User: "u", Token: "t"})
	doer := doerFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("no") })

	cases := []struct {
		name    string
		target  Target
		creds   CredentialProvider
		doer    Doer
		wantErr error
	}{
		{"缺凭证提供者", Target{Adapter: AdapterJira, BaseURL: "https://j.example.com"}, nil, doer, ErrNoCredentialProvider},
		{"缺 Doer", Target{Adapter: AdapterJira, BaseURL: "https://j.example.com"}, creds, nil, ErrNoDoer},
		{"未知平台", Target{Adapter: "zk", BaseURL: "https://j.example.com"}, creds, doer, ErrBadAdapter},
		{"坏 URL", Target{Adapter: AdapterJira, BaseURL: "https://user@j.example.com"}, creds, doer, ErrBadTarget},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewClient(c.target, c.creds, c.doer)
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("错误 = %v，应 %v", err, c.wantErr)
			}
		})
	}

	jira, err := NewClient(Target{Adapter: AdapterJira, BaseURL: "https://j.example.com/rest/api/2"}, creds, doer)
	if err != nil {
		t.Fatalf("合法 Jira 目标应可构造: %v", err)
	}
	if jira.Adapter() != AdapterJira {
		t.Fatalf("Adapter() = %q", jira.Adapter())
	}
	pd, err := NewClient(Target{Adapter: AdapterPagerDuty, BaseURL: "https://pd.example.com/v2/enqueue"}, creds, doer)
	if err != nil {
		t.Fatalf("合法 PD 目标应可构造: %v", err)
	}
	if pd.Adapter() != AdapterPagerDuty {
		t.Fatalf("Adapter() = %q", pd.Adapter())
	}
}

// TestHTTPErrorShape 非 2xx 错误带状态/path/截断片段，errors.Is 可判。
func TestHTTPErrorShape(t *testing.T) {
	e := &HTTPError{StatusCode: 500, Method: http.MethodPost, Path: "/rest/api/2/issue/X-1/comment", Body: "boom"}
	if !errors.Is(e, ErrHTTPStatus) {
		t.Fatal("HTTPError 应 Unwrap 到 ErrHTTPStatus")
	}
	if !strings.Contains(e.Error(), "500") || !strings.Contains(e.Error(), "/issue/X-1/comment") {
		t.Fatalf("错误文案缺状态/path: %s", e.Error())
	}
}

// TestRoundTripResponseLimits 非 2xx 片段截断、超大响应拒绝、空 2xx 响应
// 在需要解码时报错。
func TestRoundTripResponseLimits(t *testing.T) {
	large := strings.Repeat("x", errBodyExcerpt+100)
	client, err := NewClient(Target{Adapter: AdapterJira, BaseURL: "https://j.example.com"},
		staticCreds(Credentials{User: "u", Token: "t"}),
		doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: 500,
				Body:       io.NopCloser(strings.NewReader(large)),
				Header:     make(http.Header),
			}, nil
		}))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.PostComment(context.Background(), "OPS-1", "body")
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("应 *HTTPError，got %v", err)
	}
	if len(httpErr.Body) != errBodyExcerpt {
		t.Fatalf("错误片段长度 = %d，应 %d", len(httpErr.Body), errBodyExcerpt)
	}

	tooLarge := strings.Repeat("x", maxResponseBytes+1)
	client, err = NewClient(Target{Adapter: AdapterJira, BaseURL: "https://j.example.com"},
		staticCreds(Credentials{User: "u", Token: "t"}),
		doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(tooLarge)),
				Header:     make(http.Header),
			}, nil
		}))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.PostComment(context.Background(), "OPS-1", "body"); !errors.Is(err, ErrBadResponse) {
		t.Fatalf("超大响应应 ErrBadResponse，got %v", err)
	}

	client, err = NewClient(Target{Adapter: AdapterJira, BaseURL: "https://j.example.com"},
		staticCreds(Credentials{User: "u", Token: "t"}),
		doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
		}))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.PostComment(context.Background(), "OPS-1", "body"); !errors.Is(err, ErrBadResponse) {
		t.Fatalf("空 2xx 响应应 ErrBadResponse，got %v", err)
	}
}
