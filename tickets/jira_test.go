package tickets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// jiraServer 起 httptest 服务并构造指向它的 Jira Client（base 带 context
// path 与 /rest/api/2 后缀，验证归一）。
func jiraServer(t *testing.T, handler http.HandlerFunc, baseSuffix string) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	client, err := NewClient(
		Target{
			Adapter:       AdapterJira,
			BaseURL:       srv.URL + baseSuffix,
			CredentialRef: "vault://ops/jira",
		},
		staticCreds(Credentials{User: "bot", Token: "tok"}),
		srv.Client(),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

func decodeBody(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		// 服务器 handler 在独立 goroutine：只标记失败，不调用 FailNow。
		t.Errorf("请求体不是 JSON: %v", err)
		return map[string]any{}
	}
	return body
}

// TestJiraPostComment 评论回写：context path、Basic 认证、请求体、响应解析。
func TestJiraPostComment(t *testing.T) {
	var hits int
	client := jiraServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Method != http.MethodPost {
			t.Errorf("方法 = %s，应 POST", r.Method)
		}
		if want := "/jira/rest/api/2/issue/OPS-42/comment"; r.URL.Path != want {
			t.Errorf("path = %s，应 %s", r.URL.Path, want)
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "bot" || pass != "tok" {
			t.Errorf("Basic 认证失真: ok=%v user=%q pass=%q", ok, user, pass)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q", ct)
		}
		body := decodeBody(t, r)
		if body["body"] != "诊断结论：inode 耗尽" {
			t.Errorf("请求体 = %+v", body)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"id":"10001","self":"https://jira.example.com/rest/api/2/issue/1/comment/10001"}`)
	}, "/jira/rest/api/2")

	got, err := client.PostComment(context.Background(), "OPS-42", "诊断结论：inode 耗尽")
	if err != nil {
		t.Fatalf("PostComment: %v", err)
	}
	if got.ID != "10001" || !strings.HasSuffix(got.Self, "/comment/10001") {
		t.Fatalf("回执失真: %+v", got)
	}
	if hits != 1 {
		t.Fatalf("请求次数 = %d", hits)
	}
}

// TestJiraPostCommentFailures 评论失败面：参数校验不打网络、凭证错误、
// 非 2xx、坏响应、缺 id、传输错误。
func TestJiraPostCommentFailures(t *testing.T) {
	doer, calls := failIfCalledDoer(t)
	client, err := NewClient(Target{Adapter: AdapterJira, BaseURL: "https://j.example.com"},
		staticCreds(Credentials{User: "u", Token: "t"}), doer)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	for _, c := range []struct{ key, body string }{
		{"", "x"}, {"OPS-1", ""}, {"  ", "x"},
	} {
		if _, err := client.PostComment(context.Background(), c.key, c.body); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("(%q,%q) 应 ErrInvalidArgument，got %v", c.key, c.body, err)
		}
	}
	if *calls != 0 {
		t.Fatalf("参数校验失败时不应发请求，got %d 次", *calls)
	}

	credBoom := errors.New("vault sealed")
	clientNoCred, err := NewClient(Target{Adapter: AdapterJira, BaseURL: "https://j.example.com"},
		func(context.Context, string) (Credentials, error) { return Credentials{}, credBoom }, doer)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := clientNoCred.PostComment(context.Background(), "OPS-1", "x"); !errors.Is(err, ErrCredential) {
		t.Fatalf("凭证解析失败应 ErrCredential，got %v", err)
	}
	clientMissing, err := NewClient(Target{Adapter: AdapterJira, BaseURL: "https://j.example.com"},
		staticCreds(Credentials{User: "u"}), doer)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := clientMissing.PostComment(context.Background(), "OPS-1", "x"); !errors.Is(err, ErrMissingCredentials) {
		t.Fatalf("缺 token 应 ErrMissingCredentials，got %v", err)
	}
	if *calls != 0 {
		t.Fatalf("凭证错误时不应发请求，got %d 次", *calls)
	}

	client500 := jiraServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "boom")
	}, "")
	if _, err := client500.PostComment(context.Background(), "OPS-1", "x"); !errors.Is(err, ErrHTTPStatus) {
		t.Fatalf("500 应 ErrHTTPStatus，got %v", err)
	}
	clientBadJSON := jiraServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "not-json")
	}, "")
	if _, err := clientBadJSON.PostComment(context.Background(), "OPS-1", "x"); !errors.Is(err, ErrBadResponse) {
		t.Fatalf("坏 JSON 应 ErrBadResponse，got %v", err)
	}
	clientNoID := jiraServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"self":"x"}`)
	}, "")
	if _, err := clientNoID.PostComment(context.Background(), "OPS-1", "x"); !errors.Is(err, ErrBadResponse) {
		t.Fatalf("缺 id 应 ErrBadResponse，got %v", err)
	}
	clientTransport, err := NewClient(Target{Adapter: AdapterJira, BaseURL: "https://j.example.com"},
		staticCreds(Credentials{User: "u", Token: "t"}),
		doerFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("dial tcp: refused") }))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := clientTransport.PostComment(context.Background(), "OPS-1", "x"); !errors.Is(err, ErrTransport) {
		t.Fatalf("传输错误应 ErrTransport，got %v", err)
	}
}

// TestJiraCreateIssue 建单：字段组装、宿主 Fields 覆盖、响应解析与校验。
func TestJiraCreateIssue(t *testing.T) {
	client := jiraServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/rest/api/2/issue" {
			t.Errorf("请求 = %s %s", r.Method, r.URL.Path)
		}
		body := decodeBody(t, r)
		fields, ok := body["fields"].(map[string]any)
		if !ok {
			t.Fatalf("fields 形态失真: %+v", body)
		}
		if fields["summary"] != "宿主覆盖后的标题" {
			t.Errorf("summary = %v", fields["summary"])
		}
		project := fields["project"].(map[string]any)
		if project["key"] != "OPS" {
			t.Errorf("project = %+v", project)
		}
		issueType := fields["issuetype"].(map[string]any)
		if issueType["name"] != "Bug" {
			t.Errorf("issuetype = %+v", issueType)
		}
		if fields["description"] != "详情" {
			t.Errorf("description = %v", fields["description"])
		}
		labels, ok := fields["labels"].([]any)
		if !ok || len(labels) != 1 || labels[0] != "diag" {
			t.Errorf("labels = %+v", fields["labels"])
		}
		priority := fields["priority"].(map[string]any)
		if priority["name"] != "High" {
			t.Errorf("priority = %+v", priority)
		}
		if fields["customfield_10001"] != float64(42) {
			t.Errorf("自定义字段缺失: %+v", fields)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"id":"9","key":"OPS-9","self":"https://jira.example.com/rest/api/2/issue/9"}`)
	}, "")

	got, err := client.CreateJiraIssue(context.Background(), CreateIssueRequest{
		ProjectKey:  "OPS",
		IssueType:   "Bug",
		Summary:     "原始标题",
		Description: "详情",
		Labels:      []string{"diag"},
		Priority:    "High",
		Fields:      map[string]any{"customfield_10001": 42, "summary": "宿主覆盖后的标题"},
	})
	if err != nil {
		t.Fatalf("CreateJiraIssue: %v", err)
	}
	if got.Key != "OPS-9" || got.ID != "9" {
		t.Fatalf("回执失真: %+v", got)
	}

	// 参数校验不打网络。
	doer, calls := failIfCalledDoer(t)
	c, err := NewClient(Target{Adapter: AdapterJira, BaseURL: "https://j.example.com"},
		staticCreds(Credentials{User: "u", Token: "t"}), doer)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	bad := []CreateIssueRequest{
		{IssueType: "Bug", Summary: "s"},
		{ProjectKey: "OPS", Summary: "s"},
		{ProjectKey: "OPS", IssueType: "Bug"},
	}
	for _, in := range bad {
		if _, err := c.CreateJiraIssue(context.Background(), in); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("%+v 应 ErrInvalidArgument，got %v", in, err)
		}
	}
	if *calls != 0 {
		t.Fatalf("校验失败不应发请求: %d", *calls)
	}

	// 2xx 但缺 key。
	clientNoKey := jiraServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"id":"9"}`)
	}, "")
	if _, err := clientNoKey.CreateJiraIssue(context.Background(), CreateIssueRequest{
		ProjectKey: "OPS", IssueType: "Bug", Summary: "s",
	}); !errors.Is(err, ErrBadResponse) {
		t.Fatalf("缺 key 应 ErrBadResponse，got %v", err)
	}
}

// TestJiraTransition 流转：按 ID 直提、按名称精确匹配、零/多命中 fail-closed。
func TestJiraTransition(t *testing.T) {
	t.Run("按 ID", func(t *testing.T) {
		var posted bool
		client := jiraServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/rest/api/2/issue/OPS-1/transitions" {
				t.Errorf("请求 = %s %s", r.Method, r.URL.Path)
			}
			body := decodeBody(t, r)
			tr := body["transition"].(map[string]any)
			if tr["id"] != "31" {
				t.Errorf("transition = %+v", tr)
			}
			posted = true
			w.WriteHeader(http.StatusNoContent)
		}, "")
		if err := client.TransitionJiraIssue(context.Background(), "OPS-1", Transition{ID: "31"}); err != nil {
			t.Fatalf("TransitionJiraIssue: %v", err)
		}
		if !posted {
			t.Fatal("未提交流转")
		}
	})

	t.Run("按名称", func(t *testing.T) {
		var gotID string
		var gets, posts int
		client := jiraServer(t, func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				gets++
				_, _ = io.WriteString(w, `{"transitions":[{"id":"11","name":"In Progress"},{"id":"21","name":"Done"}]}`)
			case http.MethodPost:
				posts++
				body := decodeBody(t, r)
				gotID = body["transition"].(map[string]any)["id"].(string)
				w.WriteHeader(http.StatusNoContent)
			default:
				t.Errorf("未知方法 %s", r.Method)
			}
		}, "")
		if err := client.TransitionJiraIssue(context.Background(), "OPS-1", Transition{Name: "Done"}); err != nil {
			t.Fatalf("TransitionJiraIssue: %v", err)
		}
		if gets != 1 || posts != 1 || gotID != "21" {
			t.Fatalf("gets=%d posts=%d id=%q", gets, posts, gotID)
		}
	})

	t.Run("名称零命中", func(t *testing.T) {
		posts := 0
		client := jiraServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				posts++
			}
			_, _ = io.WriteString(w, `{"transitions":[{"id":"11","name":"In Progress"}]}`)
		}, "")
		if err := client.TransitionJiraIssue(context.Background(), "OPS-1", Transition{Name: "Done"}); !errors.Is(err, ErrTransitionNotFound) {
			t.Fatalf("应 ErrTransitionNotFound，got %v", err)
		}
		if posts != 0 {
			t.Fatal("零命中不应提交流转")
		}
	})

	t.Run("名称多重命中", func(t *testing.T) {
		client := jiraServer(t, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"transitions":[{"id":"11","name":"Done"},{"id":"12","name":"Done"}]}`)
		}, "")
		if err := client.TransitionJiraIssue(context.Background(), "OPS-1", Transition{Name: "Done"}); !errors.Is(err, ErrTransitionAmbiguous) {
			t.Fatalf("应 ErrTransitionAmbiguous，got %v", err)
		}
	})

	doer, calls := failIfCalledDoer(t)
	client, err := NewClient(Target{Adapter: AdapterJira, BaseURL: "https://j.example.com"},
		staticCreds(Credentials{User: "u", Token: "t"}), doer)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := client.TransitionJiraIssue(context.Background(), "", Transition{ID: "1"}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("空 issue key 应 ErrInvalidArgument，got %v", err)
	}
	if err := client.TransitionJiraIssue(context.Background(), "OPS-1", Transition{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("缺流转目标应 ErrInvalidArgument，got %v", err)
	}
	if err := client.TransitionJiraIssue(context.Background(), "OPS-1", Transition{ID: "1", Name: "Done"}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("ID/Name 同设应 ErrInvalidArgument，got %v", err)
	}
	if *calls != 0 {
		t.Fatalf("校验失败不应发请求: %d", *calls)
	}
}

// TestJiraSearch 单页搜索：URL 查询参数、JQL 透传、分页校验。
func TestJiraSearch(t *testing.T) {
	var rawQuery string
	client := jiraServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/rest/api/2/search" {
			t.Errorf("请求 = %s %s", r.Method, r.URL.Path)
		}
		rawQuery = r.URL.RawQuery
		_, _ = io.WriteString(w, `{"startAt":5,"maxResults":2,"total":9,"issues":[{"id":"1","key":"OPS-1","fields":{"summary":"s"}}]}`)
	}, "")
	page, err := client.SearchJiraIssues(context.Background(), `project = OPS AND status != Done ORDER BY created DESC`,
		SearchOptions{StartAt: 5, MaxResults: 2, Fields: []string{"summary", "status"}})
	if err != nil {
		t.Fatalf("SearchJiraIssues: %v", err)
	}
	q, err := url.QueryUnescape(rawQuery)
	if err != nil {
		t.Fatalf("query 解码失败: %v", err)
	}
	for _, want := range []string{
		"jql=project = OPS AND status != Done ORDER BY created DESC",
		"startAt=5", "maxResults=2", "fields=summary,status",
	} {
		if !strings.Contains(q, want) {
			t.Fatalf("query 缺 %q: %s", want, q)
		}
	}
	if page.Total != 9 || len(page.Issues) != 1 || page.Issues[0].Key != "OPS-1" {
		t.Fatalf("响应解析失真: %+v", page)
	}

	doer, calls := failIfCalledDoer(t)
	c, err := NewClient(Target{Adapter: AdapterJira, BaseURL: "https://j.example.com"},
		staticCreds(Credentials{User: "u", Token: "t"}), doer)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	bad := []struct {
		jql  string
		opts SearchOptions
		want error
	}{
		{"", SearchOptions{}, ErrInvalidArgument},
		{"project = OPS", SearchOptions{StartAt: -1}, ErrInvalidArgument},
		{"project = OPS", SearchOptions{MaxResults: -1}, ErrBadPageSize},
		{"project = OPS", SearchOptions{MaxResults: MaxJiraMaxResults + 1}, ErrBadPageSize},
		{"project = OPS", SearchOptions{Fields: []string{" "}}, ErrInvalidArgument},
	}
	for _, b := range bad {
		if _, err := c.SearchJiraIssues(context.Background(), b.jql, b.opts); !errors.Is(err, b.want) {
			t.Fatalf("%+v 应 %v，got %v", b, b.want, err)
		}
	}
	if *calls != 0 {
		t.Fatalf("校验失败不应发请求: %d", *calls)
	}

	clientNeg := jiraServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"startAt":0,"maxResults":50,"total":-1,"issues":[]}`)
	}, "")
	if _, err := clientNeg.SearchJiraIssues(context.Background(), "project = OPS", SearchOptions{}); !errors.Is(err, ErrBadResponse) {
		t.Fatalf("负分页字段应 ErrBadResponse，got %v", err)
	}
}

// TestJiraSearchAll 分页取单：多页收口、空页收口、startAt 不一致、
// 空页但 total 未到（停滞）、页大小边界。
func TestJiraSearchAll(t *testing.T) {
	t.Run("多页", func(t *testing.T) {
		var starts []string
		client := jiraServer(t, func(w http.ResponseWriter, r *http.Request) {
			start := r.URL.Query().Get("startAt")
			starts = append(starts, start)
			switch start {
			case "0":
				_, _ = io.WriteString(w, `{"startAt":0,"maxResults":2,"total":3,"issues":[{"key":"OPS-1"},{"key":"OPS-2"}]}`)
			case "2":
				_, _ = io.WriteString(w, `{"startAt":2,"maxResults":2,"total":3,"issues":[{"key":"OPS-3"}]}`)
			default:
				t.Errorf("意外 startAt=%s", start)
			}
		}, "")
		issues, err := client.SearchAllJiraIssues(context.Background(), "project = OPS", 2)
		if err != nil {
			t.Fatalf("SearchAllJiraIssues: %v", err)
		}
		if len(issues) != 3 || issues[2].Key != "OPS-3" {
			t.Fatalf("结果失真: %+v", issues)
		}
		if fmt.Sprint(starts) != "[0 2]" {
			t.Fatalf("分页序列 = %v", starts)
		}
	})

	t.Run("空页且 total 为 0", func(t *testing.T) {
		client := jiraServer(t, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"startAt":0,"maxResults":50,"total":0,"issues":[]}`)
		}, "")
		issues, err := client.SearchAllJiraIssues(context.Background(), "project = OPS", 0)
		if err != nil || len(issues) != 0 {
			t.Fatalf("空结果应 0/nil，got %d/%v", len(issues), err)
		}
	})

	t.Run("startAt 不一致", func(t *testing.T) {
		client := jiraServer(t, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"startAt":0,"maxResults":2,"total":100,"issues":[{"key":"OPS-1"},{"key":"OPS-2"}]}`)
		}, "")
		issues, err := client.SearchAllJiraIssues(context.Background(), "project = OPS", 2)
		if !errors.Is(err, ErrPagination) {
			t.Fatalf("应 ErrPagination，got %v", err)
		}
		if len(issues) != 2 {
			t.Fatalf("已取部分应保留: %d", len(issues))
		}
	})

	t.Run("空页但 total 未到", func(t *testing.T) {
		client := jiraServer(t, func(w http.ResponseWriter, r *http.Request) {
			start := r.URL.Query().Get("startAt")
			_, _ = fmt.Fprintf(w, `{"startAt":%s,"maxResults":2,"total":10,"issues":[]}`, start)
		}, "")
		if _, err := client.SearchAllJiraIssues(context.Background(), "project = OPS", 2); !errors.Is(err, ErrPaginationStalled) {
			t.Fatalf("应 ErrPaginationStalled，got %v", err)
		}
	})

	doer, calls := failIfCalledDoer(t)
	c, err := NewClient(Target{Adapter: AdapterJira, BaseURL: "https://j.example.com"},
		staticCreds(Credentials{User: "u", Token: "t"}), doer)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.SearchAllJiraIssues(context.Background(), "project = OPS", -1); !errors.Is(err, ErrBadPageSize) {
		t.Fatalf("负数页大小应 ErrBadPageSize，got %v", err)
	}
	if _, err := c.SearchAllJiraIssues(context.Background(), "project = OPS", MaxJiraMaxResults+1); !errors.Is(err, ErrBadPageSize) {
		t.Fatalf("超限页大小应 ErrBadPageSize，got %v", err)
	}
	if *calls != 0 {
		t.Fatalf("校验失败不应发请求: %d", *calls)
	}
}

// TestWrongAdapter 跨平台调用 fail-closed（不解析凭证、不发请求）。
func TestWrongAdapter(t *testing.T) {
	doer, calls := failIfCalledDoer(t)
	pd, err := NewClient(Target{Adapter: AdapterPagerDuty, BaseURL: "https://pd.example.com", Source: "svc"},
		staticCreds(Credentials{RoutingKey: "rk"}), doer)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := pd.CreateJiraIssue(context.Background(), CreateIssueRequest{
		ProjectKey: "OPS", IssueType: "Bug", Summary: "s",
	}); !errors.Is(err, ErrWrongAdapter) {
		t.Fatalf("PD client 调 Jira 方法应 ErrWrongAdapter，got %v", err)
	}
	jira, err := NewClient(Target{Adapter: AdapterJira, BaseURL: "https://j.example.com"},
		staticCreds(Credentials{User: "u", Token: "t"}), doer)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := jira.SendPagerDutyEvent(context.Background(), PagerDutyEvent{Action: PagerDutyTrigger}); !errors.Is(err, ErrWrongAdapter) {
		t.Fatalf("Jira client 调 PD 方法应 ErrWrongAdapter，got %v", err)
	}
	if *calls != 0 {
		t.Fatalf("平台不匹配不应发请求: %d", *calls)
	}
}
