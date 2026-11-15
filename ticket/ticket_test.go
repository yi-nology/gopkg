package ticket

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

func TestJiraCommentContract(t *testing.T) {
	var gotMethod, gotPath, gotAuth, gotCT, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotCT = r.Method, r.URL.Path, r.Header.Get("Content-Type")
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"1"}`))
	}))
	defer srv.Close()

	c := New(Options{})
	msg, err := c.PostComment(context.Background(), Target{
		Adapter: AdapterJira, BaseURL: srv.URL + "/", Credential: "ops@example.com:token", IssueKey: "PROJ-1",
	}, Payload{SessionID: "sess-1", Status: "done", Title: "磁盘告警", Summary: "根因是 inode 耗尽", URL: "https://console/s/1", Header: "[诊断]"})
	if err != nil {
		t.Fatalf("PostComment: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/rest/api/2/issue/PROJ-1/comment" {
		t.Fatalf("method=%s path=%s", gotMethod, gotPath)
	}
	if gotCT != "application/json" {
		t.Fatalf("content-type=%s", gotCT)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("ops@example.com:token"))
	if gotAuth != wantAuth {
		t.Fatalf("auth=%q, want %q", gotAuth, wantAuth)
	}
	var payload struct {
		Body string `json:"body"`
	}
	if err := json.Unmarshal([]byte(gotBody), &payload); err != nil {
		t.Fatalf("body=%q err=%v", gotBody, err)
	}
	for _, want := range []string{"[诊断]", "磁盘告警", "sess-1", "done", "inode", "https://console/s/1"} {
		if !strings.Contains(payload.Body, want) {
			t.Fatalf("回写正文缺 %q: %s", want, payload.Body)
		}
	}
	if !strings.Contains(msg, "PROJ-1") || !strings.Contains(msg, "201") {
		t.Fatalf("msg=%q", msg)
	}
}

func TestJiraTargetValidation(t *testing.T) {
	c := New(Options{})
	tests := []struct {
		name string
		t    Target
	}{
		{"空 base", Target{Adapter: AdapterJira, Credential: "u:t", IssueKey: "P-1"}},
		{"非 http base", Target{Adapter: AdapterJira, BaseURL: "ftp://x", Credential: "u:t", IssueKey: "P-1"}},
		{"相对 base", Target{Adapter: AdapterJira, BaseURL: "/api", Credential: "u:t", IssueKey: "P-1"}},
		{"空凭据", Target{Adapter: AdapterJira, BaseURL: "https://x", IssueKey: "P-1"}},
		{"凭据无冒号", Target{Adapter: AdapterJira, BaseURL: "https://x", Credential: "token", IssueKey: "P-1"}},
		{"空 issue", Target{Adapter: AdapterJira, BaseURL: "https://x", Credential: "u:t"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.PostComment(context.Background(), tc.t, Payload{})
			if !errors.Is(err, ErrBadTarget) {
				t.Fatalf("err=%v, want ErrBadTarget", err)
			}
		})
	}
	_, err := c.PostComment(context.Background(), Target{Adapter: "nope"}, Payload{})
	if !errors.Is(err, ErrBadTarget) {
		t.Fatalf("err=%v", err)
	}
}

func TestJiraUpstreamError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()
	c := New(Options{})
	_, err := c.PostComment(context.Background(), Target{
		Adapter: AdapterJira, BaseURL: srv.URL, Credential: "u:t", IssueKey: "P-1",
	}, Payload{Summary: "x"})
	if !errors.Is(err, ErrUpstream) || !strings.Contains(err.Error(), "500") || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err=%v", err)
	}
}

func TestJiraRedirectNotFollowed(t *testing.T) {
	var hits int
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer target.Close()
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer src.Close()
	c := New(Options{})
	_, err := c.PostComment(context.Background(), Target{
		Adapter: AdapterJira, BaseURL: src.URL, Credential: "u:t", IssueKey: "P-1",
	}, Payload{Summary: "x"})
	if !errors.Is(err, ErrUpstream) {
		t.Fatalf("err=%v", err)
	}
	if hits != 0 {
		t.Fatalf("重定向被跟随: hits=%d", hits)
	}
}

func TestCreateJiraIssue(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/2/issue" || r.Method != http.MethodPost {
			t.Errorf("path=%s method=%s", r.URL.Path, r.Method)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"key":"PROJ-9"}`))
	}))
	defer srv.Close()
	c := New(Options{})
	key, err := c.CreateJiraIssue(context.Background(), Target{
		Adapter: AdapterJira, BaseURL: srv.URL, Credential: "u:t",
	}, "PROJ", "Bug", "磁盘 inode 耗尽", strings.Repeat("详", DescriptionCap))
	if err != nil || key != "PROJ-9" {
		t.Fatalf("key=%q err=%v", key, err)
	}
	fields, _ := got["fields"].(map[string]any)
	if fields["summary"] != "磁盘 inode 耗尽" {
		t.Fatalf("fields=%+v", fields)
	}
	if desc, _ := fields["description"].(string); len(desc) > DescriptionCap+len("…") || !strings.HasSuffix(desc, "…") {
		t.Fatalf("描述未按字节上限截断: len=%d", len(desc))
	}
}

func TestCreateJiraIssueValidation(t *testing.T) {
	c := New(Options{})
	base := Target{Adapter: AdapterJira, BaseURL: "https://jira.example.com", Credential: "u:t"}
	tests := []struct {
		name                        string
		project, issueType, summary string
	}{
		{"缺 project", "", "Bug", "s"},
		{"缺 issuetype", "P", "", "s"},
		{"缺 summary", "P", "Bug", ""},
		{"summary 超限", "P", "Bug", strings.Repeat("字", JiraSummaryCap+1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.CreateJiraIssue(context.Background(), base, tc.project, tc.issueType, tc.summary, "")
			if !errors.Is(err, ErrBadTarget) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestCreateJiraIssueMissingKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := New(Options{})
	_, err := c.CreateJiraIssue(context.Background(), Target{
		Adapter: AdapterJira, BaseURL: srv.URL, Credential: "u:t",
	}, "P", "Bug", "s", "")
	if !errors.Is(err, ErrUpstream) || !strings.Contains(err.Error(), "缺 key") {
		t.Fatalf("err=%v", err)
	}
}

func TestTransitionJiraIssue(t *testing.T) {
	var gotPath, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := New(Options{})
	err := c.TransitionJiraIssue(context.Background(), Target{
		Adapter: AdapterJira, BaseURL: srv.URL, Credential: "u:t",
	}, "PROJ-1", "31")
	if err != nil {
		t.Fatalf("Transition: %v", err)
	}
	if gotPath != "/rest/api/2/issue/PROJ-1/transitions" {
		t.Fatalf("path=%s", gotPath)
	}
	if !strings.Contains(gotBody, `"id":"31"`) {
		t.Fatalf("body=%s", gotBody)
	}
	if err := c.TransitionJiraIssue(context.Background(), Target{Adapter: AdapterJira, BaseURL: srv.URL, Credential: "u:t"}, "", "1"); !errors.Is(err, ErrBadTarget) {
		t.Fatalf("err=%v", err)
	}
}

func TestSearchJiraIssues(t *testing.T) {
	var gotJQL, gotMax, gotFields string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		gotJQL, gotMax, gotFields = q.Get("jql"), q.Get("maxResults"), q.Get("fields")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"startAt":0,"maxResults":20,"total":2,"issues":[
			{"key":"P-1","fields":{"summary":"一","status":{"name":"Open"}}},
			{"key":"P-2","fields":{"summary":"二","status":{"name":"Done"}}}]}`))
	}))
	defer srv.Close()
	c := New(Options{})
	issues, err := c.SearchJiraIssues(context.Background(), Target{
		Adapter: AdapterJira, BaseURL: srv.URL, Credential: "u:t",
	}, `project = "P" AND status != Done`, 0)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(issues) != 2 || issues[0].Key != "P-1" || issues[0].Status != "Open" || issues[1].Summary != "二" {
		t.Fatalf("issues=%+v", issues)
	}
	if gotJQL != `project = "P" AND status != Done` {
		t.Fatalf("jql=%q", gotJQL)
	}
	if gotMax != strconv.Itoa(DefaultSearchMax) {
		t.Fatalf("maxResults=%s, want %d", gotMax, DefaultSearchMax)
	}
	if gotFields != "key,summary,status" {
		t.Fatalf("fields=%s", gotFields)
	}
}

func TestSearchJiraMaxClamp(t *testing.T) {
	var gotMax string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMax = r.URL.Query().Get("maxResults")
		_, _ = w.Write([]byte(`{"issues":[]}`))
	}))
	defer srv.Close()
	c := New(Options{})
	tgt := Target{Adapter: AdapterJira, BaseURL: srv.URL, Credential: "u:t"}
	for _, in := range []int{0, -1, 999} {
		if _, err := c.SearchJiraIssues(context.Background(), tgt, "x", in); err != nil {
			t.Fatalf("Search(%d): %v", in, err)
		}
		if gotMax != strconv.Itoa(DefaultSearchMax) {
			t.Fatalf("in=%d max=%s", in, gotMax)
		}
	}
	if _, err := c.SearchJiraIssues(context.Background(), tgt, "x", 50); err != nil {
		t.Fatalf("Search(50): %v", err)
	}
	if gotMax != "50" {
		t.Fatalf("max=%s", gotMax)
	}
	if _, err := c.SearchJiraIssues(context.Background(), tgt, "  ", 10); !errors.Is(err, ErrBadTarget) {
		t.Fatalf("空 jql err=%v", err)
	}
}

func TestSearchJiraAllPagination(t *testing.T) {
	var mu sync.Mutex
	var calls []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start, _ := strconv.Atoi(r.URL.Query().Get("startAt"))
		mu.Lock()
		calls = append(calls, start)
		mu.Unlock()
		issues := []string{`{"key":"P-1","fields":{"summary":"一","status":{"name":"Open"}}}`,
			`{"key":"P-2","fields":{"summary":"二","status":{"name":"Open"}}}`}
		if start >= 2 {
			issues = issues[:1]
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"startAt":%d,"maxResults":2,"total":3,"issues":[%s]}`, start, strings.Join(issues, ","))
	}))
	defer srv.Close()
	c := New(Options{})
	var got []string
	n, err := c.SearchJiraAll(context.Background(), Target{
		Adapter: AdapterJira, BaseURL: srv.URL, Credential: "u:t",
	}, "x", 2, 10, func(page []JiraIssue) error {
		for _, it := range page {
			got = append(got, it.Key)
		}
		return nil
	})
	if err != nil || n != 3 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if strings.Join(got, ",") != "P-1,P-2,P-1" {
		t.Fatalf("got=%v", got)
	}
	if len(calls) != 2 || calls[0] != 0 || calls[1] != 2 {
		t.Fatalf("calls=%v", calls)
	}
}

func TestSearchJiraAllStopsWhenServerIgnoresStartAt(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"startAt":0,"maxResults":2,"total":100,"issues":[
			{"key":"P-1","fields":{"summary":"一","status":{"name":"Open"}}},
			{"key":"P-2","fields":{"summary":"二","status":{"name":"Open"}}}]}`))
	}))
	defer srv.Close()
	c := New(Options{})
	n, err := c.SearchJiraAll(context.Background(), Target{
		Adapter: AdapterJira, BaseURL: srv.URL, Credential: "u:t",
	}, "x", 2, 0, nil)
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if calls != 2 {
		t.Fatalf("calls=%d, want 2（第二页发现游标未前进即停）", calls)
	}
}

func TestSearchJiraAllCallbackError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"startAt":0,"maxResults":2,"total":2,"issues":[
			{"key":"P-1","fields":{"summary":"一","status":{"name":"Open"}}}]}`))
	}))
	defer srv.Close()
	c := New(Options{})
	boom := errors.New("boom")
	n, err := c.SearchJiraAll(context.Background(), Target{
		Adapter: AdapterJira, BaseURL: srv.URL, Credential: "u:t",
	}, "x", 2, 1, func([]JiraIssue) error { return boom })
	if !errors.Is(err, boom) || n != 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestPagerDutyContract(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method=%s", r.Method)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer srv.Close()
	c := New(Options{PagerDutyURL: srv.URL})
	msg, err := c.PostComment(context.Background(), Target{
		Adapter: AdapterPagerDuty, Credential: "routing-key",
	}, Payload{SessionID: "sess-9", Status: "done", Summary: "结论", URL: "https://console/9"})
	if err != nil {
		t.Fatalf("PostComment: %v", err)
	}
	if got["routing_key"] != "routing-key" || got["event_action"] != "annotate" || got["dedup_key"] != "sess-9" {
		t.Fatalf("payload=%+v", got)
	}
	pl, _ := got["payload"].(map[string]any)
	note, _ := pl["note"].(string)
	for _, want := range []string{"sess-9", "结论", "https://console/9"} {
		if !strings.Contains(note, want) {
			t.Fatalf("note 缺 %q: %s", want, note)
		}
	}
	if !strings.Contains(msg, "202") {
		t.Fatalf("msg=%q", msg)
	}
}

func TestPagerDutyErrors(t *testing.T) {
	c := New(Options{PagerDutyURL: "https://events.example.com/v2/en/note"})
	if _, err := c.PostComment(context.Background(), Target{Adapter: AdapterPagerDuty}, Payload{SessionID: "s"}); !errors.Is(err, ErrBadTarget) {
		t.Fatalf("缺 routing key err=%v", err)
	}
	if _, err := c.PostComment(context.Background(), Target{Adapter: AdapterPagerDuty, Credential: "k"}, Payload{}); !errors.Is(err, ErrBadTarget) {
		t.Fatalf("缺 dedup key err=%v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"status":"invalid event"}`))
	}))
	defer srv.Close()
	c = New(Options{PagerDutyURL: srv.URL})
	_, err := c.PostComment(context.Background(), Target{Adapter: AdapterPagerDuty, Credential: "k"}, Payload{SessionID: "s"})
	if !errors.Is(err, ErrUpstream) || !strings.Contains(err.Error(), "400") {
		t.Fatalf("err=%v", err)
	}

	if _, err := New(Options{PagerDutyURL: "not-a-url"}).PostComment(context.Background(),
		Target{Adapter: AdapterPagerDuty, Credential: "k"}, Payload{SessionID: "s"}); !errors.Is(err, ErrBadTarget) {
		t.Fatalf("坏端点 err=%v", err)
	}
}

func TestCommentBody(t *testing.T) {
	body := CommentBody(Payload{Header: "[诊断]", Title: "标题", SessionID: "s1", Status: "done", Summary: "摘要", URL: "https://u"})
	for _, want := range []string{"[诊断]", "标题", "s1", "done", "摘要", "https://u"} {
		if !strings.Contains(body, want) {
			t.Fatalf("body 缺 %q: %s", want, body)
		}
	}
	if got := CommentBody(Payload{SessionID: "s1", Status: "done", Summary: "x"}); !strings.HasPrefix(got, "会话 s1（状态 done）") {
		t.Fatalf("无标题形态=%q", got)
	}
	if got := CommentBody(Payload{Title: "只有标题", Summary: "x"}); !strings.HasPrefix(got, "只有标题\n\n") {
		t.Fatalf("仅标题形态=%q", got)
	}
	long := CommentBody(Payload{Summary: strings.Repeat("字", CommentSummaryCap)})
	if len(long) > CommentSummaryCap+len("…") {
		t.Fatalf("摘要未截断: %d", len(long))
	}
	if !utf8.ValidString(long) {
		t.Fatal("截断破坏了 UTF-8")
	}
}

func TestNormalizeBase(t *testing.T) {
	got, err := normalizeBase("https://jira.example.com/")
	if err != nil || got != "https://jira.example.com" {
		t.Fatalf("got=%q err=%v", got, err)
	}
	for _, bad := range []string{"", "jira.example.com", "ftp://x", "://bad"} {
		if _, err := normalizeBase(bad); !errors.Is(err, ErrBadTarget) {
			t.Fatalf("bad=%q err=%v", bad, err)
		}
	}
}

func TestTruncateEllipsisUTF8(t *testing.T) {
	s := strings.Repeat("中", 10) // 每字 3 字节
	got := truncateEllipsis(s, 10)
	if !utf8.ValidString(got) || len(got) > 10+len("…") {
		t.Fatalf("got=%q len=%d", got, len(got))
	}
	if truncateEllipsis("abc", 10) != "abc" {
		t.Fatal("短串不应截断")
	}
}
