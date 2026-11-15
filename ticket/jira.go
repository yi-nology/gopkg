package ticket

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ── Jira REST（Cloud 与 Server/DC 路径同构） ──

// JiraIssue JQL 搜索条目。
type JiraIssue struct {
	Key     string `json:"key"`
	Summary string `json:"summary"`
	Status  string `json:"status"`
}

// SearchResult JQL 单页搜索结果（分页游标原语）。
type SearchResult struct {
	Issues     []JiraIssue
	StartAt    int
	MaxResults int
	Total      int
}

// postJiraComment Jira REST 评论：POST {base}/rest/api/2/issue/{key}/comment，
// Basic user:token。
func (c *Client) postJiraComment(ctx context.Context, t Target, p Payload) (string, error) {
	base, err := normalizeBase(t.BaseURL)
	if err != nil {
		return "", err
	}
	user, pass, err := basicCredential(t.Credential)
	if err != nil {
		return "", err
	}
	key := strings.TrimSpace(t.IssueKey)
	if key == "" {
		return "", fmt.Errorf("%w: jira 回写需 issue_key", ErrBadTarget)
	}
	body, err := json.Marshal(map[string]string{"body": CommentBody(p)})
	if err != nil {
		return "", fmt.Errorf("ticket: 编码 jira 评论失败: %w", err)
	}
	endpoint := base + "/rest/api/2/issue/" + url.PathEscape(key) + "/comment"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("%w: 构造 jira 评论请求: %v", ErrBadTarget, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(user, pass)
	raw, code, err := c.do(req)
	if err != nil {
		return "", err
	}
	if code/100 != 2 {
		return "", fmt.Errorf("%w: jira 回写 %d: %.200s", ErrUpstream, code, raw)
	}
	return fmt.Sprintf("jira %s 已回写（HTTP %d）", key, code), nil
}

// CreateJiraIssue 创建工单（project/issuetype/summary/description），返回新工单键。
// description 截断到 DescriptionCap；summary 超 JiraSummaryCap 字符 fail-loud。
func (c *Client) CreateJiraIssue(ctx context.Context, t Target, project, issueType, summary, description string) (string, error) {
	base, err := normalizeBase(t.BaseURL)
	if err != nil {
		return "", err
	}
	user, pass, err := basicCredential(t.Credential)
	if err != nil {
		return "", err
	}
	project, issueType, summary = strings.TrimSpace(project), strings.TrimSpace(issueType), strings.TrimSpace(summary)
	if project == "" || issueType == "" || summary == "" {
		return "", fmt.Errorf("%w: jira 创建需 project/issuetype/summary", ErrBadTarget)
	}
	if utf8.RuneCountInString(summary) > JiraSummaryCap {
		return "", fmt.Errorf("%w: jira summary 超过 %d 字符", ErrBadTarget, JiraSummaryCap)
	}
	body, err := json.Marshal(map[string]any{
		"fields": map[string]any{
			"project":     map[string]string{"key": project},
			"issuetype":   map[string]string{"name": issueType},
			"summary":     summary,
			"description": truncateEllipsis(description, DescriptionCap),
		},
	})
	if err != nil {
		return "", fmt.Errorf("ticket: 编码 jira 创建请求失败: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/rest/api/2/issue", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("%w: 构造 jira 创建请求: %v", ErrBadTarget, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(user, pass)
	raw, code, err := c.do(req)
	if err != nil {
		return "", err
	}
	if code/100 != 2 {
		return "", fmt.Errorf("%w: jira 创建 %d: %.200s", ErrUpstream, code, raw)
	}
	var out struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.Key == "" {
		return "", fmt.Errorf("%w: jira 创建响应缺 key（HTTP %d）", ErrUpstream, code)
	}
	return out.Key, nil
}

// TransitionJiraIssue 流转工单状态（transitionID 从 Jira 工作流取；Cloud/Server 同构）。
func (c *Client) TransitionJiraIssue(ctx context.Context, t Target, issueKey, transitionID string) error {
	base, err := normalizeBase(t.BaseURL)
	if err != nil {
		return err
	}
	user, pass, err := basicCredential(t.Credential)
	if err != nil {
		return err
	}
	issueKey, transitionID = strings.TrimSpace(issueKey), strings.TrimSpace(transitionID)
	if issueKey == "" || transitionID == "" {
		return fmt.Errorf("%w: jira 流转需 issue_key/transition_id", ErrBadTarget)
	}
	body, err := json.Marshal(map[string]any{"transition": map[string]string{"id": transitionID}})
	if err != nil {
		return fmt.Errorf("ticket: 编码 jira 流转请求失败: %w", err)
	}
	endpoint := base + "/rest/api/2/issue/" + url.PathEscape(issueKey) + "/transitions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%w: 构造 jira 流转请求: %v", ErrBadTarget, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(user, pass)
	raw, code, err := c.do(req)
	if err != nil {
		return err
	}
	if code/100 != 2 {
		return fmt.Errorf("%w: jira 流转 %d: %.200s", ErrUpstream, code, raw)
	}
	return nil
}

// SearchJiraPage JQL 搜索单页（宽口径原样透传 JQL；返回 key/summary/status）。
// maxResults 缺省/越界回落 20（上限 100）。
func (c *Client) SearchJiraPage(ctx context.Context, t Target, jql string, startAt, maxResults int) (*SearchResult, error) {
	base, err := normalizeBase(t.BaseURL)
	if err != nil {
		return nil, err
	}
	user, pass, err := basicCredential(t.Credential)
	if err != nil {
		return nil, err
	}
	jql = strings.TrimSpace(jql)
	if jql == "" {
		return nil, fmt.Errorf("%w: jira 搜索需 jql", ErrBadTarget)
	}
	if startAt < 0 {
		startAt = 0
	}
	if maxResults <= 0 || maxResults > MaxSearchMax {
		maxResults = DefaultSearchMax
	}
	q := url.Values{}
	q.Set("jql", jql)
	q.Set("startAt", strconv.Itoa(startAt))
	q.Set("maxResults", strconv.Itoa(maxResults))
	q.Set("fields", "key,summary,status")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/rest/api/2/search?"+q.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: 构造 jira 搜索请求: %v", ErrBadTarget, err)
	}
	req.SetBasicAuth(user, pass)
	raw, code, err := c.do(req)
	if err != nil {
		return nil, err
	}
	if code/100 != 2 {
		return nil, fmt.Errorf("%w: jira 搜索 %d: %.200s", ErrUpstream, code, raw)
	}
	var out struct {
		StartAt    int `json:"startAt"`
		MaxResults int `json:"maxResults"`
		Total      int `json:"total"`
		Issues     []struct {
			Key    string `json:"key"`
			Fields struct {
				Summary string `json:"summary"`
				Status  struct {
					Name string `json:"name"`
				} `json:"status"`
			} `json:"fields"`
		} `json:"issues"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("%w: jira 搜索响应非法: %v", ErrUpstream, err)
	}
	res := &SearchResult{
		Issues:     make([]JiraIssue, 0, len(out.Issues)),
		StartAt:    out.StartAt,
		MaxResults: out.MaxResults,
		Total:      out.Total,
	}
	for _, it := range out.Issues {
		res.Issues = append(res.Issues, JiraIssue{Key: it.Key, Summary: it.Fields.Summary, Status: it.Fields.Status.Name})
	}
	return res, nil
}

// SearchJiraIssues 单页 JQL 搜索（便捷形态）。
func (c *Client) SearchJiraIssues(ctx context.Context, t Target, jql string, maxResults int) ([]JiraIssue, error) {
	res, err := c.SearchJiraPage(ctx, t, jql, 0, maxResults)
	if err != nil {
		return nil, err
	}
	return res.Issues, nil
}

// SearchJiraAll 自动翻页取单原语：逐页回调 fn（fn 返回 error 即中止），
// 直到 total 消费完/短页/空页。maxPages<=0 缺省 10，上限 100。
// 返回成功回调的条目总数。
func (c *Client) SearchJiraAll(ctx context.Context, t Target, jql string, pageSize, maxPages int, fn func([]JiraIssue) error) (int, error) {
	if pageSize <= 0 || pageSize > MaxSearchMax {
		pageSize = DefaultSearchMax
	}
	if maxPages <= 0 {
		maxPages = 10
	}
	if maxPages > 100 {
		maxPages = 100
	}
	total := 0
	startAt := 0
	for page := 0; page < maxPages; page++ {
		res, err := c.SearchJiraPage(ctx, t, jql, startAt, pageSize)
		if err != nil {
			return total, err
		}
		if len(res.Issues) == 0 {
			break
		}
		next := res.StartAt + len(res.Issues)
		if next <= startAt {
			break // 服务端忽略 startAt：本页是重复页，处理前即停（防重复取单/死循环）
		}
		if fn != nil {
			if err := fn(res.Issues); err != nil {
				return total, err
			}
		}
		total += len(res.Issues)
		startAt = next
		if res.Total > 0 && startAt >= res.Total {
			break
		}
		if len(res.Issues) < pageSize {
			break
		}
	}
	return total, nil
}

// do 执行请求并读取限长响应（响应体上限防大载荷）。
func (c *Client) do(req *http.Request) ([]byte, int, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %w", ErrUpstream, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("%w: 读取响应: %w", ErrUpstream, err)
	}
	return raw, resp.StatusCode, nil
}
