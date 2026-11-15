package tickets

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Comment 回写回执：Jira 为评论 id/self；PagerDuty 映射事件时为 dedup_key。
type Comment struct {
	ID   string `json:"id"`
	Self string `json:"self,omitempty"`
}

// Issue Jira 工单标识。
type Issue struct {
	ID   string `json:"id"`
	Key  string `json:"key"`
	Self string `json:"self,omitempty"`
}

// CreateIssueRequest 建单请求。Fields 在类型化字段之后合入（宿主可覆盖
// 任意字段，机制不解释字段语义）。
type CreateIssueRequest struct {
	ProjectKey  string
	IssueType   string
	Summary     string
	Description string
	Labels      []string
	Priority    string
	Fields      map[string]any
}

// Transition 流转目标：ID 与 Name 二选一；Name 模式下先查当前可用流转并
// 精确匹配（零命中/多重命中 fail-closed）。
type Transition struct {
	ID   string
	Name string
}

// SearchOptions JQL 搜索分页参数（JQL 原样透传，不重写）。
type SearchOptions struct {
	StartAt    int
	MaxResults int
	Fields     []string
}

// JiraIssue 搜索结果条目（Fields 保留原始字段面，宿主按需解码）。
type JiraIssue struct {
	ID     string         `json:"id"`
	Key    string         `json:"key"`
	Self   string         `json:"self"`
	Fields map[string]any `json:"fields"`
}

// IssuePage Jira 搜索单页响应。
type IssuePage struct {
	StartAt    int         `json:"startAt"`
	MaxResults int         `json:"maxResults"`
	Total      int         `json:"total"`
	Issues     []JiraIssue `json:"issues"`
}

// PostComment 回写诊断结论：
//   - Jira：POST /rest/api/2/issue/{key}/comment，返回评论 id。
//   - PagerDuty：映射为 trigger 事件（dedup_key=issueKey、summary=body、
//     source=Target.Source），返回事件 dedup_key。长正文请直接调用
//     [Client.SendPagerDutyEvent] 并把正文放 CustomDetails。
func (c *Client) PostComment(ctx context.Context, issueKey, body string) (Comment, error) {
	if err := requireNonBlank("issue key", issueKey); err != nil {
		return Comment{}, err
	}
	if err := requireNonBlank("评论正文", body); err != nil {
		return Comment{}, err
	}
	switch c.adapter {
	case AdapterJira:
		return c.postJiraComment(ctx, issueKey, body)
	case AdapterPagerDuty:
		if len([]rune(body)) > MaxPagerDutySummaryLen {
			return Comment{}, fmt.Errorf("%w: PagerDuty summary 超过 %d 字符（改用 SendPagerDutyEvent + CustomDetails）",
				ErrInvalidArgument, MaxPagerDutySummaryLen)
		}
		result, err := c.sendPagerDutyEvent(ctx, PagerDutyEvent{
			Action:   PagerDutyTrigger,
			DedupKey: issueKey,
			Payload: PagerDutyPayload{
				Summary:  body,
				Source:   c.source,
				Severity: PagerDutySeverityError,
			},
		})
		if err != nil {
			return Comment{}, err
		}
		return Comment{ID: result.DedupKey}, nil
	default:
		return Comment{}, fmt.Errorf("%w: %q", ErrBadAdapter, c.adapter)
	}
}

func (c *Client) postJiraComment(ctx context.Context, issueKey, body string) (Comment, error) {
	if err := c.ensure(AdapterJira); err != nil {
		return Comment{}, err
	}
	creds, err := c.credentials(ctx)
	if err != nil {
		return Comment{}, err
	}
	if creds.User == "" || creds.Token == "" {
		return Comment{}, fmt.Errorf("%w: jira user/token 为空", ErrMissingCredentials)
	}
	endpoint := c.jiraEndpoint("issue", issueKey, "comment")
	var out Comment
	err = c.roundTrip(ctx, http.MethodPost, endpoint,
		map[string]string{"body": body}, &out,
		func(req *http.Request) { req.SetBasicAuth(creds.User, creds.Token) })
	if err != nil {
		return Comment{}, err
	}
	if out.ID == "" {
		return Comment{}, fmt.Errorf("%w: Jira 评论响应缺少 id", ErrBadResponse)
	}
	return out, nil
}

// CreateJiraIssue 创建工单（POST /rest/api/2/issue）。
func (c *Client) CreateJiraIssue(ctx context.Context, in CreateIssueRequest) (Issue, error) {
	if err := c.ensure(AdapterJira); err != nil {
		return Issue{}, err
	}
	if err := requireNonBlank("project key", in.ProjectKey); err != nil {
		return Issue{}, err
	}
	if err := requireNonBlank("issue type", in.IssueType); err != nil {
		return Issue{}, err
	}
	if err := requireNonBlank("summary", in.Summary); err != nil {
		return Issue{}, err
	}
	creds, err := c.credentials(ctx)
	if err != nil {
		return Issue{}, err
	}
	if creds.User == "" || creds.Token == "" {
		return Issue{}, fmt.Errorf("%w: jira user/token 为空", ErrMissingCredentials)
	}

	fields := map[string]any{
		"project":   map[string]any{"key": in.ProjectKey},
		"issuetype": map[string]any{"name": in.IssueType},
		"summary":   in.Summary,
	}
	if in.Description != "" {
		fields["description"] = in.Description
	}
	if len(in.Labels) > 0 {
		fields["labels"] = in.Labels
	}
	if in.Priority != "" {
		fields["priority"] = map[string]any{"name": in.Priority}
	}
	for k, v := range in.Fields {
		fields[k] = v
	}

	var out Issue
	err = c.roundTrip(ctx, http.MethodPost, c.jiraEndpoint("issue"),
		map[string]any{"fields": fields}, &out,
		func(req *http.Request) { req.SetBasicAuth(creds.User, creds.Token) })
	if err != nil {
		return Issue{}, err
	}
	if out.Key == "" {
		return Issue{}, fmt.Errorf("%w: Jira 建单响应缺少 key", ErrBadResponse)
	}
	return out, nil
}

// TransitionJiraIssue 执行流转：Transition.ID 直接提交；Transition.Name
// 先查询当前可用流转并精确匹配。成功返回 nil（Jira 通常返回 204）。
func (c *Client) TransitionJiraIssue(ctx context.Context, issueKey string, tr Transition) error {
	if err := c.ensure(AdapterJira); err != nil {
		return err
	}
	if err := requireNonBlank("issue key", issueKey); err != nil {
		return err
	}
	hasID := strings.TrimSpace(tr.ID) != ""
	hasName := strings.TrimSpace(tr.Name) != ""
	if hasID == hasName {
		return fmt.Errorf("%w: Transition 必须 ID/Name 二选一", ErrInvalidArgument)
	}
	creds, err := c.credentials(ctx)
	if err != nil {
		return err
	}
	if creds.User == "" || creds.Token == "" {
		return fmt.Errorf("%w: jira user/token 为空", ErrMissingCredentials)
	}
	auth := func(req *http.Request) { req.SetBasicAuth(creds.User, creds.Token) }

	transitionID := tr.ID
	if hasName {
		var list struct {
			Transitions []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"transitions"`
		}
		if err := c.roundTrip(ctx, http.MethodGet, c.jiraEndpoint("issue", issueKey, "transitions"), nil, &list, auth); err != nil {
			return err
		}
		matches := make([]string, 0, 1)
		for _, item := range list.Transitions {
			if item.Name == tr.Name {
				matches = append(matches, item.ID)
			}
		}
		switch len(matches) {
		case 0:
			return fmt.Errorf("%w: %q（issue %s）", ErrTransitionNotFound, tr.Name, issueKey)
		case 1:
			transitionID = matches[0]
		default:
			return fmt.Errorf("%w: %q 命中 %d 个流转", ErrTransitionAmbiguous, tr.Name, len(matches))
		}
	}
	if transitionID == "" {
		return fmt.Errorf("%w: 流转 id 为空", ErrBadResponse)
	}
	return c.roundTrip(ctx, http.MethodPost, c.jiraEndpoint("issue", issueKey, "transitions"),
		map[string]any{"transition": map[string]string{"id": transitionID}}, nil, auth)
}

// SearchJiraIssues 单页 JQL 搜索（JQL 原样透传，不做任何重写）。
func (c *Client) SearchJiraIssues(ctx context.Context, jql string, opts SearchOptions) (IssuePage, error) {
	page := IssuePage{}
	if err := c.ensure(AdapterJira); err != nil {
		return page, err
	}
	if err := requireNonBlank("jql", jql); err != nil {
		return page, err
	}
	if opts.StartAt < 0 {
		return page, fmt.Errorf("%w: startAt 不能为负", ErrInvalidArgument)
	}
	maxResults := opts.MaxResults
	if maxResults == 0 {
		maxResults = DefaultJiraMaxResults
	}
	if maxResults < 0 || maxResults > MaxJiraMaxResults {
		return page, fmt.Errorf("%w: maxResults=%d，允许 1..%d", ErrBadPageSize, opts.MaxResults, MaxJiraMaxResults)
	}
	for _, field := range opts.Fields {
		if strings.TrimSpace(field) == "" {
			return page, fmt.Errorf("%w: fields 含空项", ErrInvalidArgument)
		}
	}
	creds, err := c.credentials(ctx)
	if err != nil {
		return page, err
	}
	if creds.User == "" || creds.Token == "" {
		return page, fmt.Errorf("%w: jira user/token 为空", ErrMissingCredentials)
	}

	endpoint := c.jiraEndpoint("search")
	query := endpoint.Query()
	query.Set("jql", jql)
	query.Set("startAt", strconv.Itoa(opts.StartAt))
	query.Set("maxResults", strconv.Itoa(maxResults))
	if len(opts.Fields) > 0 {
		query.Set("fields", strings.Join(opts.Fields, ","))
	}
	endpoint.RawQuery = query.Encode()

	err = c.roundTrip(ctx, http.MethodGet, endpoint, nil, &page,
		func(req *http.Request) { req.SetBasicAuth(creds.User, creds.Token) })
	if err != nil {
		return page, err
	}
	if page.StartAt < 0 || page.MaxResults < 0 || page.Total < 0 {
		return page, fmt.Errorf("%w: 搜索响应分页字段为负", ErrBadResponse)
	}
	return page, nil
}

// SearchAllJiraIssues 逐页拉取完整结果集。分页判据：
//   - 响应 startAt 必须等于请求 startAt；
//   - 每页推进量必须为正（否则 ErrPaginationStalled，防服务端忽略 startAt
//     导致死循环/重复取单）；
//   - 取到空页或 startAt+len(issues) >= total 收口。
//
// 中途失败返回已取部分 + 错误（调用方不得把部分结果当完整结果）。
func (c *Client) SearchAllJiraIssues(ctx context.Context, jql string, pageSize int) ([]JiraIssue, error) {
	if pageSize == 0 {
		pageSize = DefaultJiraMaxResults
	}
	if pageSize < 0 || pageSize > MaxJiraMaxResults {
		return nil, fmt.Errorf("%w: pageSize=%d，允许 1..%d", ErrBadPageSize, pageSize, MaxJiraMaxResults)
	}
	var all []JiraIssue
	startAt := 0
	for {
		page, err := c.SearchJiraIssues(ctx, jql, SearchOptions{StartAt: startAt, MaxResults: pageSize})
		if err != nil {
			return all, err
		}
		if page.StartAt != startAt {
			return all, fmt.Errorf("%w: 请求 startAt=%d，响应 startAt=%d", ErrPagination, startAt, page.StartAt)
		}
		all = append(all, page.Issues...)
		if len(page.Issues) == 0 {
			if page.Total > startAt {
				// 服务端声称还有数据却返回空页：按分页停滞拒绝（部分结果不是完整结果）。
				return all, fmt.Errorf("%w: startAt=%d total=%d 却返回空页", ErrPaginationStalled, startAt, page.Total)
			}
			return all, nil
		}
		next := page.StartAt + len(page.Issues)
		if page.Total > 0 && next >= page.Total {
			return all, nil
		}
		startAt = next
	}
}
