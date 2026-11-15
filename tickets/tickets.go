package tickets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Adapter 工单平台类型。
type Adapter string

const (
	// AdapterJira Jira REST v2（Cloud/Server 同构）。
	AdapterJira Adapter = "jira"
	// AdapterPagerDuty PagerDuty Events API v2。
	AdapterPagerDuty Adapter = "pagerduty"
)

// DefaultPagerDutyBaseURL PagerDuty Events API v2 官方端点（Target.BaseURL
// 为空时使用；测试/私有代理可显式覆盖）。
const DefaultPagerDutyBaseURL = "https://events.pagerduty.com"

const (
	// DefaultJiraMaxResults Jira 分页默认页大小。
	DefaultJiraMaxResults = 50
	// MaxJiraMaxResults Jira 单页上限（服务端硬上限 100）。
	MaxJiraMaxResults = 100
	// MaxPagerDutySummaryLen PagerDuty summary 字符上限。
	MaxPagerDutySummaryLen = 1024
	// MaxPagerDutyDedupKeyLen PagerDuty dedup_key 字符上限。
	MaxPagerDutyDedupKeyLen = 255

	maxResponseBytes = 4 << 20 // 单响应读取上限
	errBodyExcerpt   = 1024    // 非 2xx 响应片段上限
)

// Target 适配器目标：平台/基准地址/凭证引用。业务域词表与凭证解析都在宿主。
type Target struct {
	Adapter Adapter
	// BaseURL 平台基准地址。Jira 必填（可带 /rest/api/2|3 后缀，请求统一
	// 走 v2）；PagerDuty 留空用 [DefaultPagerDutyBaseURL]。
	BaseURL string
	// CredentialRef 凭证平面引用（vault://… / secret://…）。本包不解析，
	// 原样交给 [CredentialProvider]。
	CredentialRef string
	// Source PagerDuty trigger 事件的 source 标识（通常宿主服务名）。
	// Payload.Source 留空时用它兜底；PostComment 映射 trigger 事件时必填。
	Source string
}

// Credentials 平台凭证：Jira 用 User+Token（Basic），PagerDuty 用 RoutingKey。
type Credentials struct {
	User       string
	Token      string
	RoutingKey string
}

// CredentialProvider 凭证引用解析器：每次请求前调用，支持轮换；失败
// fail-closed（错误原样包装为 [ErrCredential]）。
type CredentialProvider func(ctx context.Context, ref string) (Credentials, error)

// Doer HTTP 执行器：*http.Client 直接满足；宿主可注入带超时/代理/出站
// SSRF 闸的实现。
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client Jira/PagerDuty 适配器。无状态、可并发使用；凭证不落字段。
type Client struct {
	adapter Adapter
	base    *url.URL
	source  string
	credRef string
	creds   CredentialProvider
	doer    Doer
}

// 哨兵错误（errors.Is 判定，不匹配文案）。
var (
	// ErrBadAdapter 未知平台类型。
	ErrBadAdapter = errors.New("tickets: 未知平台类型")
	// ErrBadTarget 基准 URL/目标形态非法（非 http(s)、含 userinfo/query/
	// fragment、Jira 地址缺失或路径无法归一）。
	ErrBadTarget = errors.New("tickets: 目标非法")
	// ErrNoCredentialProvider 未注入凭证解析器。
	ErrNoCredentialProvider = errors.New("tickets: 缺少凭证解析器（fail-closed）")
	// ErrNoDoer 未注入 HTTP 执行器。
	ErrNoDoer = errors.New("tickets: 缺少 HTTP 执行器（fail-closed）")
	// ErrWrongAdapter 在错误平台类型的 Client 上调用了专用方法。
	ErrWrongAdapter = errors.New("tickets: 平台类型不匹配")
	// ErrMissingCredentials 凭证缺必填字段（Jira user/token、
	// PagerDuty routing key）。
	ErrMissingCredentials = errors.New("tickets: 凭证缺必填字段（fail-closed）")
	// ErrCredential 凭证解析失败。
	ErrCredential = errors.New("tickets: 凭证解析失败")
	// ErrTransport 网络层失败（连接/超时/出站闸拒绝）。
	ErrTransport = errors.New("tickets: 请求传输失败")
	// ErrHTTPStatus 平台返回非 2xx（具体码见 [HTTPError]）。
	ErrHTTPStatus = errors.New("tickets: 平台返回非 2xx")
	// ErrBadResponse 2xx 但响应形态非法（空/非 JSON/缺必填字段）。
	ErrBadResponse = errors.New("tickets: 响应形态非法")
	// ErrEncode 请求体无法 JSON 编码。
	ErrEncode = errors.New("tickets: 请求体编码失败")
	// ErrInvalidArgument 调用参数非法（空 issue key/评论/流转/JQL 等）。
	ErrInvalidArgument = errors.New("tickets: 参数非法")
	// ErrBadPageSize 页大小非正或超过平台上限。
	ErrBadPageSize = errors.New("tickets: 页大小非法")
	// ErrPagination 分页响应与请求不一致。
	ErrPagination = errors.New("tickets: 分页响应不一致")
	// ErrPaginationStalled 分页 startAt 不前进（防死循环）。
	ErrPaginationStalled = errors.New("tickets: 分页停滞")
	// ErrTransitionNotFound 按名称流转时零命中。
	ErrTransitionNotFound = errors.New("tickets: 流转名称未找到")
	// ErrTransitionAmbiguous 按名称流转时多重命中。
	ErrTransitionAmbiguous = errors.New("tickets: 流转名称多重命中")
	// ErrNoSources 轮询器没有 Source。
	ErrNoSources = errors.New("tickets: 轮询器无 Source")
	// ErrPollerNotConfigured 轮询器缺 Ledger/Handler。
	ErrPollerNotConfigured = errors.New("tickets: 轮询器未配置 Ledger/Handler")
)

// HTTPError 非 2xx 响应。只携带 path（不含 query/凭证）与截断响应片段。
type HTTPError struct {
	StatusCode int
	Method     string
	Path       string
	Body       string
}

// Error 人类可读错误（日志排障用）。
func (e *HTTPError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("tickets: %s %s 返回 %d", e.Method, e.Path, e.StatusCode)
	}
	return fmt.Sprintf("tickets: %s %s 返回 %d: %s", e.Method, e.Path, e.StatusCode, e.Body)
}

// Unwrap 让 errors.Is(err, ErrHTTPStatus) 成立。
func (e *HTTPError) Unwrap() error { return ErrHTTPStatus }

// NormalizeBaseURL 基准地址归一（宿主可在启动期单独校验配置）。
//
// Jira：要求 http/https、host 非空、无 userinfo/query/fragment；剥离
// `/rest/api/2` 或 `/rest/api/3` 后缀，其余路径作为 context path 保留。
// PagerDuty：空值用官方端点；剥离 `/v2/enqueue` 或 `/v2` 后缀。
func NormalizeBaseURL(adapter Adapter, raw string) (string, error) {
	var (
		u   *url.URL
		err error
	)
	switch adapter {
	case AdapterJira:
		if strings.TrimSpace(raw) == "" {
			return "", fmt.Errorf("%w: jira baseURL 为空", ErrBadTarget)
		}
		u, err = parseBaseURL(raw)
		if err != nil {
			return "", err
		}
		path := strings.TrimRight(u.Path, "/")
		switch {
		case strings.HasSuffix(path, "/rest/api/2"):
			path = strings.TrimSuffix(path, "/rest/api/2")
		case strings.HasSuffix(path, "/rest/api/3"):
			// 配置可来自 Cloud v3 习惯，但本包协议面固定 v2（Cloud/Server 同构）。
			path = strings.TrimSuffix(path, "/rest/api/3")
		case strings.Contains(path, "/rest/api/"):
			return "", fmt.Errorf("%w: 无法归一的 Jira API 路径 %q", ErrBadTarget, u.Path)
		}
		u.Path = path
	case AdapterPagerDuty:
		if strings.TrimSpace(raw) == "" {
			raw = DefaultPagerDutyBaseURL
		}
		u, err = parseBaseURL(raw)
		if err != nil {
			return "", err
		}
		path := strings.TrimRight(u.Path, "/")
		switch {
		case strings.HasSuffix(path, "/v2/enqueue"):
			path = strings.TrimSuffix(path, "/v2/enqueue")
		case strings.HasSuffix(path, "/v2"):
			path = strings.TrimSuffix(path, "/v2")
		case strings.Contains(path, "/v2/"):
			return "", fmt.Errorf("%w: 无法归一的 PagerDuty API 路径 %q", ErrBadTarget, u.Path)
		}
		u.Path = path
	default:
		return "", fmt.Errorf("%w: %q", ErrBadAdapter, adapter)
	}
	return u.String(), nil
}

func parseBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadTarget, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%w: scheme 必须为 http/https，got %q", ErrBadTarget, u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%w: 缺少 host", ErrBadTarget)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: 凭证不得写入 URL", ErrBadTarget)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%w: 不得携带 query/fragment", ErrBadTarget)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return u, nil
}

// NewClient 构建适配器并做全量 fail-closed 校验。
func NewClient(target Target, creds CredentialProvider, doer Doer) (*Client, error) {
	if creds == nil {
		return nil, ErrNoCredentialProvider
	}
	if doer == nil {
		return nil, ErrNoDoer
	}
	normalized, err := NormalizeBaseURL(target.Adapter, target.BaseURL)
	if err != nil {
		return nil, err
	}
	base, err := url.Parse(normalized)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadTarget, err)
	}
	return &Client{
		adapter: target.Adapter,
		base:    base,
		source:  target.Source,
		credRef: target.CredentialRef,
		creds:   creds,
		doer:    doer,
	}, nil
}

// Adapter 返回客户端平台类型。
func (c *Client) Adapter() Adapter { return c.adapter }

func (c *Client) ensure(adapter Adapter) error {
	if c.adapter != adapter {
		return fmt.Errorf("%w: client=%s, method=%s", ErrWrongAdapter, c.adapter, adapter)
	}
	return nil
}

func (c *Client) credentials(ctx context.Context) (Credentials, error) {
	creds, err := c.creds(ctx, c.credRef)
	if err != nil {
		return Credentials{}, fmt.Errorf("%w: %w", ErrCredential, err)
	}
	return creds, nil
}

// jiraEndpoint 拼 /rest/api/2/... 路径（base 的 context path 保留）。
func (c *Client) jiraEndpoint(segments ...string) *url.URL {
	elems := append([]string{"rest", "api", "2"}, segments...)
	return c.base.JoinPath(elems...)
}

// pagerDutyEndpoint 拼 /v2/enqueue。
func (c *Client) pagerDutyEndpoint(segments ...string) *url.URL {
	elems := append([]string{"v2"}, segments...)
	return c.base.JoinPath(elems...)
}

// roundTrip 执行一次 JSON HTTP 调用。prepare 负责鉴权头（凭证已由调用方
// 解析并校验）。非 2xx 返回 *HTTPError；2xx 但 JSON 形态非法返回包装后的
// ErrBadResponse。
func (c *Client) roundTrip(ctx context.Context, method string, endpoint *url.URL, payload, out any, prepare func(*http.Request)) error {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrEncode, err)
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if prepare != nil {
		prepare(req)
	}

	resp, err := c.doer.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %s %s: %w", ErrTransport, method, endpoint.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("%w: 读取响应失败: %v", ErrTransport, err)
	}
	if len(raw) > maxResponseBytes {
		return fmt.Errorf("%w: 响应超过 %d 字节", ErrBadResponse, maxResponseBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		excerpt := string(raw)
		if len(excerpt) > errBodyExcerpt {
			excerpt = excerpt[:errBodyExcerpt]
		}
		return &HTTPError{
			StatusCode: resp.StatusCode,
			Method:     method,
			Path:       endpoint.Path,
			Body:       strings.TrimSpace(excerpt),
		}
	}
	if out == nil {
		return nil
	}
	if len(raw) == 0 {
		return fmt.Errorf("%w: %s %s 返回空响应体", ErrBadResponse, method, endpoint.Path)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("%w: %s %s: %v", ErrBadResponse, method, endpoint.Path, err)
	}
	return nil
}

func requireNonBlank(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%w: %s 为空", ErrInvalidArgument, field)
	}
	return nil
}
