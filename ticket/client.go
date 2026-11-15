package ticket

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

// 工单系统适配器词表。
type Adapter string

const (
	AdapterJira      Adapter = "jira"      // Server/DC 与 Cloud 同构 REST（Basic = user:token）
	AdapterPagerDuty Adapter = "pagerduty" // Events API v2（Routing Key）
)

// 契约常量。
const (
	// DefaultPagerDutyURL PagerDuty Events API v2 备注端点。
	DefaultPagerDutyURL = "https://events.pagerduty.com/v2/en/note"
	// DefaultTimeout 缺省 HTTP 超时。
	DefaultTimeout = 10 * time.Second
	// CommentSummaryCap 回写摘要截断上限（字节）。
	CommentSummaryCap = 1600
	// DescriptionCap Jira 描述截断上限（字节）。
	DescriptionCap = 4000
	// JiraSummaryCap Jira summary 上限（字符）。
	JiraSummaryCap = 255
	// DefaultSearchMax JQL 搜索缺省单页条数。
	DefaultSearchMax = 20
	// MaxSearchMax JQL 搜索单页上限。
	MaxSearchMax = 100

	maxResponseBytes = 256 * 1024
)

// 错误哨兵（errors.Is 判定；文案带上下文）。
var (
	ErrBadTarget = errors.New("ticket: 目标配置非法")
	ErrUpstream  = errors.New("ticket: 工单系统请求失败")
)

// Target 工单回投目标。Credential 是宿主持有凭证平面解析后的明文形态：
// Jira 为 "user:api_token"（Basic），PagerDuty 为 routing key。
type Target struct {
	Adapter    Adapter
	BaseURL    string // jira: https://host（Cloud/Server 同构）；pagerduty 忽略
	Credential string
	IssueKey   string // jira 工单键（PROJ-123）；pagerduty 空即可（dedup_key 走会话 id）
}

// Payload 回写体（会话终态钩子组装；Summary 由宿主先脱敏）。
type Payload struct {
	SessionID string
	Status    string
	Title     string
	Summary   string // 结论摘要（宿主已脱敏；本包只截断）
	URL       string // 控制台会话回链（可选）
	Header    string // 可选首行（宿主品牌/标记，如 "[诊断] ..."）
}

// Options Client 构造选项。
type Options struct {
	// HTTPClient 出站客户端（宿主负责 SSRF 闸/Transport）；nil=10s 超时+
	// 不跟随重定向的缺省 client。
	HTTPClient *http.Client
	// PagerDutyURL 覆盖 Events v2 端点（测试/代理用；空=DefaultPagerDutyURL）。
	PagerDutyURL string
}

// Client 无状态工单适配器（并发安全）。
type Client struct {
	http         *http.Client
	pagerDutyURL string
}

// New 装配适配器。
func New(opts Options) *Client {
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{
			Timeout: DefaultTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse // 重定向可绕开宿主 SSRF 闸，缺省拒绝跟随
			},
		}
	}
	u := strings.TrimSpace(opts.PagerDutyURL)
	if u == "" {
		u = DefaultPagerDutyURL
	}
	return &Client{http: hc, pagerDutyURL: u}
}

// PostComment 回写结论到工单（Jira 评论 / PagerDuty 备注），返回原始响应摘要。
func (c *Client) PostComment(ctx context.Context, t Target, p Payload) (string, error) {
	switch t.Adapter {
	case AdapterJira:
		return c.postJiraComment(ctx, t, p)
	case AdapterPagerDuty:
		return c.postPagerDuty(ctx, t, p)
	default:
		return "", fmt.Errorf("%w: 未知适配器 %q（jira|pagerduty）", ErrBadTarget, t.Adapter)
	}
}

// CommentBody 组装回写正文（标题/状态/回链/摘要四段；摘要截断）。
func CommentBody(p Payload) string {
	var b strings.Builder
	if h := strings.TrimSpace(p.Header); h != "" {
		b.WriteString(h)
		b.WriteString("\n\n")
	}
	title := strings.TrimSpace(p.Title)
	session := strings.TrimSpace(p.SessionID)
	status := strings.TrimSpace(p.Status)
	switch {
	case title != "" && (session != "" || status != ""):
		fmt.Fprintf(&b, "%s（会话 %s，状态 %s）\n\n", title, session, status)
	case title != "":
		b.WriteString(title + "\n\n")
	case session != "" || status != "":
		fmt.Fprintf(&b, "会话 %s（状态 %s）\n\n", session, status)
	}
	b.WriteString(truncateEllipsis(p.Summary, CommentSummaryCap))
	if u := strings.TrimSpace(p.URL); u != "" {
		b.WriteString("\n\n回链: " + u)
	}
	return b.String()
}

// truncateEllipsis 按字节上限截断并补省略号（不切断 UTF-8 字符）。
func truncateEllipsis(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	const ell = "…"
	cut := max - len(ell)
	if cut < 0 {
		cut = 0
	}
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + ell
}

// normalizeBase Jira base 归一（去尾斜杠 + 绝对 http(s) 校验）。
func normalizeBase(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("%w: base_url 为空", ErrBadTarget)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: base_url 非法: %v", ErrBadTarget, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("%w: base_url 须为绝对 http(s) 地址: %q", ErrBadTarget, raw)
	}
	return strings.TrimRight(u.String(), "/"), nil
}

// basicCredential 拆分 Jira "user:token"（缺冒号 fail-loud，绝不 panic）。
func basicCredential(cred string) (user, pass string, err error) {
	cred = strings.TrimSpace(cred)
	if cred == "" {
		return "", "", fmt.Errorf("%w: credential 为空", ErrBadTarget)
	}
	user, pass, ok := strings.Cut(cred, ":")
	if !ok {
		return "", "", fmt.Errorf("%w: Jira credential 须为 user:token", ErrBadTarget)
	}
	return user, pass, nil
}
