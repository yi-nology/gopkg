package ticket

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// postPagerDuty Events API v2 备注（annotate）：routing key + dedup_key=会话 id；
// v2 响应 202 即受理。
func (c *Client) postPagerDuty(ctx context.Context, t Target, p Payload) (string, error) {
	key := strings.TrimSpace(t.Credential)
	if key == "" {
		return "", fmt.Errorf("%w: pagerduty 回写需 routing key", ErrBadTarget)
	}
	dedup := strings.TrimSpace(p.SessionID)
	if dedup == "" {
		return "", fmt.Errorf("%w: pagerduty 备注需会话 id 作 dedup_key", ErrBadTarget)
	}
	if err := validateEndpoint(c.pagerDutyURL); err != nil {
		return "", err
	}
	body, err := json.Marshal(map[string]any{
		"routing_key":  key,
		"event_action": "annotate",
		"dedup_key":    dedup,
		"payload": map[string]any{
			"note": CommentBody(p),
		},
	})
	if err != nil {
		return "", fmt.Errorf("ticket: 编码 pagerduty 备注失败: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.pagerDutyURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("%w: 构造 pagerduty 请求: %v", ErrBadTarget, err)
	}
	req.Header.Set("Content-Type", "application/json")
	raw, code, err := c.do(req)
	if err != nil {
		return "", err
	}
	if code != http.StatusAccepted {
		return "", fmt.Errorf("%w: pagerduty 回写 %d: %.200s", ErrUpstream, code, raw)
	}
	return fmt.Sprintf("pagerduty 备注已受理（HTTP %d）", code), nil
}

// validateEndpoint 端点必须是绝对 http(s) 地址（宿主仍负最终 SSRF 责任）。
func validateEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("%w: pagerduty 端点非法: %q", ErrBadTarget, raw)
	}
	return nil
}
