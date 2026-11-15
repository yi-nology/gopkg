package tickets

import (
	"context"
	"fmt"
	"net/http"
	"time"
	"unicode/utf8"
)

// PagerDutyAction Events API v2 事件动作。
type PagerDutyAction string

const (
	// PagerDutyTrigger 触发/更新事件（需 summary + source）。
	PagerDutyTrigger PagerDutyAction = "trigger"
	// PagerDutyAcknowledge 确认事件（需 dedup_key）。
	PagerDutyAcknowledge PagerDutyAction = "acknowledge"
	// PagerDutyResolve 解决事件（需 dedup_key）。
	PagerDutyResolve PagerDutyAction = "resolve"
)

// PagerDuty 严重度词表（Events v2 固定四档）。
const (
	PagerDutySeverityCritical = "critical"
	PagerDutySeverityError    = "error"
	PagerDutySeverityWarning  = "warning"
	PagerDutySeverityInfo     = "info"
)

// PagerDutyPayload 事件载荷（trigger 必填 summary/source；其余可选）。
type PagerDutyPayload struct {
	Summary   string `json:"summary"`
	Source    string `json:"source"`
	Severity  string `json:"severity,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
	Component string `json:"component,omitempty"`
	Group     string `json:"group,omitempty"`
	Class     string `json:"class,omitempty"`
}

// PagerDutyLink 事件关联链接。
type PagerDutyLink struct {
	Href string `json:"href"`
	Text string `json:"text"`
}

// PagerDutyImage 事件关联图片。
type PagerDutyImage struct {
	Src string `json:"src"`
	Alt string `json:"alt"`
}

// PagerDutyEvent 待发送事件。CustomDetails 放诊断正文等结构化细节
// （仅 trigger 支持；acknowledge/resolve 只带 dedup_key）。
type PagerDutyEvent struct {
	Action        PagerDutyAction
	DedupKey      string
	Payload       PagerDutyPayload
	CustomDetails map[string]any
	Links         []PagerDutyLink
	Images        []PagerDutyImage
}

// PagerDutyResult Events API v2 响应。
type PagerDutyResult struct {
	Status   string `json:"status"`
	Message  string `json:"message"`
	DedupKey string `json:"dedup_key"`
}

// pagerDutyWire Events API v2 请求体（routing_key 由凭证面每请求注入）。
type pagerDutyWire struct {
	RoutingKey  string            `json:"routing_key"`
	EventAction PagerDutyAction   `json:"event_action"`
	DedupKey    string            `json:"dedup_key,omitempty"`
	Payload     *pagerDutyPayload `json:"payload,omitempty"`
	Links       []PagerDutyLink   `json:"links,omitempty"`
	Images      []PagerDutyImage  `json:"images,omitempty"`
}

type pagerDutyPayload struct {
	Summary       string         `json:"summary"`
	Source        string         `json:"source"`
	Severity      string         `json:"severity,omitempty"`
	Timestamp     string         `json:"timestamp,omitempty"`
	Component     string         `json:"component,omitempty"`
	Group         string         `json:"group,omitempty"`
	Class         string         `json:"class,omitempty"`
	CustomDetails map[string]any `json:"custom_details,omitempty"`
}

// SendPagerDutyEvent 发送 Events API v2 事件（POST /v2/enqueue）。
// routing key 来自 [CredentialProvider]；事件校验 fail-closed：
//   - action 必须是 trigger/acknowledge/resolve；
//   - trigger 必须有 summary/source（source 可由 Target.Source 兜底），
//     summary ≤ 1024 字符、severity 属于四档（空 = error）；
//   - acknowledge/resolve 必须有 dedup_key，且只带 dedup_key（载荷/
//     自定义细节/链接/图片一律拒绝，不静默丢弃）；
//   - dedup_key ≤ 255 字符；timestamp 非空必须是 RFC3339。
func (c *Client) SendPagerDutyEvent(ctx context.Context, ev PagerDutyEvent) (PagerDutyResult, error) {
	if err := c.ensure(AdapterPagerDuty); err != nil {
		return PagerDutyResult{}, err
	}
	return c.sendPagerDutyEvent(ctx, ev)
}

func (c *Client) sendPagerDutyEvent(ctx context.Context, ev PagerDutyEvent) (PagerDutyResult, error) {
	var out PagerDutyResult
	if err := validatePagerDutyEvent(c.source, ev); err != nil {
		return out, err
	}
	creds, err := c.credentials(ctx)
	if err != nil {
		return out, err
	}
	if creds.RoutingKey == "" {
		return out, fmt.Errorf("%w: pagerduty routing key 为空", ErrMissingCredentials)
	}

	payload := ev.Payload
	if payload.Source == "" {
		payload.Source = c.source
	}
	if payload.Severity == "" {
		payload.Severity = PagerDutySeverityError
	}
	wire := pagerDutyWire{
		RoutingKey:  creds.RoutingKey,
		EventAction: ev.Action,
		DedupKey:    ev.DedupKey,
		Links:       ev.Links,
		Images:      ev.Images,
	}
	if ev.Action == PagerDutyTrigger {
		wire.Payload = &pagerDutyPayload{
			Summary:       payload.Summary,
			Source:        payload.Source,
			Severity:      payload.Severity,
			Timestamp:     payload.Timestamp,
			Component:     payload.Component,
			Group:         payload.Group,
			Class:         payload.Class,
			CustomDetails: ev.CustomDetails,
		}
	}
	err = c.roundTrip(ctx, http.MethodPost, c.pagerDutyEndpoint("enqueue"), wire, &out, nil)
	if err != nil {
		return PagerDutyResult{}, err
	}
	if out.Status != "success" {
		return PagerDutyResult{}, fmt.Errorf("%w: PagerDuty status=%q message=%q", ErrBadResponse, out.Status, out.Message)
	}
	if out.DedupKey == "" {
		return PagerDutyResult{}, fmt.Errorf("%w: PagerDuty 响应缺少 dedup_key", ErrBadResponse)
	}
	return out, nil
}

func validatePagerDutyEvent(defaultSource string, ev PagerDutyEvent) error {
	switch ev.Action {
	case PagerDutyTrigger, PagerDutyAcknowledge, PagerDutyResolve:
	default:
		return fmt.Errorf("%w: 未知 event_action %q", ErrInvalidArgument, ev.Action)
	}
	if utf8.RuneCountInString(ev.DedupKey) > MaxPagerDutyDedupKeyLen {
		return fmt.Errorf("%w: dedup_key 超过 %d 字符", ErrInvalidArgument, MaxPagerDutyDedupKeyLen)
	}
	if ev.Action != PagerDutyTrigger {
		if ev.DedupKey == "" {
			return fmt.Errorf("%w: %s 必须提供 dedup_key", ErrInvalidArgument, ev.Action)
		}
		if ev.Payload != (PagerDutyPayload{}) || ev.CustomDetails != nil ||
			len(ev.Links) != 0 || len(ev.Images) != 0 {
			return fmt.Errorf("%w: %s 只接受 dedup_key（细节请用 trigger）", ErrInvalidArgument, ev.Action)
		}
		return nil
	}

	if ev.Payload.Summary == "" {
		return fmt.Errorf("%w: trigger 的 summary 为空", ErrInvalidArgument)
	}
	if utf8.RuneCountInString(ev.Payload.Summary) > MaxPagerDutySummaryLen {
		return fmt.Errorf("%w: summary 超过 %d 字符", ErrInvalidArgument, MaxPagerDutySummaryLen)
	}
	if ev.Payload.Source == "" && defaultSource == "" {
		return fmt.Errorf("%w: trigger 的 source 为空（Target.Source 也未配置）", ErrInvalidArgument)
	}
	if ev.Payload.Severity != "" {
		switch ev.Payload.Severity {
		case PagerDutySeverityCritical, PagerDutySeverityError, PagerDutySeverityWarning, PagerDutySeverityInfo:
		default:
			return fmt.Errorf("%w: 未知 severity %q", ErrInvalidArgument, ev.Payload.Severity)
		}
	}
	if ev.Payload.Timestamp != "" {
		if _, err := time.Parse(time.RFC3339, ev.Payload.Timestamp); err != nil {
			return fmt.Errorf("%w: timestamp 必须 RFC3339: %v", ErrInvalidArgument, err)
		}
	}
	for i, link := range ev.Links {
		if link.Href == "" {
			return fmt.Errorf("%w: links[%d].href 为空", ErrInvalidArgument, i)
		}
	}
	for i, img := range ev.Images {
		if img.Src == "" {
			return fmt.Errorf("%w: images[%d].src 为空", ErrInvalidArgument, i)
		}
	}
	return nil
}
