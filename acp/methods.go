package acp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// handleInitialize ACP 握手：protocolVersion=1 + 不支持 loadSession + 空
// promptCapabilities（不声明 image/audio/embeddedContext）+ agentCard。
func (b *Bridge) handleInitialize(context.Context, json.RawMessage) (any, []Notification, error) {
	return map[string]any{
		"protocolVersion": ProtocolVersion,
		"agentCapabilities": map[string]any{
			"loadSession":        false,
			"promptCapabilities": map[string]bool{},
		},
		"agentCard": map[string]any{
			"name":        b.opts.agentName(),
			"description": b.opts.agentDescription(),
		},
		"authMethods": nil,
	}, nil, nil
}

// handleSessionNew 派发 ACP 会话号；宿主会话在首个 prompt 惰性创建
// （与 bianque 桥一致：IDE 建会话不代表用户已发问，不空烧引擎）。
func (b *Bridge) handleSessionNew(context.Context, json.RawMessage) (any, []Notification, error) {
	b.nextID++
	id := fmt.Sprintf("acp-%d-%d", time.Now().Unix(), b.nextID)
	b.sessions[id] = ""
	return map[string]any{"sessionId": id}, nil, nil
}

// handleSessionPrompt 一轮问答：首问惰性建宿主会话（钉专家等由 Host 配置），
// 续问投递 input；终态定稿报告以单条 agent_message_chunk 通知承载，响应
// stopReason=end_of_turn。
func (b *Bridge) handleSessionPrompt(ctx context.Context, params json.RawMessage) (any, []Notification, error) {
	var p struct {
		SessionID string          `json:"sessionId"`
		Prompt    json.RawMessage `json:"prompt"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, nil, Errorf(CodeInvalidParams, "invalid params: %v", err)
	}
	if strings.TrimSpace(p.SessionID) == "" {
		return nil, nil, Errorf(CodeInvalidParams, "sessionId 不能为空")
	}
	text := promptText(p.Prompt)
	if strings.TrimSpace(text) == "" {
		return nil, nil, Errorf(CodeInvalidParams, "prompt 不能为空")
	}
	report, err := b.prompt(ctx, p.SessionID, text)
	if err != nil {
		return nil, nil, err
	}
	return map[string]any{"stopReason": "end_of_turn"}, []Notification{{
		JSONRPC: "2.0",
		Method:  "session/update",
		Params: map[string]any{
			"sessionId": p.SessionID,
			"update": map[string]any{
				"sessionUpdate": "agent_message_chunk",
				"content":       map[string]any{"type": "text", "text": report},
			},
		},
	}}, nil
}

// prompt 首问建会话、续问投递、等终态取定稿报告。
func (b *Bridge) prompt(ctx context.Context, acpSessionID, text string) (string, error) {
	if b.host == nil {
		return "", Errorf(CodeInternalError, "host 未配置")
	}
	hostSessionID := b.sessions[acpSessionID]
	if hostSessionID == "" {
		created, err := b.host.CreateSession(ctx, SessionRequest{Input: text})
		if err != nil {
			return "", fmt.Errorf("创建会话失败: %w", err)
		}
		if strings.TrimSpace(created) == "" {
			return "", errors.New("创建会话失败: host 未返回会话号")
		}
		b.sessions[acpSessionID] = created
		hostSessionID = created
	} else if err := b.host.SendInput(ctx, hostSessionID, text); err != nil {
		return "", fmt.Errorf("追问投递失败: %w", err)
	}
	res, err := b.host.WaitTerminal(ctx, hostSessionID)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(res.FinalReport) != "" {
		return res.FinalReport, nil
	}
	if !res.Succeeded {
		status := res.Status
		if status == "" {
			status = "unknown"
		}
		return "", fmt.Errorf("会话终态 %s 且无定稿报告", status)
	}
	return "（会话成功但无定稿报告文本）", nil
}

// promptText prompt 双形态抽取：ACP 标准 content block 数组只取 text 部分，
// 简写字符串原样；单 block 对象也接受。其余形态=空串（交给调用方回 -32602）。
func promptText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &parts); err == nil {
		var sb strings.Builder
		for _, p := range parts {
			if p.Type == "text" || p.Type == "" {
				sb.WriteString(p.Text)
			}
		}
		return sb.String()
	}
	var block struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &block); err == nil && (block.Type == "text" || block.Type == "") {
		return block.Text
	}
	return ""
}
