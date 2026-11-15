package imchan

// dingtalk.go — 钉钉通道：Stream 模式 WS 长连接（出站连接型，免公网回调——与
// 飞书 WS 同形态），机器人消息经 CALLBACK 订阅 topic /v1.0/im/bot/messages/get
// 投递；回投走消息自带的 sessionWebhook（钉钉机器人语义：每条入站消息携带过期
// 前可用的回投 URL——通道内按 subject 记忆，重启后等新消息刷新；群聊/单聊同路）。
//
// 依赖放行条件（飞书 v3.12.2 精确锁版同纪律）：dingtalk-stream-sdk-go v0.9.1
// 精确锁版。凭证：企业内部应用 ClientId(appKey)/ClientSecret(appSecret) 双字段。
//
// 已知边界（v1 如实声明）：sessionWebhook 记忆为进程内 map——多副本部署下回投
// 走各自记忆（钉钉消息恰投到持 webhook 的副本，语义自洽）；SDK 硬编码官方网关，
// e2e 走探活/解析/回投三层单测。SDK 的 StreamClient.Start 只完成建连即返回
//（读循环在后台 + AutoReconnect），本通道按 Channel 契约把它包成阻塞 Start：
// ctx 取消/Close 时显式 Close 连接。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/open-dingtalk/dingtalk-stream-sdk-go/client"
	"github.com/open-dingtalk/dingtalk-stream-sdk-go/payload"
)

// dingtalkTokenURL 钉钉企业内部应用 accessToken 端点（包级变量：测试换 httptest
// 假端点）。
var dingtalkTokenURL = "https://api.dingtalk.com/v1.0/oauth2/accessToken"

// DingTalkProbe 凭证探活：拿一次 appAccessToken（Start 前置快速失败 + 管理面
// test 端点共用）。
func DingTalkProbe(clientID, clientSecret string) error {
	if clientID == "" || clientSecret == "" {
		return fmt.Errorf("凭证缺失（client_id/client_secret 为空）")
	}
	body := fmt.Sprintf(`{"appKey":%q,"appSecret":%q}`, clientID, clientSecret)
	hc := &http.Client{Timeout: 10 * time.Second}
	resp, err := hc.Post(dingtalkTokenURL, "application/json", strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("钉钉不可达: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // 响应体只读一次
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return fmt.Errorf("钉钉响应读取失败: %w", err)
	}
	var out struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.AccessToken == "" {
		return fmt.Errorf("钉钉凭证被拒（HTTP %d）", resp.StatusCode)
	}
	return nil
}

// DingTalkChannel 钉钉通道实现（Stream 模式）。
type DingTalkChannel struct {
	id, clientID, clientSecret string

	mu        sync.Mutex
	webhooks  map[string]string // subject → sessionWebhook（入站消息到达时刷新）
	stream    *client.StreamClient
	connected bool
	closed    bool

	closeCh   chan struct{}
	closeOnce sync.Once
}

// NewDingTalkChannel 构造。
func NewDingTalkChannel(id, clientID, clientSecret string) *DingTalkChannel {
	return &DingTalkChannel{
		id: id, clientID: clientID, clientSecret: clientSecret,
		webhooks: map[string]string{}, closeCh: make(chan struct{}),
	}
}

// ID 通道实例 id。
func (d *DingTalkChannel) ID() string { return d.id }

// Kind 通道类型。
func (d *DingTalkChannel) Kind() string { return KindDingTalk }

// Connected Stream 连接已建立（SDK 后台自动重连期间保持真值；Close/Start 返回
// 后置假）。
func (d *DingTalkChannel) Connected() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.connected
}

// dingtalkMessage 钉钉机器人消息 data 载荷（CALLBACK topic 投递形态）。
type dingtalkMessage struct {
	ConversationID   string `json:"conversationId"`
	ConversationType string `json:"conversationType"` // "1"=单聊 "2"=群聊
	SenderStaffID    string `json:"senderStaffId"`
	SenderNick       string `json:"senderNick"`
	SessionWebhook   string `json:"sessionWebhook"`
	MsgID            string `json:"msgId"`
	Text             struct {
		Content string `json:"content"`
	} `json:"text"`
	MsgType string `json:"msgType"`
}

// Start 阻塞运行 Stream 长连接（ctx 取消退出；SDK 内置自动重连；探活先行显形
// 凭证问题）。SDK 的 Start 建连后即返回，这里补阻塞等待 + 生命周期关闭。
func (d *DingTalkChannel) Start(ctx context.Context, handler func(InboundMessage)) error {
	if handler == nil {
		return fmt.Errorf("imchan: dingtalk 通道 %s 的 handler 为空", d.id)
	}
	if d.isClosed() {
		return ErrClosed
	}
	if err := DingTalkProbe(d.clientID, d.clientSecret); err != nil {
		return fmt.Errorf("通道 %s 凭证探活失败: %w", d.id, err)
	}
	if d.isClosed() {
		return ErrClosed
	}
	cli := client.NewStreamClient(
		client.WithAppCredential(client.NewAppCredentialConfig(d.clientID, d.clientSecret)),
		client.WithSubscription("CALLBACK", "/v1.0/im/bot/messages/get", func(_ context.Context, df *payload.DataFrame) (*payload.DataFrameResponse, error) {
			if msg := d.parseDataFrame(df); msg != nil {
				msg.Channel = d.ID() // 平面路由键（缺省空串会被宿主判 nil 静默丢消息）
				handler(*msg)
			}
			return &payload.DataFrameResponse{Headers: df.Headers}, nil
		}),
	)
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return ErrClosed
	}
	d.stream = cli
	d.mu.Unlock()

	if err := cli.Start(ctx); err != nil {
		d.clearStream(cli)
		return err
	}
	d.mu.Lock()
	if !d.closed {
		d.connected = true
	}
	d.mu.Unlock()

	select {
	case <-ctx.Done():
		d.closeStream()
		return ctx.Err()
	case <-d.closeCh:
		d.closeStream()
		return ErrClosed
	}
}

// parseDataFrame SDK 帧 → 统一入站模型（text 消息；Subject=conversationId）。
// @提及占位由平台投递语义处理，这里只 trim。
func (d *DingTalkChannel) parseDataFrame(df *payload.DataFrame) *InboundMessage {
	if df == nil {
		return nil
	}
	var m dingtalkMessage
	if err := json.Unmarshal([]byte(df.Data), &m); err != nil {
		return nil
	}
	msg := messageFromDingTalk(&m)
	if msg == nil {
		return nil
	}
	if m.SessionWebhook != "" {
		d.mu.Lock()
		d.webhooks[m.ConversationID] = m.SessionWebhook
		d.mu.Unlock()
	}
	return msg
}

// ParseDingTalkMessage 原始 CALLBACK data JSON → 统一入站模型（无 webhook 记忆；
// 宿主自建帧路由时可复用）。非 text / 空正文 / 缺会话 id 返回 nil。
func ParseDingTalkMessage(data string) *InboundMessage {
	var m dingtalkMessage
	if err := json.Unmarshal([]byte(data), &m); err != nil {
		return nil
	}
	return messageFromDingTalk(&m)
}

func messageFromDingTalk(m *dingtalkMessage) *InboundMessage {
	if m.ConversationID == "" || m.MsgType != "text" {
		return nil
	}
	text := strings.TrimSpace(m.Text.Content)
	if text == "" {
		return nil
	}
	chatType := ChatP2P
	if m.ConversationType == "2" {
		chatType = ChatGroup
	}
	return &InboundMessage{
		Kind: KindDingTalk, Subject: m.ConversationID, ChatType: chatType,
		Sender: m.SenderStaffID, Text: text, MsgID: m.MsgID,
	}
}

// Send 回投文本：查 subject 的 sessionWebhook 记忆（钉钉机器人回投语义）；无
// 记忆=需新消息刷新（重启后首次回投前的已知边界，错误显形）。
func (d *DingTalkChannel) Send(subject, chatType, text string) error {
	_ = chatType // sessionWebhook 已绑定会话，群聊/单聊同路
	if strings.TrimSpace(text) == "" {
		return nil
	}
	d.mu.Lock()
	hook := d.webhooks[subject]
	closed := d.closed
	d.mu.Unlock()
	if closed {
		return ErrClosed
	}
	if hook == "" {
		return fmt.Errorf("钉钉回投缺 sessionWebhook（subject %s 无近期入站消息；发起新消息后重试）", subject)
	}
	body, err := json.Marshal(map[string]any{"msgtype": "text", "text": map[string]string{"content": text}})
	if err != nil {
		return err
	}
	hc := &http.Client{Timeout: 15 * time.Second}
	resp, err := hc.Post(hook, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck // 响应体只读一次
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return err
	}
	var out struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("钉钉回投响应非法（HTTP %d）", resp.StatusCode)
	}
	if out.ErrCode != 0 {
		return fmt.Errorf("钉钉回投失败: errcode=%d msg=%s", out.ErrCode, out.ErrMsg)
	}
	return nil
}

// Close 终止 Stream 连接并让 Start 返回 ErrClosed（幂等）。
func (d *DingTalkChannel) Close() error {
	d.closeOnce.Do(func() {
		d.mu.Lock()
		d.closed = true
		d.connected = false
		d.mu.Unlock()
		close(d.closeCh)
		d.closeStream()
	})
	return nil
}

func (d *DingTalkChannel) isClosed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.closed
}

// clearStream 清掉 Start 失败时的实例引用（不动他人已替换的实例）。
func (d *DingTalkChannel) clearStream(cli *client.StreamClient) {
	d.mu.Lock()
	if d.stream == cli {
		d.stream = nil
	}
	d.connected = false
	d.mu.Unlock()
}

// closeStream 关闭当前 SDK 连接并清引用。
func (d *DingTalkChannel) closeStream() {
	d.mu.Lock()
	cli := d.stream
	d.stream = nil
	d.connected = false
	d.mu.Unlock()
	if cli != nil {
		cli.Close()
	}
}

var (
	_ Channel = (*DingTalkChannel)(nil)
	_ Sender  = (*DingTalkChannel)(nil)
)
