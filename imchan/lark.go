package imchan

// lark.go — 飞书通道：WS 长连接收消息 + im/v1 回投——「出站连接型」首个真实
// 通道（无公网回调/免证书免验签）。凭证值由宿主从凭证平面解密直传；依赖放行
// 条件：v3.12.2 精确锁版 + gorilla/websocket 钉版（GO-2026-6278，上游声明
// ≥v1.5.3 后可移除）。
//
// 为什么用官方 SDK 而不是手写：飞书 WS 帧是 protobuf 编码 + 租约/心跳/分片
// 重组状态机（pbbp2.Frame），手写要复制一整层协议且无法离线验证；QQ/aibot 的
// JSON 帧协议才适合手写。SDK 类型只在 Start 内部流转，除 ParseLarkMessage
//（宿主自定义 dispatcher 场景可复用）外不向宿主泄漏。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	lark "github.com/larksuite/oapi-sdk-go/v3"
	larkdispatcher "github.com/larksuite/oapi-sdk-go/v3/event/dispatcher"
	larkim "github.com/larksuite/oapi-sdk-go/v3/service/im/v1"
	larkws "github.com/larksuite/oapi-sdk-go/v3/ws"
)

// larkTokenURL 飞书自建应用 token 端点（包级变量：测试换 httptest 假端点）。
var larkTokenURL = "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal"

// LarkProbe 凭证探活：拿一次 app_access_token（Start 前置快速失败 + 管理面
// test 端点共用）。凭证无效/网络不通返回带原因的错误。
func LarkProbe(appID, appSecret string) error {
	if appID == "" || appSecret == "" {
		return fmt.Errorf("凭证缺失（app_id/app_secret 为空）")
	}
	body := fmt.Sprintf(`{"app_id":%q,"app_secret":%q}`, appID, appSecret)
	hc := &http.Client{Timeout: 10 * time.Second}
	resp, err := hc.Post(larkTokenURL, "application/json", strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("飞书不可达: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // 响应体只读一次
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return fmt.Errorf("飞书响应读取失败: %w", err)
	}
	var out struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("飞书响应非法（HTTP %d）", resp.StatusCode)
	}
	if out.Code != 0 {
		return fmt.Errorf("飞书凭证被拒: code=%d msg=%s", out.Code, out.Msg)
	}
	return nil
}

// LarkChannel 飞书通道实现。
type LarkChannel struct {
	id, appID, appSecret string

	mu        sync.Mutex
	client    *lark.Client
	ws        *larkws.Client
	connected bool
	closed    bool

	closeCh   chan struct{}
	closeOnce sync.Once
}

// NewLarkChannel 构造（凭证值由宿主从凭证平面解密直传——缺失时 Start 探活
// 快速显形失败，不静默）。
func NewLarkChannel(id, appID, appSecret string) *LarkChannel {
	return &LarkChannel{id: id, appID: appID, appSecret: appSecret, closeCh: make(chan struct{})}
}

// ID 通道实例 id。
func (l *LarkChannel) ID() string { return l.id }

// Kind 通道类型。
func (l *LarkChannel) Kind() string { return KindLark }

// Connected WS 会话就绪（SDK OnReady 置真、OnDisconnected 置假）。
func (l *LarkChannel) Connected() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.connected
}

// Start 阻塞运行 WS 长连接（ctx 取消退出；SDK 内置自动重连与心跳）。先探活
// 凭证（假凭证/网络问题秒级显形，不进 SDK 重连黑洞）。
func (l *LarkChannel) Start(ctx context.Context, handler func(InboundMessage)) error {
	if handler == nil {
		return fmt.Errorf("imchan: lark 通道 %s 的 handler 为空", l.id)
	}
	if l.isClosed() {
		return ErrClosed
	}
	if err := LarkProbe(l.appID, l.appSecret); err != nil {
		return fmt.Errorf("通道 %s 凭证探活失败: %w", l.id, err)
	}
	if l.isClosed() {
		return ErrClosed
	}
	// 无超时的 DefaultClient 在网络黑洞下会卡死 Send → 宿主 worker 永久阻塞。
	// 30s 足够覆盖飞书 API 往返。
	client := lark.NewClient(l.appID, l.appSecret, lark.WithHttpClient(&http.Client{Timeout: 30 * time.Second}))
	dispatcher := larkdispatcher.NewEventDispatcher("", "").
		OnP2MessageReceiveV1(func(_ context.Context, event *larkim.P2MessageReceiveV1) error {
			if msg := l.ParseLarkMessage(event); msg != nil {
				msg.Channel = l.ID() // 平面路由键（缺省空串会被宿主判 nil 静默丢消息）
				handler(*msg)
			}
			return nil
		})
	cli := larkws.NewClient(l.appID, l.appSecret, larkws.WithEventHandler(dispatcher))
	cli.SetOnReady(func() { l.setConnected(true) })
	cli.SetOnReconnected(func() { l.setConnected(true) })
	cli.SetOnDisconnected(func() { l.setConnected(false) })

	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return ErrClosed
	}
	l.client, l.ws = client, cli
	l.mu.Unlock()

	err := cli.Start(ctx)

	l.mu.Lock()
	l.connected = false
	l.client = nil
	l.ws = nil
	l.mu.Unlock()
	if l.isClosed() {
		return ErrClosed
	}
	return err
}

// Close 终止 WS 会话（幂等）。SDK 的 Close 非阻塞；Start 会随后返回 ErrClosed。
func (l *LarkChannel) Close() error {
	l.closeOnce.Do(func() {
		l.mu.Lock()
		l.closed = true
		l.connected = false
		ws := l.ws
		l.mu.Unlock()
		close(l.closeCh)
		if ws != nil {
			ws.Close()
		}
	})
	return nil
}

func (l *LarkChannel) isClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed
}

func (l *LarkChannel) setConnected(v bool) {
	l.mu.Lock()
	if !l.closed {
		l.connected = v
	}
	l.mu.Unlock()
}

// mentionToken 飞书文本中的 @占位（@_user_1 形态）。
var mentionToken = regexp.MustCompile(`@_user_\d+`)

// ParseLarkMessage 事件 → 统一入站模型：收 text/image/file（附件随消息带惰性
// 下载闭包——飞书 message resource 按 message_id+file_key 现取，回调线程零 IO）；
// Subject=chat_id（私聊与群聊统一回投锚点）；@提及占位剥除。
// 群聊 @门由飞书平台投递语义兜底：群内仅 @机器人 的消息触发 receive 事件（单聊
// 全量投递）——平台行为变更时在此补显式 mention 匹配（event.Message.Mentions
// 可取被提者 open_id）。
func (l *LarkChannel) ParseLarkMessage(event *larkim.P2MessageReceiveV1) *InboundMessage {
	if event == nil || event.Event == nil || event.Event.Message == nil {
		return nil
	}
	m := event.Event.Message
	if m.MessageType == nil || m.Content == nil || m.ChatId == nil {
		return nil
	}
	chatType := ChatP2P
	if m.ChatType != nil && *m.ChatType == ChatGroup {
		chatType = ChatGroup
	}
	sender := ""
	if event.Event.Sender != nil && event.Event.Sender.SenderId != nil && event.Event.Sender.SenderId.OpenId != nil {
		sender = *event.Event.Sender.SenderId.OpenId
	}
	msgID := ""
	if m.MessageId != nil {
		msgID = *m.MessageId
	}
	msg := &InboundMessage{
		Kind: KindLark, Subject: *m.ChatId, ChatType: chatType,
		Sender: sender, MsgID: msgID,
	}
	switch *m.MessageType {
	case "text":
		var content struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal([]byte(*m.Content), &content); err != nil {
			return nil
		}
		msg.Text = strings.TrimSpace(mentionToken.ReplaceAllString(content.Text, ""))
		if msg.Text == "" {
			return nil // 纯 @机器人 无正文：不惊动诊断
		}
	case "image":
		var content struct {
			ImageKey string `json:"image_key"`
		}
		if err := json.Unmarshal([]byte(*m.Content), &content); err != nil || content.ImageKey == "" {
			return nil
		}
		msg.Files = []InboundFile{{
			Name: "lark-image-" + shortID(msgID) + ".png", MimeType: "image/png",
			Open: l.openResource(msgID, content.ImageKey, "image"),
		}}
	case "file":
		var content struct {
			FileKey  string `json:"file_key"`
			FileName string `json:"file_name"`
		}
		if err := json.Unmarshal([]byte(*m.Content), &content); err != nil || content.FileKey == "" {
			return nil
		}
		name := content.FileName
		if name == "" {
			name = "lark-file-" + shortID(msgID)
		}
		msg.Files = []InboundFile{{
			Name: name,
			Open: l.openResource(msgID, content.FileKey, "file"),
		}}
	default:
		return nil // 富媒体/系统消息忽略
	}
	return msg
}

// openResource 飞书 message resource 惰性下载闭包（宿主处理阶段调用）。
func (l *LarkChannel) openResource(messageID, fileKey, resType string) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) {
		l.mu.Lock()
		client := l.client
		l.mu.Unlock()
		if client == nil {
			return nil, fmt.Errorf("飞书通道未启动")
		}
		req := larkim.NewGetMessageResourceReqBuilder().
			MessageId(messageID).FileKey(fileKey).Type(resType).Build()
		resp, err := client.Im.MessageResource.Get(context.Background(), req)
		if err != nil {
			return nil, err
		}
		if !resp.Success() {
			return nil, fmt.Errorf("飞书资源下载失败: code=%d msg=%s", resp.Code, resp.Msg)
		}
		return io.NopCloser(resp.File), nil
	}
}

// shortID 消息 id 截短（附件命名去噪）。
func shortID(msgID string) string {
	if len(msgID) > 12 {
		return msgID[:12]
	}
	if msgID == "" {
		return "anon"
	}
	return msgID
}

// Send 经 im/v1 以 chat_id 回投文本（text 消息体）。
func (l *LarkChannel) Send(subject, chatType, text string) error {
	_ = chatType // 飞书回投统一按 chat_id，p2p/group 同路
	l.mu.Lock()
	client := l.client
	closed := l.closed
	l.mu.Unlock()
	if closed {
		return ErrClosed
	}
	if client == nil {
		return fmt.Errorf("飞书通道未启动")
	}
	content, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		return err
	}
	req := larkim.NewCreateMessageReqBuilder().
		ReceiveIdType("chat_id").
		Body(larkim.NewCreateMessageReqBodyBuilder().
			ReceiveId(subject).
			MsgType("text").
			Content(string(content)).
			Build()).
		Build()
	resp, err := client.Im.Message.Create(context.Background(), req)
	if err != nil {
		return err
	}
	if !resp.Success() {
		return fmt.Errorf("飞书回投失败: code=%d msg=%s", resp.Code, resp.Msg)
	}
	return nil
}

var (
	_ Channel = (*LarkChannel)(nil)
	_ Sender  = (*LarkChannel)(nil)
)
