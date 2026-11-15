package imchan

// wecom_aibot.go — 企业微信智能机器人通道：aibot WS 长连接（出站连接型，与
// 飞书/钉钉/QQ 同形态）收群/单聊文本消息 + markdown 回投。与 wecom（企业应用
// 回调+应用消息）并存：两形态各管一摊——智能机器人是群聊/单聊直加机器人的
// 新产品面。
//
// 官方 wecom-aibot-go-sdk v0.0.2 评估后弃用：Disconnect 与读协程对 m.ws 无锁
// 竞争（go test -race 实证，上游病）+ 零 tag 单维护者仓 + go.mod placeholder+
// replace 异味——协议仅四帧（aibot_subscribe 认证/ping 心跳/aibot_msg_callback
// 推送/aibot_send_msg 发送），按 QQ 通道同款工程形态手写：探活先行显形 + 断链
// 退避重连（连续认证失败达阈值终态显形，区别于 SDK 的静默放弃）+ 读超时看门狗 +
// 回投 req_id 应答匹配。零额外第三方依赖（gorilla/websocket 已直接消费）。
//
// 凭证：企微智能机器人 BotID/BotSecret 双字段。
//
// 已知边界（v1 如实声明）：①回投为 WS 主动发送（智能机器人支持群/单聊直发，无
// QQ 式被动窗口约束）；②同 BotID 服务端单连接互踢（新连接建立服务端断旧）——
// 多副本部署时长连接恰落一个副本，其余副本回投报未连接显形（QQ/钉钉同款边界）；
// ③文本长度不做本地截断，超长由服务侧 errcode 显形（官方上限口径未核实，不臆造
// 数值）。

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// 测试缝合点（qqTokenURL 同纪律）。
var (
	wecomAibotWSURL        = "wss://openws.work.weixin.qq.com" // 官方网关
	wecomAibotProbeTimeout = 8 * time.Second                   // 探活认证窗口
	wecomAibotMaxAuthFail  = 5                                 // 连续认证失败放弃阈值（终态显形）
)

// aibot 帧命令（官方协议字面量）。
const (
	aibotCmdSubscribe = "aibot_subscribe"
	aibotCmdPing      = "ping"
	aibotCmdCallback  = "aibot_msg_callback"
	aibotCmdSendMsg   = "aibot_send_msg"
)

// ErrAibotAuth 企微智能机器人认证失败（网关 errcode 非零）。
//
// 错误判定走 error 链（errors.Is），不靠文案关键词：文案一改（改措辞、换分隔符、
// 加前缀）判定就会静默失效，而失效形态是「认证失败不再被识别」→ 连续失败计数
// 不增长 → 退避重连一直重试到凭证被吊销也不终态显形。errcode 保留在消息里供
// 排障，但只供人读。
var ErrAibotAuth = errors.New("aibot 认证失败")

// aibotAuthError 造一个带 errcode 的认证错误（哨兵 + 上下文）。
func aibotAuthError(code int, msg string) error {
	return fmt.Errorf("%w: errcode=%d msg=%s", ErrAibotAuth, code, msg)
}

// aibotFrame 网关帧（官方协议：cmd/headers/body/errcode 形态）。
type aibotFrame struct {
	Cmd     string `json:"cmd,omitempty"`
	Headers struct {
		ReqID string `json:"req_id"`
	} `json:"headers"`
	Body    json.RawMessage `json:"body,omitempty"`
	ErrCode int             `json:"errcode,omitempty"`
	ErrMsg  string          `json:"errmsg,omitempty"`
}

// aibotReqID 请求序号（前缀路由依据：认证/心跳应答按 reqID 前缀识别）。
func aibotReqID(prefix string) string {
	buf := make([]byte, 6)
	_, _ = rand.Read(buf)
	return prefix + "-" + hex.EncodeToString(buf)
}

// WecomAibotProbe 凭证探活：真 WS 认证一次（管理面 + Start 前置快速失败——假
// 凭证秒级显形，不进重连循环）。
func WecomAibotProbe(botID, botSecret string) error {
	if botID == "" || botSecret == "" {
		return fmt.Errorf("凭证缺失（bot_id/bot_secret 为空）")
	}
	ctx, cancel := context.WithTimeout(context.Background(), wecomAibotProbeTimeout)
	defer cancel()
	deadline := time.Now().Add(wecomAibotProbeTimeout)
	conn, err := aibotDial(ctx, deadline)
	if err != nil {
		return fmt.Errorf("企微智能机器人网关不可达: %w", err)
	}
	defer conn.Close() //nolint:errcheck // 探活连接用毕即弃
	if err := aibotAuth(conn, botID, botSecret, deadline); err != nil {
		return fmt.Errorf("企微智能机器人认证失败: %w", err)
	}
	return nil
}

// aibotDial 拨号（测试假网关走 ws://；官方 wss 由默认 dialer TLS 承载）。
func aibotDial(ctx context.Context, deadline time.Time) (*websocket.Conn, error) {
	d := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	conn, _, err := d.DialContext(ctx, wecomAibotWSURL, nil)
	if err != nil {
		return nil, err
	}
	_ = conn.SetReadDeadline(deadline)
	return conn, nil
}

// aibotAuth 认证握手：发 aibot_subscribe 帧 → 同 reqID 应答 errcode 判定。
func aibotAuth(conn *websocket.Conn, botID, botSecret string, deadline time.Time) error {
	req := aibotFrame{Cmd: aibotCmdSubscribe}
	req.Headers.ReqID = aibotReqID(aibotCmdSubscribe)
	body, err := json.Marshal(map[string]string{"bot_id": botID, "secret": botSecret})
	if err != nil {
		return err
	}
	req.Body = body
	_ = conn.SetWriteDeadline(deadline)
	if err := conn.WriteJSON(req); err != nil {
		return fmt.Errorf("认证帧发送失败: %w", err)
	}
	for {
		var resp aibotFrame
		if err := conn.ReadJSON(&resp); err != nil {
			return fmt.Errorf("认证应答读取失败: %w", err)
		}
		if resp.Headers.ReqID != req.Headers.ReqID {
			continue // 非本请求应答（乱序推送）
		}
		if resp.ErrCode != 0 {
			return aibotAuthError(resp.ErrCode, resp.ErrMsg)
		}
		return nil
	}
}

// WecomAibotChannel 企业微信智能机器人通道实现。
type WecomAibotChannel struct {
	id, botID, botSecret string

	// clock/backoff 断链重连注入点（零值走单源默认）。
	clock   Clock
	backoff Backoff

	stateMu    sync.Mutex
	connected  bool
	closed     bool
	hbInterval time.Duration
	conn       *websocket.Conn // 当前连接快照（Send 写侧；随 runSession 生命周期挂摘）

	closeCh   chan struct{}
	closeOnce sync.Once

	writeMu sync.Mutex // 单连接写协程互斥（心跳协程/认证帧/回投经此串行）

	pendingMu sync.Mutex
	pending   map[string]chan aibotFrame // reqID → 应答槽（回投 ack 匹配）
}

// NewWecomAibotChannel 构造（凭证值由宿主解密直传——缺失经探活显形）。
func NewWecomAibotChannel(id, botID, botSecret string) *WecomAibotChannel {
	return &WecomAibotChannel{
		id: id, botID: botID, botSecret: botSecret,
		closeCh: make(chan struct{}),
		pending: map[string]chan aibotFrame{},
	}
}

// ID 通道实例 id。
func (w *WecomAibotChannel) ID() string { return w.id }

// Kind 通道类型。
func (w *WecomAibotChannel) Kind() string { return KindWecomAibot }

// Connected 认证完成且连接在位（断链即假——管理面运行态口径）。
func (w *WecomAibotChannel) Connected() bool {
	w.stateMu.Lock()
	defer w.stateMu.Unlock()
	return w.connected
}

// Start 阻塞运行 WS 长连接（ctx 取消退出）：探活先行显形 → 断链退避重连
// （Backoff 单源）——连续认证失败达阈值即终态返回错误（区别于 SDK 的静默放弃，
// 宿主状态面显形）。
func (w *WecomAibotChannel) Start(ctx context.Context, handler func(InboundMessage)) error {
	if handler == nil {
		return fmt.Errorf("imchan: wecom_aibot 通道 %s 的 handler 为空", w.id)
	}
	if w.isClosed() {
		return ErrClosed
	}
	if err := WecomAibotProbe(w.botID, w.botSecret); err != nil {
		return fmt.Errorf("通道 %s 凭证探活失败: %w", w.id, err)
	}
	if w.isClosed() {
		return ErrClosed
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-w.closeCh:
			cancel()
		case <-runCtx.Done():
		}
	}()

	authFails := 0
	r := Reconnecter{
		Backoff: w.backoff,
		Clock:   w.clock,
		Fatal: func(err error) error {
			if errors.Is(err, ErrAibotAuth) {
				authFails++
				if authFails >= wecomAibotMaxAuthFail {
					return fmt.Errorf("通道 %s 连续认证失败 %d 次（凭证被吊销？）: %w", w.id, authFails, err)
				}
			} else {
				authFails = 0
			}
			return nil
		},
	}
	err := r.Run(runCtx, func(sctx context.Context) error {
		if w.isClosed() {
			return ErrClosed
		}
		return w.runSession(sctx, handler)
	})
	if w.isClosed() {
		return ErrClosed
	}
	return err
}

// runSession 一次连接全生命周期：拨号 → 认证 → 心跳协程 + 读循环（看门狗/分发/
// 应答匹配）。返回即断链。
func (w *WecomAibotChannel) runSession(ctx context.Context, handler func(InboundMessage)) error {
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, wecomAibotWSURL, nil)
	if err != nil {
		return fmt.Errorf("网关拨号失败: %w", err)
	}
	w.stateMu.Lock()
	w.conn = conn
	w.stateMu.Unlock()
	defer func() {
		w.stateMu.Lock()
		if w.conn == conn {
			w.conn = nil
		}
		w.connected = false
		w.stateMu.Unlock()
		conn.Close() //nolint:errcheck // 断链关闭，读侧已持有真实错误
	}()

	// ctx 取消立即砸连接解除读阻塞（Close 幂等安全）。
	sessCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-sessCtx.Done():
			_ = conn.Close()
		case <-stop:
		}
	}()

	hb := 30 * time.Second
	if err := w.handshake(conn); err != nil {
		return err
	}
	w.stateMu.Lock()
	w.connected = true
	w.hbInterval = hb
	w.stateMu.Unlock()

	// 心跳协程（写侧经 writeMu 串行；写失败=断链，cancel 收敛）。
	tick := time.NewTicker(hb)
	defer tick.Stop()
	go func() {
		for {
			select {
			case <-sessCtx.Done():
				return
			case <-tick.C:
				ping := aibotFrame{Cmd: aibotCmdPing}
				ping.Headers.ReqID = aibotReqID(aibotCmdPing)
				if err := w.writeFrame(conn, ping); err != nil {
					cancel()
					return
				}
			}
		}
	}()

	// 读超时看门狗：2.5 拍无任何下行（心跳 ack/推送）判僵死断链。
	for {
		_ = conn.SetReadDeadline(time.Now().Add(5 * hb / 2))
		var f aibotFrame
		if err := conn.ReadJSON(&f); err != nil {
			return fmt.Errorf("网关读断: %w", err)
		}
		switch {
		case strings.HasPrefix(f.Headers.ReqID, aibotCmdPing):
			// 心跳 ack
		case strings.HasPrefix(f.Headers.ReqID, aibotCmdSubscribe):
			// 认证应答（重连会话期不应出现；errcode 非零按认证失败上报）
			if f.ErrCode != 0 {
				return aibotAuthError(f.ErrCode, f.ErrMsg)
			}
		case f.Cmd == aibotCmdCallback:
			w.dispatch(f, handler)
		default:
			w.resolvePending(f)
		}
		if err := sessCtx.Err(); err != nil {
			return err
		}
	}
}

// handshake 认证握手（运行会话期；应答按 reqID 匹配）。
func (w *WecomAibotChannel) handshake(conn *websocket.Conn) error {
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	if err := aibotAuth(conn, w.botID, w.botSecret, time.Now().Add(15*time.Second)); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Time{})
	return nil
}

// dispatch CALLBACK 帧分发：仅 text 消息归一投递（纯图/事件不惊动诊断）。
func (w *WecomAibotChannel) dispatch(f aibotFrame, handler func(InboundMessage)) {
	var msg struct {
		MsgID    string `json:"msgid"`
		ChatID   string `json:"chatid"`
		ChatType string `json:"chattype"`
		MsgType  string `json:"msgtype"`
		From     struct {
			UserID string `json:"userid"`
		} `json:"from"`
		Text struct {
			Content string `json:"content"`
		} `json:"text"`
	}
	if err := json.Unmarshal(f.Body, &msg); err != nil || msg.MsgID == "" || msg.MsgType != "text" {
		return
	}
	chatType := ChatP2P
	if strings.EqualFold(strings.TrimSpace(msg.ChatType), ChatGroup) {
		chatType = ChatGroup
	}
	subject := strings.TrimSpace(msg.ChatID)
	if subject == "" {
		subject = strings.TrimSpace(msg.From.UserID)
	}
	text := strings.TrimSpace(msg.Text.Content)
	if subject == "" || text == "" {
		return
	}
	handler(InboundMessage{
		Channel: w.id, // 平面路由键（缺省空串会被宿主判 nil 静默丢消息）
		Kind:    KindWecomAibot, Subject: subject, ChatType: chatType,
		Sender: strings.TrimSpace(msg.From.UserID), Text: text, MsgID: msg.MsgID,
	})
}

// Send markdown 回投：aibot_send_msg 帧 chat_type 1/2 双档 + reqID 应答匹配
// （智能机器人支持直发，无 QQ 式被动窗口）；ack errcode 非零显形。
func (w *WecomAibotChannel) Send(subject, chatType, text string) error {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	if !w.Connected() {
		return fmt.Errorf("企微智能机器人通道未连接（断链重连中；该轮回投失败显形）")
	}
	chatT := 1 // 单聊
	if chatType == ChatGroup {
		chatT = 2
	}
	req := aibotFrame{Cmd: aibotCmdSendMsg}
	req.Headers.ReqID = aibotReqID(aibotCmdSendMsg)
	body, err := json.Marshal(map[string]any{
		"chatid": subject, "msgtype": "markdown", "chat_type": chatT,
		"markdown": map[string]string{"content": text},
	})
	if err != nil {
		return err
	}
	req.Body = body

	ack := make(chan aibotFrame, 1)
	w.pendingMu.Lock()
	w.pending[req.Headers.ReqID] = ack
	w.pendingMu.Unlock()
	defer func() {
		w.pendingMu.Lock()
		delete(w.pending, req.Headers.ReqID)
		w.pendingMu.Unlock()
	}()

	w.writeMu.Lock()
	conn := w.activeConn()
	if conn == nil {
		w.writeMu.Unlock()
		return fmt.Errorf("企微智能机器人通道未连接（连接已断开）")
	}
	werr := conn.WriteJSON(req)
	w.writeMu.Unlock()
	if werr != nil {
		return fmt.Errorf("企微智能机器人回投发送失败: %w", werr)
	}
	select {
	case resp := <-ack:
		if resp.ErrCode != 0 {
			return fmt.Errorf("企微智能机器人回投被拒: errcode=%d msg=%s", resp.ErrCode, resp.ErrMsg)
		}
		return nil
	case <-w.closeCh:
		return ErrClosed
	case <-time.After(15 * time.Second):
		return fmt.Errorf("企微智能机器人回投应答超时（15s）")
	}
}

// resolvePending 回投应答匹配（reqID → 槽）。
func (w *WecomAibotChannel) resolvePending(f aibotFrame) {
	w.pendingMu.Lock()
	ch, ok := w.pending[f.Headers.ReqID]
	w.pendingMu.Unlock()
	if ok {
		select {
		case ch <- f:
		default:
		}
	}
}

// writeFrame 帧写出（写协程互斥）。
func (w *WecomAibotChannel) writeFrame(conn *websocket.Conn, f aibotFrame) error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	return conn.WriteJSON(f)
}

// activeConn 当前连接快照（Send 写侧用；连接态随 runSession 生命周期）。
func (w *WecomAibotChannel) activeConn() *websocket.Conn {
	w.stateMu.Lock()
	defer w.stateMu.Unlock()
	return w.conn
}

// Close 终止网关连接并让 Start/等待中的回投返回 ErrClosed（幂等）。
func (w *WecomAibotChannel) Close() error {
	w.closeOnce.Do(func() {
		w.stateMu.Lock()
		w.closed = true
		w.connected = false
		conn := w.conn
		w.stateMu.Unlock()
		close(w.closeCh)
		if conn != nil {
			_ = conn.Close()
		}
	})
	return nil
}

func (w *WecomAibotChannel) isClosed() bool {
	w.stateMu.Lock()
	defer w.stateMu.Unlock()
	return w.closed
}

// isAibotAuthErr 认证类错误判定（读 error 链的哨兵，不看文案）。
func isAibotAuthErr(err error) bool {
	return err != nil && errors.Is(err, ErrAibotAuth)
}

var (
	_ Channel = (*WecomAibotChannel)(nil)
	_ Sender  = (*WecomAibotChannel)(nil)
)
