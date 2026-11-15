package imchan

// qq.go — QQ 开放平台机器人通道：群/单聊 AT 消息经官方 WS 网关（wss）长连接
// 投递——「出站连接型」与飞书/钉钉同形态（免公网回调面）。回投走 v2 群/单聊
// 消息 API 的被动回复语义（带最近入站 msg_id + msg_seq 递增；QQ 群/单聊无
// webhook 形态，主动消息需平台额度）。
//
// 网关循环手写（gorilla/websocket）而非官方 botgo SDK 会话管理：其 ws 管理器
// 面向频道 intents，群/单聊（C2C_GROUP_AT_MESSAGES=1<<25）不在覆盖面。token/
// 网关/API 三端点包级变量缝合，单测假端点/假网关全链覆盖。
//
// 凭证：QQ 开放平台机器人 AppID/AppSecret 双字段。
//
// 已知边界（v1 如实声明）：①群/单聊回投受 QQ 被动窗口限制（msg_id 时效约
// 5 分钟，同 id 上限 5 条）——诊断超窗时 QQ 侧拒收、错误显形；文本 1500 字
// 截断。②同 AppID 网关单连接互踢：多副本部署时长连接恰落一个副本（入站
// 自洽），其他副本回投因无 msg_id 记忆显形失败——钉钉 sessionWebhook 记忆
// 同款边界。③频道（guild）AT 消息不接：本平面的 chat 形态只有 p2p/group
// 两种 chatType，频道回投需第三种贯穿宿主平面，无场景不扩。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// 测试缝合点：单测换假端点/假网关（生产恒官方）。
var (
	qqTokenURL = "https://bots.qq.com/app/getAppAccessToken" // 应用 access token
	qqAPIBase  = "https://api.sgroup.qq.com"                 // v2 消息 API + /gateway
)

// QQProbe 凭证探活：拿一次 app access token（管理面 + Start 前置快速失败）。
func QQProbe(appID, appSecret string) error {
	if appID == "" || appSecret == "" {
		return fmt.Errorf("凭证缺失（app_id/app_secret 为空）")
	}
	_, err := qqFetchToken(appID, appSecret)
	return err
}

// qqFetchToken 换取 app access token（POST getAppAccessToken → {access_token}）。
func qqFetchToken(appID, appSecret string) (string, error) {
	body := fmt.Sprintf(`{"appId":%q,"clientSecret":%q}`, appID, appSecret)
	hc := &http.Client{Timeout: 10 * time.Second}
	resp, err := hc.Post(qqTokenURL, "application/json", strings.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("QQ 开放平台不可达: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // 响应体只读一次
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", fmt.Errorf("QQ 响应读取失败: %w", err)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		Code        int    `json:"code"`
		Message     string `json:"message"`
	}
	_ = json.Unmarshal(raw, &out) // 成功形态无 code 字段；失败形态解析出 code/message
	if out.AccessToken == "" {
		if out.Code != 0 || out.Message != "" {
			return "", fmt.Errorf("QQ 凭证被拒: code=%d msg=%s", out.Code, out.Message)
		}
		return "", fmt.Errorf("QQ 凭证被拒（HTTP %d）", resp.StatusCode)
	}
	return out.AccessToken, nil
}

// QQChannel QQ 开放平台机器人通道实现。
type QQChannel struct {
	id, appID, appSecret string

	// clock/backoff 断链重连注入点（零值走单源默认：RealClock + 1s→60s）。
	clock   Clock
	backoff Backoff
	// gatewayURL 非空=跳过 /gateway 直连此 URL（单测假网关注入）。
	gatewayURL string

	// token 缓存（并发回投单飞；失败即重取）。
	tokMu    sync.Mutex
	token    string
	tokenExp time.Time

	stateMu   sync.Mutex
	conn      *websocket.Conn
	connected bool
	closed    bool
	sessionID string // 网关会话（断链 RESUME 续约；INVALID_SESSION 弃约改 Identify）
	lastSeq   uint32

	closeCh   chan struct{}
	closeOnce sync.Once

	writeMu sync.Mutex // 单连接只允许一个写协程：心跳协程与 op1 立答经此串行

	msgMu   sync.Mutex
	lastMsg map[string]string // subject → 最近入站 msg_id（被动回投引用）
	msgSeq  map[string]int    // msg_id → 已用 seq（同 id 被动回复递增）
}

// NewQQChannel 构造。
func NewQQChannel(id, appID, appSecret string) *QQChannel {
	return &QQChannel{
		id: id, appID: appID, appSecret: appSecret,
		closeCh: make(chan struct{}),
		lastMsg: map[string]string{}, msgSeq: map[string]int{},
	}
}

// ID 通道实例 id。
func (q *QQChannel) ID() string { return q.id }

// Kind 通道类型。
func (q *QQChannel) Kind() string { return KindQQ }

// Connected 网关握手完成（READY/RESUMED 后真值；断链即假——管理面运行态口径）。
func (q *QQChannel) Connected() bool {
	q.stateMu.Lock()
	defer q.stateMu.Unlock()
	return q.connected
}

// Start 阻塞运行网关长连接（ctx 取消退出）：凭证探活先行显形 → 断链退避重连
// （Backoff 单源，默认 1s 倍增到 60s；会话存活则 RESUME 续约）。运行期异常
// 内部消化（Start 返回错误即终态失败，宿主不再拉起）。
func (q *QQChannel) Start(ctx context.Context, handler func(InboundMessage)) error {
	if handler == nil {
		return fmt.Errorf("imchan: qq 通道 %s 的 handler 为空", q.id)
	}
	if q.isClosed() {
		return ErrClosed
	}
	if err := QQProbe(q.appID, q.appSecret); err != nil {
		return fmt.Errorf("通道 %s 凭证探活失败: %w", q.id, err)
	}
	if q.isClosed() {
		return ErrClosed
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-q.closeCh:
			cancel()
		case <-runCtx.Done():
		}
	}()
	r := Reconnecter{Backoff: q.backoff, Clock: q.clock}
	err := r.Run(runCtx, func(sctx context.Context) error {
		if q.isClosed() {
			return ErrClosed
		}
		return q.runSession(sctx, handler)
	})
	if q.isClosed() {
		return ErrClosed
	}
	return err
}

// runSession 一次网关会话全生命周期：token → /gateway → 拨号 → Hello →
// Identify/Resume → READY → 收发循环（心跳协程 + 读超时看门狗）。返回即断链。
func (q *QQChannel) runSession(ctx context.Context, handler func(InboundMessage)) error {
	token, err := q.cachedToken()
	if err != nil {
		return err
	}
	gwURL := q.gatewayURL
	if gwURL == "" {
		if gwURL, err = q.fetchGateway(token); err != nil {
			return err
		}
	}
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, gwURL, nil)
	if err != nil {
		return fmt.Errorf("网关拨号失败: %w", err)
	}
	q.stateMu.Lock()
	q.conn = conn
	q.stateMu.Unlock()
	defer func() {
		q.stateMu.Lock()
		if q.conn == conn {
			q.conn = nil
		}
		q.connected = false
		q.stateMu.Unlock()
		conn.Close() //nolint:errcheck // 断链关闭，读侧已持有真实错误
	}()

	// ctx 取消立即砸连接解除读阻塞（Read 无 ctx 形态；Close 幂等安全）。
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

	// Hello（op10）→ Identify（首次）或 Resume（续约会话）。
	hb, err := q.handshake(conn, token)
	if err != nil {
		return err
	}

	// 心跳协程（写侧与 op1 立答经 writeMu 串行；写失败=断链，cancel 收敛）。
	tick := time.NewTicker(hb)
	defer tick.Stop()
	go func() {
		for {
			select {
			case <-sessCtx.Done():
				return
			case <-tick.C:
				if err := q.writeOp(conn, 1, q.seq()); err != nil {
					cancel()
					return
				}
			}
		}
	}()

	// 读超时看门狗：2.5 拍无任何下行（心跳 ACK/事件）判僵死断链——QQ 无 ws
	// 层 ping/pong，ACK 缺失即连接僵尸的唯一信号。
	for {
		_ = conn.SetReadDeadline(time.Now().Add(5 * hb / 2))
		var p qqWSPayload
		if err := conn.ReadJSON(&p); err != nil {
			return fmt.Errorf("网关读断: %w", err)
		}
		if p.S > 0 {
			q.stateMu.Lock()
			q.lastSeq = p.S
			q.stateMu.Unlock()
		}
		switch p.Op {
		case 11: // Heartbeat ACK
		case 1: // 服务端索心跳：立即补拍
			_ = q.writeOp(conn, 1, q.seq())
		case 7: // 服务端要求重连（劣化/迁移）
			return fmt.Errorf("网关要求重连（op7）")
		case 0:
			if q.dispatch(p.T, p.D, handler) {
				return fmt.Errorf("网关会话失效（INVALID_SESSION）")
			}
		}
		if err := sessCtx.Err(); err != nil {
			return err
		}
	}
}

// handshake 读 Hello 并发 Identify/Resume，返回服务端心跳拍。
func (q *QQChannel) handshake(conn *websocket.Conn, token string) (time.Duration, error) {
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	var p qqWSPayload
	if err := conn.ReadJSON(&p); err != nil {
		return 0, fmt.Errorf("读 Hello 失败: %w", err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	if p.Op != 10 {
		return 0, fmt.Errorf("期望 Hello（op10）实得 op=%d", p.Op)
	}
	var hello struct {
		HeartbeatInterval int `json:"heartbeat_interval"`
	}
	_ = json.Unmarshal(p.D, &hello)
	hb := time.Duration(hello.HeartbeatInterval) * time.Millisecond
	if hb <= 0 {
		hb = 30 * time.Second
	}
	q.stateMu.Lock()
	sessionID, seq := q.sessionID, q.lastSeq
	q.stateMu.Unlock()
	if sessionID != "" {
		if err := q.writeOp(conn, 6, map[string]any{
			"token": "QQBot " + token, "session_id": sessionID, "seq": seq,
		}); err != nil {
			return 0, fmt.Errorf("发送 Resume 失败: %w", err)
		}
		return hb, nil
	}
	if err := q.writeOp(conn, 2, map[string]any{
		"token": "QQBot " + token, "intents": 1 << 25, "shard": []int{0, 1},
	}); err != nil {
		return 0, fmt.Errorf("发送 Identify 失败: %w", err)
	}
	return hb, nil
}

// qqWSPayload 网关帧（QQ 官方协议 op/s/t/d）。
type qqWSPayload struct {
	Op int             `json:"op"`
	D  json.RawMessage `json:"d"`
	S  uint32          `json:"s"`
	T  string          `json:"t"`
}

// dispatch op0 事件分发；返回 true=INVALID_SESSION（Resume 被拒，外层弃会话改 Identify）。
func (q *QQChannel) dispatch(eventType string, data json.RawMessage, handler func(InboundMessage)) bool {
	switch eventType {
	case "READY":
		var d struct {
			SessionID string `json:"session_id"`
		}
		if err := json.Unmarshal(data, &d); err == nil && d.SessionID != "" {
			q.stateMu.Lock()
			q.sessionID = d.SessionID
			q.connected = true
			q.stateMu.Unlock()
		}
	case "RESUMED":
		q.stateMu.Lock()
		q.connected = true
		q.stateMu.Unlock()
	case "INVALID_SESSION":
		q.stateMu.Lock()
		q.sessionID = "" // 弃会话：下轮改走 Identify
		q.connected = false
		q.stateMu.Unlock()
		return true
	case "C2C_MESSAGE_CREATE":
		var ev struct {
			ID      string `json:"id"`
			Content string `json:"content"`
			Author  struct {
				UserOpenID string `json:"user_openid"`
			} `json:"author"`
		}
		if err := json.Unmarshal(data, &ev); err != nil {
			return false
		}
		if msg := q.inbound(ChatP2P, ev.Author.UserOpenID, "", ev.ID, ev.Content); msg != nil {
			handler(*msg)
		}
	case "GROUP_AT_MESSAGE_CREATE":
		var ev struct {
			ID      string `json:"id"`
			Content string `json:"content"`
			Author  struct {
				MemberOpenID string `json:"member_openid"`
			} `json:"author"`
			GroupOpenID string `json:"group_openid"`
		}
		if err := json.Unmarshal(data, &ev); err != nil {
			return false
		}
		if msg := q.inbound(ChatGroup, ev.GroupOpenID, ev.Author.MemberOpenID, ev.ID, ev.Content); msg != nil {
			handler(*msg)
		}
	}
	return false
}

// inbound 事件 → 统一入站模型 + 被动回投引用记忆。空文本忽略（纯图/纯 @ 无正文），
// 但引用记忆仍刷新（下一条被动回复可引用这条空文本消息）。
func (q *QQChannel) inbound(chatType, subject, sender, msgID, content string) *InboundMessage {
	if subject == "" || msgID == "" {
		return nil
	}
	text := strings.TrimSpace(content)
	q.msgMu.Lock()
	q.lastMsg[subject] = msgID
	q.msgMu.Unlock()
	if text == "" {
		return nil
	}
	return &InboundMessage{
		Channel: q.id, // 平面路由键（缺省空串会被宿主判 nil 静默丢消息）
		Kind:    KindQQ, Subject: subject, ChatType: chatType,
		Sender: sender, Text: text, MsgID: msgID,
	}
}

// Send 被动回投：v2 群/单聊消息 API + 最近入站 msg_id 引用 + msg_seq 递增（同 id
// 上限 5 条、约 5 分钟时效——超窗 QQ 侧拒收错误显形）。无引用记忆=显形错误（重启
// 后该 subject 需新消息刷新；多副本非连接副本恒显形——见包注释边界②）。
func (q *QQChannel) Send(subject, chatType, text string) error {
	if text == "" {
		return nil
	}
	if q.isClosed() {
		return ErrClosed
	}
	q.msgMu.Lock()
	msgID := q.lastMsg[subject]
	seq := 0
	if msgID != "" {
		q.msgSeq[msgID]++
		seq = q.msgSeq[msgID]
	}
	q.msgMu.Unlock()
	if msgID == "" {
		return fmt.Errorf("QQ 回投缺被动引用（subject %s 无近期入站消息；QQ 群/单聊须在收到消息后限时被动回复）", subject)
	}
	token, err := q.cachedToken()
	if err != nil {
		return err
	}
	path := "/v2/users/" + subject + "/messages" // 单聊
	if chatType == ChatGroup {
		path = "/v2/groups/" + subject + "/messages"
	}
	body, err := json.Marshal(map[string]any{
		"content": truncateRunes(text, 1500), "msg_type": 0, "msg_id": msgID, "msg_seq": seq,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, qqAPIBase+path, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "QQBot "+token)
	hc := &http.Client{Timeout: 15 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("QQ 回投不可达: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // 响应体只读一次
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		var out struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(raw, &out)
		return fmt.Errorf("QQ 回投失败（HTTP %d）: code=%d msg=%s", resp.StatusCode, out.Code, out.Message)
	}
	return nil
}

// cachedToken 进程内 token 缓存（按官方 expires_in 上限 2h 缓存、留 60s 刷新窗；
// 失败即重取）。
func (q *QQChannel) cachedToken() (string, error) {
	q.tokMu.Lock()
	defer q.tokMu.Unlock()
	if q.token != "" && time.Now().Before(q.tokenExp) {
		return q.token, nil
	}
	tk, err := qqFetchToken(q.appID, q.appSecret)
	if err != nil {
		return "", err
	}
	q.token = tk
	q.tokenExp = time.Now().Add(2*time.Hour - 60*time.Second)
	return tk, nil
}

// fetchGateway 拿网关 wss URL（GET /gateway，鉴权同消息 API）。
func (q *QQChannel) fetchGateway(token string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, qqAPIBase+"/gateway", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "QQBot "+token)
	hc := &http.Client{Timeout: 10 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("QQ 网关地址不可达: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // 响应体只读一次
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	var out struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.URL == "" {
		return "", fmt.Errorf("QQ 网关地址非法（HTTP %d）", resp.StatusCode)
	}
	return out.URL, nil
}

// writeOp 帧写出（单连接写协程互斥：心跳协程/op1 立答/握手期串行）。
func (q *QQChannel) writeOp(conn *websocket.Conn, op int, d any) error {
	q.writeMu.Lock()
	defer q.writeMu.Unlock()
	return conn.WriteJSON(struct {
		Op int `json:"op"`
		D  any `json:"d"`
	}{Op: op, D: d})
}

// seq 当前收序号（心跳载荷）。
func (q *QQChannel) seq() uint32 {
	q.stateMu.Lock()
	defer q.stateMu.Unlock()
	return q.lastSeq
}

// Close 终止网关连接并让 Start 返回 ErrClosed（幂等）。等待中的重连退避通过
// closeCh→cancel 立即打断，不会卡满 60s。
func (q *QQChannel) Close() error {
	q.closeOnce.Do(func() {
		q.stateMu.Lock()
		q.closed = true
		q.connected = false
		conn := q.conn
		q.stateMu.Unlock()
		close(q.closeCh)
		if conn != nil {
			_ = conn.Close()
		}
	})
	return nil
}

func (q *QQChannel) isClosed() bool {
	q.stateMu.Lock()
	defer q.stateMu.Unlock()
	return q.closed
}

// qqTruncSuffix 截断尾注（Send 与单测共用单源）。
const qqTruncSuffix = "…（内容过长已截断）"

// truncateRunes rune 安全截断（QQ 文本消息上限口径 1500 字）。
func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + qqTruncSuffix
}

var (
	_ Channel = (*QQChannel)(nil)
	_ Sender  = (*QQChannel)(nil)
)
