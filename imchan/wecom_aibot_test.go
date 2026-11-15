package imchan

// 企微智能机器人通道契约测试：探活（假网关认证成败两路）/全链（认证 →
// CALLBACK 文本入站归一 → SEND_MSG markdown 回投 ack 成败两路）/连续认证
// 失败终态阈值/Close 语义。帧类型用实现侧 aibotFrame 单源。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// fakeAibotGateway 起假网关：仅升级连接，协议交互由测试脚本驱动。
func fakeAibotGateway(t *testing.T) (*httptest.Server, chan *websocket.Conn) {
	t.Helper()
	conns := make(chan *websocket.Conn, 8)
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		conns <- c
	}))
	return srv, conns
}

func aibotWrite(t *testing.T, c *websocket.Conn, f aibotFrame) {
	t.Helper()
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := c.WriteJSON(f); err != nil {
		t.Fatalf("假网关写帧失败: %v", err)
	}
}

func aibotRead(t *testing.T, c *websocket.Conn) aibotFrame {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var f aibotFrame
	if err := c.ReadJSON(&f); err != nil {
		t.Fatalf("假网关读帧失败: %v", err)
	}
	return f
}

// aibotAuthHandshake 读认证帧（断言凭证回显）并按 ok 与应答。
func aibotAuthHandshake(t *testing.T, c *websocket.Conn, wantID, wantSecret string, ok bool) aibotFrame {
	t.Helper()
	f := aibotRead(t, c)
	if f.Cmd != aibotCmdSubscribe {
		t.Fatalf("期望认证帧实得 cmd=%q", f.Cmd)
	}
	var body struct {
		BotID  string `json:"bot_id"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(f.Body, &body); err != nil {
		t.Fatalf("认证帧 body 非法: %v", err)
	}
	if body.BotID != wantID || body.Secret != wantSecret {
		t.Fatalf("认证凭证错: bot_id=%q secret=%q", body.BotID, body.Secret)
	}
	resp := aibotFrame{Headers: f.Headers}
	if !ok {
		resp.ErrCode, resp.ErrMsg = 95001, "invalid secret"
	}
	aibotWrite(t, c, resp)
	return f
}

func TestWecomAibotProbe(t *testing.T) {
	oldURL := wecomAibotWSURL
	oldTO := wecomAibotProbeTimeout
	wecomAibotProbeTimeout = 4 * time.Second
	defer func() {
		wecomAibotWSURL = oldURL
		wecomAibotProbeTimeout = oldTO
	}()
	if err := WecomAibotProbe("", ""); err == nil {
		t.Fatal("缺凭证应拒")
	}

	// 认证成功。
	srv, conns := fakeAibotGateway(t)
	defer srv.Close()
	wecomAibotWSURL = "ws" + strings.TrimPrefix(srv.URL, "http")
	probeDone := make(chan error, 1)
	go func() { probeDone <- WecomAibotProbe("bot-1", "sec-1") }()
	c1 := <-conns
	aibotAuthHandshake(t, c1, "bot-1", "sec-1", true)
	select {
	case err := <-probeDone:
		if err != nil {
			t.Fatalf("有效凭证应通过: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("探活未收敛")
	}

	// 认证失败（errcode 显形 + 哨兵可判）。
	errSrv, errConns := fakeAibotGateway(t)
	defer errSrv.Close()
	wecomAibotWSURL = "ws" + strings.TrimPrefix(errSrv.URL, "http")
	probeFail := make(chan error, 1)
	go func() { probeFail <- WecomAibotProbe("bot-1", "bad") }()
	c2 := <-errConns
	aibotAuthHandshake(t, c2, "bot-1", "bad", false)
	select {
	case err := <-probeFail:
		if err == nil || !strings.Contains(err.Error(), "95001") || !isAibotAuthErr(err) {
			t.Fatalf("认证失败应显形 errcode 且命中哨兵: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("探活失败未收敛")
	}
}

// TestWecomAibotChannelLoop 全链：探活连接 + 运行连接两代际 → CALLBACK 文本入站
// 归一 → SEND_MSG markdown 回投 ack 成败两路 → ctx 退出。
func TestWecomAibotChannelLoop(t *testing.T) {
	oldURL := wecomAibotWSURL
	oldTO := wecomAibotProbeTimeout
	wecomAibotProbeTimeout = 4 * time.Second
	defer func() {
		wecomAibotWSURL = oldURL
		wecomAibotProbeTimeout = oldTO
	}()

	srv, conns := fakeAibotGateway(t)
	defer srv.Close()
	wecomAibotWSURL = "ws" + strings.TrimPrefix(srv.URL, "http")

	w := NewWecomAibotChannel("aibot-1", "bot-1", "sec-1")
	got := make(chan InboundMessage, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.Start(ctx, func(m InboundMessage) { got <- m }) }()

	// 第一代际：探活连接（认证成功后即被探活 Disconnect）。
	cProbe := <-conns
	aibotAuthHandshake(t, cProbe, "bot-1", "sec-1", true)

	// 第二代际：运行连接。
	cRun := <-conns
	aibotAuthHandshake(t, cRun, "bot-1", "sec-1", true)

	// 入站：群文本 CALLBACK。
	var cbHdr struct {
		ReqID string `json:"req_id"`
	}
	cbHdr.ReqID = "srv-1"
	aibotWrite(t, cRun, aibotFrame{Cmd: aibotCmdCallback, Headers: cbHdr, Body: json.RawMessage(
		`{"msgid":"m-1","chatid":"wrp-9","chattype":"group","msgtype":"text",` +
			`"from":{"userid":"mem-7"},"text":{"content":" 排查磁盘 "}}`)})
	select {
	case m := <-got:
		if m.Channel != "aibot-1" || m.Kind != KindWecomAibot || m.Subject != "wrp-9" ||
			m.ChatType != ChatGroup || m.Sender != "mem-7" || m.Text != "排查磁盘" || m.MsgID != "m-1" {
			t.Fatalf("群消息归一错: %+v", m)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("入站消息未达")
	}

	// 回投（群档）：读 SEND_MSG 帧 → ack 成功。
	sendErr := make(chan error, 2)
	go func() { sendErr <- w.Send("wrp-9", ChatGroup, "**报告**") }()
	sendFrame := aibotRead(t, cRun)
	if sendFrame.Cmd != aibotCmdSendMsg {
		t.Fatalf("期望 SEND_MSG 实得 %q", sendFrame.Cmd)
	}
	var body struct {
		ChatID   string `json:"chatid"`
		ChatType int    `json:"chat_type"`
		MsgType  string `json:"msgtype"`
		Markdown struct {
			Content string `json:"content"`
		} `json:"markdown"`
	}
	if err := json.Unmarshal(sendFrame.Body, &body); err != nil {
		t.Fatalf("SEND_MSG body 非法: %v", err)
	}
	if body.ChatID != "wrp-9" || body.ChatType != 2 || body.MsgType != "markdown" || body.Markdown.Content != "**报告**" {
		t.Fatalf("回投形态错: %+v", body)
	}
	aibotWrite(t, cRun, aibotFrame{Headers: sendFrame.Headers, ErrCode: 0})
	select {
	case err := <-sendErr:
		if err != nil {
			t.Fatalf("ack 成功应无错: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("回投未收敛")
	}

	// 回投（单聊档 + ack 错误信封）。
	go func() { sendErr <- w.Send("usr-3", ChatP2P, "私聊回") }()
	sendFrame2 := aibotRead(t, cRun)
	var body2 struct {
		ChatID   string `json:"chatid"`
		ChatType int    `json:"chat_type"`
	}
	if err := json.Unmarshal(sendFrame2.Body, &body2); err != nil || body2.ChatID != "usr-3" || body2.ChatType != 1 {
		t.Fatalf("单聊回投形态错: %+v err=%v", body2, err)
	}
	aibotWrite(t, cRun, aibotFrame{Headers: sendFrame2.Headers, ErrCode: 95000, ErrMsg: "forbidden"})
	select {
	case err := <-sendErr:
		if err == nil || !strings.Contains(err.Error(), "95000") {
			t.Fatalf("ack 错误应显形: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("回投错误未收敛")
	}

	// 非文本 / 缺 msgid 的 CALLBACK 不投递。
	aibotWrite(t, cRun, aibotFrame{Cmd: aibotCmdCallback, Body: json.RawMessage(
		`{"msgid":"m-2","chatid":"wrp-9","msgtype":"image"}`)})
	select {
	case m := <-got:
		t.Fatalf("非文本不应投递: %+v", m)
	case <-time.After(100 * time.Millisecond):
	}

	// 优雅退出。
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("退出应携带 ctx.Err: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start 未随 ctx 退出")
	}
}

// TestWecomAibotAuthFailTerminal 连续认证失败达阈值 → Start 终态返回错误
// （不是无限退避）；假时钟保证序列瞬时。
func TestWecomAibotAuthFailTerminal(t *testing.T) {
	oldURL := wecomAibotWSURL
	oldTO := wecomAibotProbeTimeout
	wecomAibotProbeTimeout = 4 * time.Second
	defer func() {
		wecomAibotWSURL = oldURL
		wecomAibotProbeTimeout = oldTO
	}()

	srv, conns := fakeAibotGateway(t)
	defer srv.Close()
	wecomAibotWSURL = "ws" + strings.TrimPrefix(srv.URL, "http")

	w := NewWecomAibotChannel("aibot-1", "bot-1", "sec-1")
	w.clock = &fakeClock{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.Start(ctx, func(InboundMessage) {}) }()

	// 探活成功。
	cProbe := <-conns
	aibotAuthHandshake(t, cProbe, "bot-1", "sec-1", true)
	// 之后 5 次运行连接全部认证失败。
	for i := 0; i < wecomAibotMaxAuthFail; i++ {
		c := <-conns
		aibotAuthHandshake(t, c, "bot-1", "sec-1", false)
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "连续认证失败 5 次") {
			t.Fatalf("应终态显形连续认证失败: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("认证失败阈值未收敛")
	}
}

// TestWecomAibotSendBeforeConnected 未连接时回投直接显形，不静默丢失。
func TestWecomAibotSendBeforeConnected(t *testing.T) {
	w := NewWecomAibotChannel("aibot-1", "bot-1", "sec-1")
	if err := w.Send("u1", ChatP2P, "hi"); err == nil || !strings.Contains(err.Error(), "未连接") {
		t.Fatalf("未连接应显形: %v", err)
	}
	if err := w.Send("u1", ChatP2P, "  "); err != nil {
		t.Fatalf("空文本应静默忽略: %v", err)
	}
}

// TestIsAibotAuthErrBySentinel 认证判定读 error 链的哨兵，不看文案。
func TestIsAibotAuthErrBySentinel(t *testing.T) {
	err := aibotAuthError(95001, "invalid credential")
	if !isAibotAuthErr(err) {
		t.Fatalf("哨兵错误应判为认证失败: %v", err)
	}
	if !isAibotAuthErr(fmt.Errorf("外层上下文: %w", err)) {
		t.Fatal("包裹后仍应判为认证失败")
	}
	plain := fmt.Errorf("%w: errcode=95001 msg=invalid", ErrAibotAuth)
	if !isAibotAuthErr(plain) {
		t.Fatal("判定不应依赖文案关键词")
	}
	if isAibotAuthErr(errors.New("连接超时")) {
		t.Fatal("无关错误不应判为认证失败")
	}
	if isAibotAuthErr(nil) {
		t.Fatal("nil 不应判为认证失败")
	}
}
