package imchan

// QQ 通道契约测试：探活（假端点）/网关全链（假 WS 网关——Identify、READY/
// 群·单聊事件分发、心跳 ACK、断链 RESUME 续约）/回投（被动引用 + msg_seq
// 递增 + 错误信封 + 截断）/Close 语义。网关循环手写的红利：进程内全链可测。

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// fakeQQToken 起假 token 端点（返回 at-1；err=true 时回错误形态）。
func fakeQQToken(t *testing.T, errShape bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if errShape {
			_, _ = w.Write([]byte(`{"code":11253,"message":"invalid appid"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"at-1","expires_in":"7200"}`))
	}))
}

// fakeQQGateway 起假 WS 网关：仅升级连接，协议交互由测试脚本驱动。
func fakeQQGateway(t *testing.T) (*httptest.Server, chan *websocket.Conn) {
	t.Helper()
	conns := make(chan *websocket.Conn, 4)
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

func wsWrite(t *testing.T, c *websocket.Conn, op int, d any, s uint32, evt string) {
	t.Helper()
	frame := map[string]any{"op": op, "d": d}
	if s > 0 {
		frame["s"] = s
	}
	if evt != "" {
		frame["t"] = evt
	}
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := c.WriteJSON(frame); err != nil {
		t.Fatalf("假网关写帧失败: %v", err)
	}
}

func wsRead(t *testing.T, c *websocket.Conn, dst any) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := c.ReadJSON(dst); err != nil {
		t.Fatalf("假网关读帧失败: %v", err)
	}
}

func TestQQProbe(t *testing.T) {
	srv := fakeQQToken(t, false)
	defer srv.Close()
	old := qqTokenURL
	qqTokenURL = srv.URL
	defer func() { qqTokenURL = old }()

	if err := QQProbe("app-1", "sec"); err != nil {
		t.Fatalf("有效凭证应通过: %v", err)
	}
	if err := QQProbe("", ""); err == nil {
		t.Fatal("缺凭证应拒")
	}
	errSrv := fakeQQToken(t, true)
	defer errSrv.Close()
	qqTokenURL = errSrv.URL
	if err := QQProbe("app-1", "bad"); err == nil || !strings.Contains(err.Error(), "11253") {
		t.Fatalf("错误形态应显形 code: %v", err)
	}
}

// TestQQWSGatewayLoop 网关全链：Identify → READY → 群/单聊事件分发 → 心跳/ACK →
// 断链重连走 RESUME 续约（session_id+seq 接续）。假时钟让 1s 退避瞬时完成。
func TestQQWSGatewayLoop(t *testing.T) {
	tokSrv := fakeQQToken(t, false)
	defer tokSrv.Close()
	oldTok := qqTokenURL
	qqTokenURL = tokSrv.URL
	defer func() { qqTokenURL = oldTok }()

	gwSrv, conns := fakeQQGateway(t)
	defer gwSrv.Close()
	wsURL := "ws" + strings.TrimPrefix(gwSrv.URL, "http")

	q := NewQQChannel("qq-1", "app-1", "sec")
	q.gatewayURL = wsURL
	q.clock = &fakeClock{}

	got := make(chan InboundMessage, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- q.Start(ctx, func(m InboundMessage) { got <- m }) }()

	// 第一条连接：Hello → Identify → READY → 两条事件 → 心跳/ACK。
	c1 := <-conns
	wsWrite(t, c1, 10, map[string]any{"heartbeat_interval": 300}, 0, "")
	var idFrame struct {
		Op int `json:"op"`
		D  struct {
			Token   string `json:"token"`
			Intents int    `json:"intents"`
		} `json:"d"`
	}
	wsRead(t, c1, &idFrame)
	if idFrame.Op != 2 || !strings.HasPrefix(idFrame.D.Token, "QQBot at-1") || idFrame.D.Intents != 1<<25 {
		t.Fatalf("Identify 形态错: %+v", idFrame)
	}
	wsWrite(t, c1, 0, map[string]any{"session_id": "s-1", "user": map[string]any{"id": "bot"}}, 1, "READY")
	wsWrite(t, c1, 0, map[string]any{
		"id": "gm-1", "content": " 排查负载 ",
		"author":       map[string]any{"member_openid": "mem-9"},
		"group_openid": "grp-1",
	}, 2, "GROUP_AT_MESSAGE_CREATE")
	wsWrite(t, c1, 0, map[string]any{
		"id": "cm-1", "content": "看下磁盘",
		"author": map[string]any{"user_openid": "usr-7"},
	}, 3, "C2C_MESSAGE_CREATE")

	select {
	case m := <-got:
		if m.Channel != "qq-1" || m.Subject != "grp-1" || m.ChatType != ChatGroup ||
			m.Sender != "mem-9" || m.Text != "排查负载" || m.MsgID != "gm-1" || m.Kind != KindQQ {
			t.Fatalf("群消息归一错: %+v", m)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("群消息未达")
	}
	select {
	case m := <-got:
		if m.Subject != "usr-7" || m.ChatType != ChatP2P || m.MsgID != "cm-1" {
			t.Fatalf("单聊消息归一错: %+v", m)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("单聊消息未达")
	}
	if !q.Connected() {
		t.Fatal("READY 后应标记已连接")
	}

	// 心跳到达 → 回 ACK（保活）。
	var hb struct {
		Op int `json:"op"`
		D  any `json:"d"`
	}
	wsRead(t, c1, &hb)
	if hb.Op != 1 {
		t.Fatalf("期望心跳 op1 实得 %+v", hb)
	}
	wsWrite(t, c1, 11, nil, 0, "")

	// 断链 → 假时钟瞬时退避 → RESUME（session_id/seq 接续）。
	_ = c1.Close()
	c2 := <-conns
	wsWrite(t, c2, 10, map[string]any{"heartbeat_interval": 300}, 0, "")
	var rs struct {
		Op int `json:"op"`
		D  struct {
			Token     string `json:"token"`
			SessionID string `json:"session_id"`
			Seq       uint32 `json:"seq"`
		} `json:"d"`
	}
	wsRead(t, c2, &rs)
	if rs.Op != 6 || rs.D.SessionID != "s-1" || rs.D.Seq != 3 {
		t.Fatalf("Resume 形态错: %+v", rs)
	}
	wsWrite(t, c2, 0, map[string]any{}, 4, "RESUMED")
	waitFor(t, 2*time.Second, q.Connected)

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

// TestQQCloseInterruptsStart Close 打断运行中的 Start 并返回 ErrClosed。
func TestQQCloseInterruptsStart(t *testing.T) {
	tokSrv := fakeQQToken(t, false)
	defer tokSrv.Close()
	oldTok := qqTokenURL
	qqTokenURL = tokSrv.URL
	defer func() { qqTokenURL = oldTok }()
	gwSrv, conns := fakeQQGateway(t)
	defer gwSrv.Close()

	q := NewQQChannel("qq-1", "app-1", "sec")
	q.gatewayURL = "ws" + strings.TrimPrefix(gwSrv.URL, "http")
	q.clock = &fakeClock{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- q.Start(ctx, func(InboundMessage) {}) }()
	c1 := <-conns
	wsWrite(t, c1, 10, map[string]any{"heartbeat_interval": 300}, 0, "")
	var idFrame map[string]any
	wsRead(t, c1, &idFrame)
	wsWrite(t, c1, 0, map[string]any{"session_id": "s-1"}, 1, "READY")
	waitFor(t, 2*time.Second, q.Connected)
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("Close 后 Start 应返回 ErrClosed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close 未打断 Start")
	}
	if q.Connected() {
		t.Fatal("Close 后不应 Connected")
	}
	if err := q.Send("grp-1", ChatGroup, "hi"); !errors.Is(err, ErrClosed) {
		t.Fatalf("Close 后回投应 ErrClosed: %v", err)
	}
	if err := q.Close(); err != nil {
		t.Fatalf("Close 应幂等: %v", err)
	}
}

func TestQQSend(t *testing.T) {
	tokSrv := fakeQQToken(t, false)
	defer tokSrv.Close()
	oldTok := qqTokenURL
	qqTokenURL = tokSrv.URL
	defer func() { qqTokenURL = oldTok }()

	var gotPath, gotAuth, gotBody string
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		gotBody = string(buf[:n])
		_, _ = w.Write([]byte(`{}`))
	}))
	defer apiSrv.Close()
	oldAPI := qqAPIBase
	qqAPIBase = apiSrv.URL
	defer func() { qqAPIBase = oldAPI }()

	q := NewQQChannel("qq-1", "app-1", "sec")
	// 无被动引用记忆 → 显形。
	if err := q.Send("grp-x", ChatGroup, "hi"); err == nil || !strings.Contains(err.Error(), "被动引用") {
		t.Fatalf("无记忆应显形: %v", err)
	}
	q.msgMu.Lock()
	q.lastMsg["grp-1"], q.lastMsg["usr-7"] = "gm-1", "cm-1"
	q.msgMu.Unlock()

	if err := q.Send("grp-1", ChatGroup, "报告"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v2/groups/grp-1/messages" || !strings.HasPrefix(gotAuth, "QQBot at-1") ||
		!strings.Contains(gotBody, `"msg_id":"gm-1"`) || !strings.Contains(gotBody, `"msg_seq":1`) {
		t.Fatalf("群回投形态错: %s %s %s", gotPath, gotAuth, gotBody)
	}
	if err := q.Send("grp-1", ChatGroup, "补充"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotBody, `"msg_seq":2`) {
		t.Fatalf("同 msg_id seq 应递增: %s", gotBody)
	}
	if err := q.Send("usr-7", ChatP2P, "私聊回"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v2/users/usr-7/messages" {
		t.Fatalf("单聊回投路径错: %s", gotPath)
	}

	// API 错误信封。
	errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":11253,"message":"msg_id expired"}`))
	}))
	defer errSrv.Close()
	qqAPIBase = errSrv.URL
	err := q.Send("usr-7", ChatP2P, "hi")
	if err == nil || !strings.Contains(err.Error(), "11253") || !strings.Contains(err.Error(), "400") {
		t.Fatalf("API 错误信封应显形: %v", err)
	}
}

func TestQQTruncateRunes(t *testing.T) {
	if got := truncateRunes("短文本", 10); got != "短文本" {
		t.Fatalf("短文本不应截断: %q", got)
	}
	long := strings.Repeat("测", 1600)
	want := string([]rune(long)[:1500]) + qqTruncSuffix
	if got := truncateRunes(long, 1500); got != want {
		t.Fatalf("截断形态错: got %d runes want %d", len([]rune(got)), len([]rune(want)))
	}
}

// TestQQInboundEmpty 纯图/纯 @（空文本）消息：引用记忆仍刷新、不投递诊断；
// 缺 subject/msgID 的畸形事件忽略。
func TestQQInboundEmpty(t *testing.T) {
	q := NewQQChannel("qq-1", "app-1", "sec")
	if msg := q.inbound(ChatGroup, "grp-1", "mem-1", "gm-2", "  "); msg != nil {
		t.Fatalf("空文本不应投递: %+v", msg)
	}
	q.msgMu.Lock()
	ref := q.lastMsg["grp-1"]
	q.msgMu.Unlock()
	if ref != "gm-2" {
		t.Fatalf("空文本也应刷新被动引用: %q", ref)
	}
	if msg := q.inbound(ChatGroup, "", "mem-1", "gm-3", "hi"); msg != nil {
		t.Fatal("缺 subject 应忽略")
	}
	if msg := q.inbound(ChatGroup, "grp-1", "mem-1", "", "hi"); msg != nil {
		t.Fatal("缺 msgID 应忽略")
	}
}
