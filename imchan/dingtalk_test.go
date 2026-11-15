package imchan

// 钉钉通道契约测试：探活（假端点）/解析正反形态（单群判别 + webhook 记忆）/
// 回投（sessionWebhook 查表 + 错误信封）/Close 语义。WS 长连全链依赖 SDK
// 硬编码官方网关，离线只覆盖探活/解析/回投三层（与 bianque 同策略）。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/open-dingtalk/dingtalk-stream-sdk-go/payload"
)

func TestDingTalkProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"accessToken":"at-1","expireIn":7200}`))
	}))
	defer srv.Close()
	old := dingtalkTokenURL
	dingtalkTokenURL = srv.URL
	defer func() { dingtalkTokenURL = old }()

	if err := DingTalkProbe("k", "s"); err != nil {
		t.Fatalf("有效凭证应通过: %v", err)
	}
	if err := DingTalkProbe("", ""); err == nil {
		t.Fatal("缺凭证应拒")
	}
	errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":"InvalidAuthentication"}`))
	}))
	defer errSrv.Close()
	dingtalkTokenURL = errSrv.URL
	if err := DingTalkProbe("k", "bad"); err == nil {
		t.Fatal("无 accessToken 应报错")
	}
}

func TestParseDingTalkDataFrame(t *testing.T) {
	d := NewDingTalkChannel("dt-1", "k", "s")
	data := `{"conversationId":"cid-1","conversationType":"1","senderStaffId":"staff-9",` +
		`"senderNick":"张三","sessionWebhook":"https://oapi.dingtalk.com/robot/send?x=1",` +
		`"msgId":"m-1","msgType":"text","text":{"content":" 排查负载 "}}`
	df := &payload.DataFrame{Data: data}
	msg := d.parseDataFrame(df)
	if msg == nil {
		t.Fatal("应解析出消息")
	}
	if msg.Subject != "cid-1" || msg.ChatType != ChatP2P || msg.Sender != "staff-9" ||
		msg.Text != "排查负载" || msg.Kind != KindDingTalk || msg.MsgID != "m-1" {
		t.Fatalf("解析形态错: %+v", msg)
	}
	// webhook 记忆刷新
	d.mu.Lock()
	hook := d.webhooks["cid-1"]
	d.mu.Unlock()
	if hook != "https://oapi.dingtalk.com/robot/send?x=1" {
		t.Fatalf("webhook 未记忆: %q", hook)
	}
	// 群聊判别
	group := d.parseDataFrame(&payload.DataFrame{Data: `{"conversationId":"c2","conversationType":"2",` +
		`"msgId":"m-2","msgType":"text","text":{"content":"群问题"}}`})
	if group == nil || group.ChatType != ChatGroup {
		t.Fatalf("群聊判别错: %+v", group)
	}
	// 负形态：非文本 / 空正文 / 缺会话 id / 坏 JSON / nil 帧。
	for _, bad := range []*payload.DataFrame{
		{Data: `{"conversationId":"c3","msgType":"picture"}`},
		{Data: `{"conversationId":"c4","msgType":"text","text":{"content":"  "}}`},
		{Data: `{"msgType":"text","text":{"content":"hi"}}`},
		{Data: `not-json`},
		nil,
	} {
		if got := d.parseDataFrame(bad); got != nil {
			t.Fatalf("负形态应忽略: %+v", got)
		}
	}
	// 导出的纯解析入口（无 webhook 记忆）。
	plain := ParseDingTalkMessage(`{"conversationId":"c5","conversationType":"2","msgId":"m-5",` +
		`"msgType":"text","text":{"content":"hi"}}`)
	if plain == nil || plain.Subject != "c5" || plain.ChatType != ChatGroup {
		t.Fatalf("纯解析入口错: %+v", plain)
	}
}

func TestDingTalkSend(t *testing.T) {
	var gotPath string
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.String()
		buf := make([]byte, 512)
		n, _ := r.Body.Read(buf)
		gotBody = string(buf[:n])
		_, _ = w.Write([]byte(`{"errcode":0,"errmsg":"ok"}`))
	}))
	defer srv.Close()

	d := NewDingTalkChannel("dt-1", "k", "s")
	// 无 webhook 记忆 → 显形错误
	if err := d.Send("cid-x", ChatP2P, "hi"); err == nil || !strings.Contains(err.Error(), "sessionWebhook") {
		t.Fatalf("无记忆应显形: %v", err)
	}
	d.webhooks["cid-x"] = srv.URL + "/send?x=1"
	if err := d.Send("cid-x", ChatP2P, "hi"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotPath, "/send") || !strings.Contains(gotBody, `"text"`) {
		t.Fatalf("回投形态错: %s %s", gotPath, gotBody)
	}
	if err := d.Send("cid-x", ChatP2P, "  "); err != nil {
		t.Fatalf("空文本应静默忽略: %v", err)
	}
	// 钉钉错误码信封
	errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"errcode":310000,"errmsg":"sign not match"}`))
	}))
	defer errSrv.Close()
	d.webhooks["cid-y"] = errSrv.URL
	if err := d.Send("cid-y", ChatP2P, "hi"); err == nil || !strings.Contains(err.Error(), "310000") {
		t.Fatalf("错误码信封应显形: %v", err)
	}
}

// TestDingTalkClose Close 后回投返回 ErrClosed，且幂等。
func TestDingTalkClose(t *testing.T) {
	d := NewDingTalkChannel("dt-1", "k", "s")
	d.webhooks["cid-1"] = "http://example.invalid/send"
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.Send("cid-1", ChatP2P, "hi"); err != ErrClosed {
		t.Fatalf("Close 后应 ErrClosed: %v", err)
	}
	if d.Connected() {
		t.Fatal("Close 后不应 Connected")
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close 应幂等: %v", err)
	}
}
