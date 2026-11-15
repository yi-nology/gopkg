package imchan

// 飞书通道契约测试（离线：事件结构体直构，不触网络）：text/群 @剥除/image/
// file 惰性附件正形态，nil/富媒体/空正文/坏 JSON 负形态，探活假端点。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	larkim "github.com/larksuite/oapi-sdk-go/v3/service/im/v1"
)

func sp(s string) *string { return &s }

func TestParseLarkMessage(t *testing.T) {
	ev := &larkim.P2MessageReceiveV1{Event: &larkim.P2MessageReceiveV1Data{
		Message: &larkim.EventMessage{
			MessageId: sp("om1"), ChatId: sp("oc1"), ChatType: sp("p2p"),
			MessageType: sp("text"), Content: sp(`{"text":"磁盘快满了帮我看看"}`),
		},
		Sender: &larkim.EventSender{SenderId: &larkim.UserId{OpenId: sp("ou1")}},
	}}
	m := (&LarkChannel{}).ParseLarkMessage(ev)
	if m == nil || m.Subject != "oc1" || m.ChatType != ChatP2P || m.MsgID != "om1" ||
		m.Sender != "ou1" || m.Text != "磁盘快满了帮我看看" || m.Kind != KindLark {
		t.Fatalf("解析不符: %+v", m)
	}
}

func TestParseLarkMessageGroupMention(t *testing.T) {
	ev := &larkim.P2MessageReceiveV1{Event: &larkim.P2MessageReceiveV1Data{
		Message: &larkim.EventMessage{
			MessageId: sp("om2"), ChatId: sp("oc2"), ChatType: sp("group"),
			MessageType: sp("text"), Content: sp(`{"text":"@_user_1 负载怎么样"}`),
		},
	}}
	m := (&LarkChannel{}).ParseLarkMessage(ev)
	if m == nil || m.ChatType != ChatGroup || m.Text != "负载怎么样" {
		t.Fatalf("群聊 @剥除不符: %+v", m)
	}
}

func TestParseLarkMessageSkipsNonText(t *testing.T) {
	ev := &larkim.P2MessageReceiveV1{Event: &larkim.P2MessageReceiveV1Data{
		Message: &larkim.EventMessage{ChatId: sp("oc3"), MessageType: sp("image"), Content: sp(`{}`)},
	}}
	if m := (&LarkChannel{}).ParseLarkMessage(ev); m != nil {
		t.Fatalf("空 image_key 应忽略: %+v", m)
	}
	// 纯 @无正文：忽略
	ev2 := &larkim.P2MessageReceiveV1{Event: &larkim.P2MessageReceiveV1Data{
		Message: &larkim.EventMessage{
			ChatId: sp("oc4"), ChatType: sp("group"), MessageType: sp("text"),
			Content: sp(`{"text":"@_user_1"}`),
		},
	}}
	if m := (&LarkChannel{}).ParseLarkMessage(ev2); m != nil {
		t.Fatalf("纯 @应忽略: %+v", m)
	}
	// 坏 JSON / 缺字段 / nil 事件。
	bad := &larkim.P2MessageReceiveV1{Event: &larkim.P2MessageReceiveV1Data{
		Message: &larkim.EventMessage{ChatId: sp("oc5"), MessageType: sp("text"), Content: sp(`{bad`)},
	}}
	if m := (&LarkChannel{}).ParseLarkMessage(bad); m != nil {
		t.Fatalf("坏 JSON 应忽略: %+v", m)
	}
	if m := (&LarkChannel{}).ParseLarkMessage(nil); m != nil {
		t.Fatal("nil 事件应忽略")
	}
	if m := (&LarkChannel{}).ParseLarkMessage(&larkim.P2MessageReceiveV1{}); m != nil {
		t.Fatal("空事件应忽略")
	}
	// 未知消息类型。
	unknown := &larkim.P2MessageReceiveV1{Event: &larkim.P2MessageReceiveV1Data{
		Message: &larkim.EventMessage{ChatId: sp("oc6"), MessageType: sp("post"), Content: sp(`{}`)},
	}}
	if m := (&LarkChannel{}).ParseLarkMessage(unknown); m != nil {
		t.Fatalf("未知类型应忽略: %+v", m)
	}
}

// TestParseLarkMessageFiles image/file 附件正形态：名称/MIME/惰性闭包齐备。
func TestParseLarkMessageFiles(t *testing.T) {
	img := &larkim.P2MessageReceiveV1{Event: &larkim.P2MessageReceiveV1Data{
		Message: &larkim.EventMessage{
			MessageId: sp("om-image-1234567890"), ChatId: sp("oc7"), ChatType: sp("group"),
			MessageType: sp("image"), Content: sp(`{"image_key":"img-key-1"}`),
		},
	}}
	m := (&LarkChannel{}).ParseLarkMessage(img)
	if m == nil || len(m.Files) != 1 || m.Files[0].Name != "lark-image-om-image-123.png" ||
		m.Files[0].MimeType != "image/png" || m.Files[0].Open == nil {
		t.Fatalf("image 附件形态错: %+v", m)
	}
	// 未启动客户端：惰性闭包调用显形，不在解析期 IO。
	if _, err := m.Files[0].Open(); err == nil || !strings.Contains(err.Error(), "未启动") {
		t.Fatalf("未启动应显形: %v", err)
	}

	file := &larkim.P2MessageReceiveV1{Event: &larkim.P2MessageReceiveV1Data{
		Message: &larkim.EventMessage{
			MessageId: sp("om-file-1"), ChatId: sp("oc8"),
			MessageType: sp("file"), Content: sp(`{"file_key":"fk-1","file_name":"app.log"}`),
		},
	}}
	fm := (&LarkChannel{}).ParseLarkMessage(file)
	if fm == nil || len(fm.Files) != 1 || fm.Files[0].Name != "app.log" || fm.Files[0].Open == nil {
		t.Fatalf("file 附件形态错: %+v", fm)
	}
	// 缺 file_name：按 file_key/message_id 生成稳定名。
	noname := &larkim.P2MessageReceiveV1{Event: &larkim.P2MessageReceiveV1Data{
		Message: &larkim.EventMessage{
			MessageId: sp("om-file-2"), ChatId: sp("oc9"),
			MessageType: sp("file"), Content: sp(`{"file_key":"fk-2"}`),
		},
	}}
	nm := (&LarkChannel{}).ParseLarkMessage(noname)
	if nm == nil || nm.Files[0].Name != "lark-file-om-file-2" {
		t.Fatalf("缺名附件命名错: %+v", nm)
	}
}

func TestLarkProbeAgainstFakeEndpoint(t *testing.T) {
	old := larkTokenURL
	defer func() { larkTokenURL = old }()
	larkTokenURL = newFakeLarkToken(t, `{"code":99991663,"msg":"invalid app_id"}`)
	if err := LarkProbe("cli-x", "sec"); err == nil || !strings.Contains(err.Error(), "99991663") {
		t.Fatalf("坏凭证应报 code，实得 %v", err)
	}
	larkTokenURL = newFakeLarkToken(t, `{"code":0,"app_access_token":"t"}`)
	if err := LarkProbe("cli-x", "sec"); err != nil {
		t.Fatalf("好凭证不应报错: %v", err)
	}
	if err := LarkProbe("", ""); err == nil {
		t.Fatal("空凭证应报缺失")
	}
	if err := LarkProbe("cli-x", "sec"); err != nil {
		// 上一个是合法响应；这条只为覆盖成功分支的可重复性。
		t.Fatal(err)
	}
}

// TestLarkSendClosed Close 后回投显形 ErrClosed（未启动时回投显形错误）。
func TestLarkSendClosed(t *testing.T) {
	l := NewLarkChannel("lark-1", "app", "sec")
	if err := l.Send("oc1", ChatP2P, "hi"); err == nil || !strings.Contains(err.Error(), "未启动") {
		t.Fatalf("未启动应显形: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Send("oc1", ChatP2P, "hi"); err != ErrClosed {
		t.Fatalf("Close 后应 ErrClosed: %v", err)
	}
	if l.Connected() {
		t.Fatal("Close 后不应 Connected")
	}
}

// newFakeLarkToken 假飞书 token 端点（固定响应体），返回 URL。
func newFakeLarkToken(t *testing.T, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}
