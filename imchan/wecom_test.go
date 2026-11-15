package imchan

// 企微回调通道契约测试：加解密回环/验签/解析正反形态/同步回复派发/URL 验证/
// Send 应用消息（httptest 假端点）/Close 语义。

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

const testAESKey = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"

func newWecomFixture(t *testing.T) *WecomChannel {
	t.Helper()
	w := NewWecomChannel("wecom-1", "test-token", testAESKey, "corp-x", "secret-x", "1000002")
	if len(w.aesKey) != 32 {
		t.Fatalf("AES key 解码应 32B，得 %d", len(w.aesKey))
	}
	return w
}

func wecomTestEncrypt(t *testing.T, key []byte, msg, receiveid string) string {
	t.Helper()
	random := make([]byte, 16)
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(msg)))
	plain := append(append(random, lenBytes...), []byte(msg)...)
	plain = append(plain, []byte(receiveid)...)
	pad := 32 - len(plain)%32
	for range pad {
		plain = append(plain, byte(pad))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	ct := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, key[:16]).CryptBlocks(ct, plain)
	return base64.StdEncoding.EncodeToString(ct)
}

func wecomTestSig(parts ...string) string {
	slices.Sort(parts)
	sum := sha1.Sum([]byte(strings.Join(parts, "")))
	return fmt.Sprintf("%x", sum)
}

func TestWecomCryptoRoundtrip(t *testing.T) {
	w := newWecomFixture(t)
	const ts, nonce = "1700000000", "n-1"
	enc, sig, err := w.Encrypt(`{"x":1}`, "corp-x", ts, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if !w.VerifySignature(ts, nonce, enc, sig) {
		t.Fatal("加密体签名应自洽")
	}
	msg, receiveid, err := w.Decrypt(enc)
	if err != nil || msg != `{"x":1}` || receiveid != "corp-x" {
		t.Fatalf("回环失败: msg=%s receiveid=%s err=%v", msg, receiveid, err)
	}
	if w.VerifySignature(ts, nonce, enc, "bad") {
		t.Fatal("坏签名应不通过")
	}
	// 非法 EncodingAESKey / 密文形态必须显形，不得静默。
	bad := NewWecomChannel("bad", "tok", "short", "", "", "")
	if _, _, err := bad.Decrypt("AAAA"); err == nil {
		t.Fatal("非法 AESKey 应报错")
	}
	if _, _, err := w.Decrypt("not-base64!"); err == nil {
		t.Fatal("非法 Base64 应报错")
	}
	if _, _, err := w.Decrypt(base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Fatal("短密文应报错")
	}
}

// TestWecomParseMessage 正反形态：text 单聊/群聊归一；event/空正文/缺发送者
// 一律 nil（不惊动宿主诊断）。
func TestWecomParseMessage(t *testing.T) {
	payloadJSON := `{"msgid":"m-1","msgtype":"text","chattype":"single",` +
		`"from":{"userid":"user-7"},"text":{"content":" 排查负载 "}}`
	msg := ParseWecomMessage(payloadJSON)
	if msg == nil {
		t.Fatal("应解析出消息")
	}
	if msg.Subject != "user-7" || msg.ChatType != ChatP2P || msg.Text != "排查负载" ||
		msg.Kind != KindWecom || msg.Sender != "user-7" || msg.MsgID != "m-1" {
		t.Fatalf("解析形态错: %+v", msg)
	}
	group := ParseWecomMessage(`{"msgid":"m-2","msgtype":"text","chattype":"group",` +
		`"from":{"userid":"user-8"},"text":{"content":"群问题"}}`)
	if group == nil || group.ChatType != ChatGroup {
		t.Fatalf("群聊归一错: %+v", group)
	}
	for _, bad := range []string{
		`{"msgid":"m","msgtype":"event"}`,
		`{"msgid":"m","msgtype":"text","from":{"userid":"u"},"text":{"content":"  "}}`,
		`{"msgid":"m","msgtype":"text","text":{"content":"hi"}}`,
		`not json`,
	} {
		if got := ParseWecomMessage(bad); got != nil {
			t.Fatalf("负形态应忽略 %q，实得 %+v", bad, got)
		}
	}
}

func TestWecomHandleCallback(t *testing.T) {
	w := newWecomFixture(t)
	var got InboundMessage
	if err := w.Start(context.Background(), func(m InboundMessage) { got = m }); err != nil {
		t.Fatal(err)
	}
	if !w.Connected() {
		t.Fatal("handler 注册后应 Connected")
	}
	payloadJSON := `{"msgid":"m-2","msgtype":"text","chattype":"single",` +
		`"from":{"userid":"user-7"},"text":{"content":"回调探针"}}`
	const ts, nonce = "1700000001", "n-2"
	encrypt := wecomTestEncrypt(t, w.aesKey, payloadJSON, "")
	sig := wecomTestSig("test-token", ts, nonce, encrypt)
	enc, rsig, err := w.HandleCallback(context.Background(), sig, ts, nonce, encrypt)
	if err != nil {
		t.Fatal(err)
	}
	if got.Text != "回调探针" || got.Channel != "wecom-1" || got.Kind != KindWecom {
		t.Fatalf("handler 未派发: %+v", got)
	}
	plain, _, err := w.Decrypt(enc)
	if err != nil || !strings.Contains(plain, "已收到") {
		t.Fatalf("同步回复解密失败: %.60s %v", plain, err)
	}
	if !w.VerifySignature(ts, nonce, enc, rsig) {
		t.Fatal("同步回复签名应自洽")
	}
	if _, _, err := w.HandleCallback(context.Background(), "bad", ts, nonce, encrypt); err == nil {
		t.Fatal("坏签名应拒")
	}
	if _, err := w.VerifyURL("bad", ts, nonce, encrypt); err == nil {
		t.Fatal("URL 验证坏签名应拒")
	}
}

func TestWecomHandleCallbackBeforeStart(t *testing.T) {
	w := newWecomFixture(t)
	payloadJSON := `{"msgid":"m-3","msgtype":"text","from":{"userid":"u"},"text":{"content":"hi"}}`
	const ts, nonce = "1700000003", "n-3"
	encrypt := wecomTestEncrypt(t, w.aesKey, payloadJSON, "")
	sig := wecomTestSig("test-token", ts, nonce, encrypt)
	if _, _, err := w.HandleCallback(context.Background(), sig, ts, nonce, encrypt); err == nil ||
		!strings.Contains(err.Error(), "未启动") {
		t.Fatalf("未注册 handler 应显形: %v", err)
	}
	if err := w.Start(context.Background(), nil); err == nil {
		t.Fatal("nil handler 应拒")
	}
}

func TestWecomVerifyURL(t *testing.T) {
	w := newWecomFixture(t)
	const echo = "echo-plaintext-123"
	const ts, nonce = "1700000002", "n-3"
	encrypt := wecomTestEncrypt(t, w.aesKey, echo, "")
	sig := wecomTestSig("test-token", ts, nonce, encrypt)
	plain, err := w.VerifyURL(sig, ts, nonce, encrypt)
	if err != nil || plain != echo {
		t.Fatalf("URL 验证失败: plain=%q err=%v", plain, err)
	}
}

func TestWecomSendAppMessage(t *testing.T) {
	var gotPath, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.URL.Path == "/cgi-bin/gettoken" {
			_, _ = fmt.Fprint(w, `{"errcode":0,"access_token":"at-1","expires_in":7200}`)
			return
		}
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		gotBody = string(buf[:n])
		_, _ = fmt.Fprint(w, `{"errcode":0,"errmsg":"ok"}`)
	}))
	defer srv.Close()
	oldBase := wecomAPIBase
	wecomAPIBase = srv.URL
	defer func() { wecomAPIBase = oldBase }()

	w := newWecomFixture(t)
	if err := w.Send("user-7", ChatP2P, "诊断报告推送"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/cgi-bin/message/send" {
		t.Fatalf("应用消息路径错: %s", gotPath)
	}
	if !strings.Contains(gotBody, "user-7") || !strings.Contains(gotBody, "诊断报告推送") {
		t.Fatalf("推送体错: %s", gotBody)
	}
	// 二次调用走 access_token 缓存（仍成功）。
	if err := w.Send("user-7", ChatP2P, "第二条"); err != nil {
		t.Fatalf("第二条: %v", err)
	}
	if err := w.Probe(); err != nil {
		t.Fatalf("探活应通过: %v", err)
	}
}

// TestWecomProbeRejects 凭证缺失/被拒的正反形态。
func TestWecomProbeRejects(t *testing.T) {
	w := NewWecomChannel("w", "tok", testAESKey, "", "", "")
	if err := w.Probe(); err == nil {
		t.Fatal("缺凭证应拒")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"errcode":40013,"errmsg":"invalid corpid"}`)
	}))
	defer srv.Close()
	oldBase := wecomAPIBase
	wecomAPIBase = srv.URL
	defer func() { wecomAPIBase = oldBase }()
	if err := newWecomFixture(t).Probe(); err == nil {
		t.Fatal("被拒凭证应报错")
	}
}

// TestWecomClose Close 后 Connected=false、Start 返回 ErrClosed、回调显形。
func TestWecomClose(t *testing.T) {
	w := newWecomFixture(t)
	if err := w.Start(context.Background(), func(InboundMessage) {}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if w.Connected() {
		t.Fatal("Close 后不应 Connected")
	}
	if err := w.Start(context.Background(), func(InboundMessage) {}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Close 后 Start 应返回 ErrClosed: %v", err)
	}
	if err := w.Send("user-1", ChatP2P, "hi"); !errors.Is(err, ErrClosed) {
		t.Fatalf("Close 后回投应 ErrClosed: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close 应幂等: %v", err)
	}
	payloadJSON := `{"msgid":"m-4","msgtype":"text","from":{"userid":"u"},"text":{"content":"hi"}}`
	const ts, nonce = "1700000004", "n-4"
	encrypt := wecomTestEncrypt(t, w.aesKey, payloadJSON, "")
	sig := wecomTestSig("test-token", ts, nonce, encrypt)
	if _, _, err := w.HandleCallback(context.Background(), sig, ts, nonce, encrypt); !errors.Is(err, ErrClosed) {
		t.Fatalf("Close 后回调应返回 ErrClosed: %v", err)
	}
}
