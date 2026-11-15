package imchan

// wecom.go — 企业微信智能机器人回调通道：HTTP 回调形态（企微无机器人 WS
// 网关——「出站连接型」选型的例外）。本通道只提供验签/解密/解析/派发/回投
// 能力；公开入口的验签+加密由宿主 HTTP 端点驱动，回调参数原样交给
// CallbackChannel 扩展接口。
//
// 协议（企微通用加解密方案 + 智能机器人 JSON 载荷）：
//   - 签名 = SHA1(字典序排序(token, timestamp, nonce, encrypt) 拼接)；
//   - 解密 = Base64Decode(encrypt) → AES-256-CBC（key=Base64Decode(aesKey+"=")，
//     IV=key[:16]）→ 去 PKCS7 → random(16B)+msg_len(4B 网络序)+msg+receiveid；
//   - GET URL 验证：解密 echostr 明文原样返回；POST 消息：派发后同步加密回复；
//   - Send：应用消息 API（touser=subject；access_token 进程内缓存至过期前 5 分钟）。

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// wecomAPIBase 企微 API 基址（包级变量：测试换 httptest 假端点；生产恒官方）。
var wecomAPIBase = "https://qyapi.weixin.qq.com"

// WecomChannel 企微回调通道。
type WecomChannel struct {
	id      string
	token   string // 回调验签 token
	aesKey  []byte // 32B（EncodingAESKey+"=" Base64 解码）
	corpID  string // 企业 ID（应用消息 access_token）
	secret  string // 应用消息 corpsecret
	agentID int    // 应用 agentid

	tokMu    sync.Mutex
	accToken string
	accExp   time.Time

	http *http.Client

	mu      sync.Mutex
	handler func(InboundMessage)
	closed  bool
}

// NewWecomChannel 构造（encodingAESKey 为企微后台的 43 字符 Base64 串；agentID
// 非数字时 Send 面报错显形——回调面不依赖它）。
func NewWecomChannel(id, token, encodingAESKey, corpID, secret, agentID string) *WecomChannel {
	w := &WecomChannel{
		id: id, token: token, corpID: corpID, secret: secret,
		http: &http.Client{Timeout: 15 * time.Second},
	}
	if k, err := base64.StdEncoding.DecodeString(encodingAESKey + "="); err == nil && len(k) == 32 {
		w.aesKey = k
	}
	w.agentID = atoiDefault(agentID)
	return w
}

// ID 通道实例 id。
func (w *WecomChannel) ID() string { return w.id }

// Kind 通道类型。
func (w *WecomChannel) Kind() string { return KindWecom }

// Connected handler 已注册且通道未关闭。
func (w *WecomChannel) Connected() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.handler != nil && !w.closed
}

// Start 非阻塞：注册入站 handler 即返回（企微回调经宿主 HTTP 端点同步进入
// HandleCallback；宿主生命周期 goroutine 立即退出，通道常驻态由 handler
// 有无表达）。回调形态与长连接形态的 Start 语义差异在 Channel 文档已声明。
func (w *WecomChannel) Start(_ context.Context, handler func(InboundMessage)) error {
	if handler == nil {
		return fmt.Errorf("imchan: wecom 通道 %s 的 handler 为空", w.id)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrClosed
	}
	w.handler = handler
	return nil
}

// Close 摘除 handler 并标记关闭（幂等）。已注册的 HTTP 端点后续回调返回
// 「未启动」错误，不会静默吞消息。
func (w *WecomChannel) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	w.handler = nil
	return nil
}

// VerifySignature 回调验签：SHA1(字典序排序(token,timestamp,nonce,encrypt)
// 拼接)。恒时比对——普通字符串比较在签名前缀命中时有逐字节时序差。
func (w *WecomChannel) VerifySignature(timestamp, nonce, encrypt, msgSignature string) bool {
	parts := []string{w.token, timestamp, nonce, encrypt}
	slices.Sort(parts)
	sum := sha1Sum(strings.Join(parts, ""))
	return subtle.ConstantTimeCompare([]byte(sum), []byte(msgSignature)) == 1
}

// Decrypt 回调解密：返回（消息 JSON, receiveid, error）。
func (w *WecomChannel) Decrypt(encrypt string) (string, string, error) {
	if len(w.aesKey) != 32 {
		return "", "", fmt.Errorf("EncodingAESKey 非法（解码后须 32 字节）")
	}
	ct, err := base64.StdEncoding.DecodeString(encrypt)
	if err != nil {
		return "", "", fmt.Errorf("密文 Base64 非法: %w", err)
	}
	block, err := aes.NewCipher(w.aesKey)
	if err != nil {
		return "", "", err
	}
	if len(ct) < 48 || len(ct)%16 != 0 {
		return "", "", fmt.Errorf("密文长度非法（%d）", len(ct))
	}
	iv := w.aesKey[:16]
	plain := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ct)
	plain = pkcs7Unpad(plain)
	if len(plain) < 20 {
		return "", "", fmt.Errorf("解密明文过短")
	}
	msgLen := binary.BigEndian.Uint32(plain[16:20])
	if int(20+msgLen) > len(plain) {
		return "", "", fmt.Errorf("解密 msg_len 越界")
	}
	return string(plain[20 : 20+msgLen]), string(plain[20+msgLen:]), nil
}

// Encrypt 回复加密：明文 → 企微信封（random+len+msg+receiveid）→ AES-CBC →
// Base64，附回调应答所需的 msg_signature。
func (w *WecomChannel) Encrypt(msg, receiveid, timestamp, nonce string) (encrypted, signature string, err error) {
	if len(w.aesKey) != 32 {
		return "", "", fmt.Errorf("EncodingAESKey 非法")
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", "", err
	}
	buf := make([]byte, 0, 20+len(msg)+len(receiveid))
	buf = append(buf, random...)
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(msg)))
	buf = append(buf, lenBytes...)
	buf = append(buf, []byte(msg)...)
	buf = append(buf, []byte(receiveid)...)

	block, err := aes.NewCipher(w.aesKey)
	if err != nil {
		return "", "", err
	}
	padded := pkcs7Pad(buf, 32)
	ct := make([]byte, len(padded))
	enc := cipher.NewCBCEncrypter(block, w.aesKey[:16])
	enc.CryptBlocks(ct, padded)
	encrypted = base64.StdEncoding.EncodeToString(ct)
	// 签名与 VerifySignature 同式：字典序排序后拼接（企微协议要求）。
	parts := []string{w.token, timestamp, nonce, encrypted}
	slices.Sort(parts)
	signature = sha1Sum(strings.Join(parts, ""))
	return encrypted, signature, nil
}

// wecomInboundMsg 智能机器人回调载荷（字段按企微文档宽松解析——未知形态忽略）。
type wecomInboundMsg struct {
	MsgID          string `json:"msgid"`
	MsgType        string `json:"msgtype"`
	ChatType       string `json:"chattype"` // single | group
	ConversationID string `json:"conversationid"`
	From           struct {
		UserID string `json:"userid"`
	} `json:"from"`
	Text struct {
		Content string `json:"content"`
	} `json:"text"`
}

// ParseWecomMessage 载荷 → 统一入站模型（text 消息；Subject=from.userid——应用
// 消息回投的 touser 与之同键；群聊 conversationid 作群锚点备用字段不参与路由
// v1）。非 text / 空正文 / 缺发送者返回 nil。
func ParseWecomMessage(payloadJSON string) *InboundMessage {
	var m wecomInboundMsg
	if err := json.Unmarshal([]byte(payloadJSON), &m); err != nil || m.MsgType != "text" {
		return nil
	}
	content := strings.TrimSpace(m.Text.Content)
	if content == "" || m.From.UserID == "" {
		return nil
	}
	chatType := ChatP2P
	if m.ChatType == "group" {
		chatType = ChatGroup
	}
	return &InboundMessage{
		Kind: KindWecom, Subject: m.From.UserID, ChatType: chatType,
		Sender: m.From.UserID, Text: content, MsgID: m.MsgID,
	}
}

// scrubSecret 从错误文案里抹掉 corpsecret（错误文案是数据出口，不是日志——
// 它会经宿主的通道测试 detail 回显进 API 响应）。
func (w *WecomChannel) scrubSecret(msg string) string {
	if w.secret == "" {
		return msg
	}
	return strings.ReplaceAll(msg, w.secret, "***")
}

// Probe 凭证探活：gettoken 一次（corpid+corpsecret）。
func (w *WecomChannel) Probe() error {
	if w.corpID == "" || w.secret == "" {
		return fmt.Errorf("凭证缺失（corp_id/corp_secret 为空）")
	}
	url := fmt.Sprintf("%s/cgi-bin/gettoken?corpid=%s&corpsecret=%s", wecomAPIBase, w.corpID, w.secret)
	resp, err := w.http.Get(url)
	if err != nil {
		// 错误文案脱敏：Go 的 url.Error 只遮蔽 URL userinfo 里的密码，不遮蔽
		// query 参数 ⇒ corpsecret 会原样进错误文案。协议侧无法把 secret 移出
		// query（企微 gettoken 的官方形态就是 query），故在错误文案源头抹掉。
		return fmt.Errorf("企微 API 不可达: %s", w.scrubSecret(err.Error()))
	}
	defer resp.Body.Close() //nolint:errcheck // 响应体只读一次
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var out struct {
		ErrCode     int    `json:"errcode"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || (out.ErrCode != 0 && out.AccessToken == "") {
		return fmt.Errorf("企微凭证被拒（HTTP %d）", resp.StatusCode)
	}
	return nil
}

// Send 应用消息推送（touser=subject；access_token 缓存至过期前 5 分钟）。
func (w *WecomChannel) Send(subject, chatType, text string) error {
	_ = chatType // 应用消息按 touser 投递，p2p/group 同路
	tok, err := w.accessToken()
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]any{
		"touser": subject, "msgtype": "text", "agentid": w.agentID,
		"text": map[string]string{"content": text},
	})
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s/cgi-bin/message/send?access_token=%s", wecomAPIBase, tok)
	resp, err := w.http.Post(url, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("企微推送不可达: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // 响应体只读一次
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var out struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("企微推送响应非法（HTTP %d）", resp.StatusCode)
	}
	if out.ErrCode != 0 {
		return fmt.Errorf("企微推送失败: errcode=%d msg=%s", out.ErrCode, out.ErrMsg)
	}
	return nil
}

// accessToken 取/刷应用令牌（过期前 5 分钟失效）。
func (w *WecomChannel) accessToken() (string, error) {
	w.tokMu.Lock()
	defer w.tokMu.Unlock()
	if w.accToken != "" && time.Now().Before(w.accExp.Add(-5*time.Minute)) {
		return w.accToken, nil
	}
	if w.corpID == "" || w.secret == "" {
		return "", fmt.Errorf("企微凭证缺失（corp_id/corp_secret）")
	}
	url := fmt.Sprintf("%s/cgi-bin/gettoken?corpid=%s&corpsecret=%s", wecomAPIBase, w.corpID, w.secret)
	resp, err := w.http.Get(url)
	if err != nil {
		// 同 Probe：错误文案含整条 URL（corpsecret 明文）⇒ 出栈前抹掉。
		return "", fmt.Errorf("企微 API 不可达: %s", w.scrubSecret(err.Error()))
	}
	defer resp.Body.Close() //nolint:errcheck // 响应体只读一次
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var out struct {
		ErrCode     int    `json:"errcode"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.AccessToken == "" {
		return "", fmt.Errorf("企微 access_token 获取失败（HTTP %d raw=%.120s）", resp.StatusCode, raw)
	}
	w.accToken, w.accExp = out.AccessToken, time.Now().Add(time.Duration(out.ExpiresIn)*time.Second)
	return w.accToken, nil
}

// HandleCallback POST 消息回调（宿主 HTTP handler 调用）：验签 → 解密 → 派发 →
// 同步加密回复。返回（加密回复体, msg_signature, error）。
func (w *WecomChannel) HandleCallback(ctx context.Context, msgSignature, timestamp, nonce, body string) (encrypted, signature string, err error) {
	_ = ctx
	if !w.VerifySignature(timestamp, nonce, body, msgSignature) {
		return "", "", fmt.Errorf("回调签名校验失败")
	}
	payloadJSON, _, err := w.Decrypt(body)
	if err != nil {
		return "", "", err
	}
	w.mu.Lock()
	h := w.handler
	closed := w.closed
	w.mu.Unlock()
	if closed {
		return "", "", ErrClosed
	}
	if h == nil {
		return "", "", fmt.Errorf("wecom 通道未启动（handler 未注册）")
	}
	if msg := ParseWecomMessage(payloadJSON); msg != nil {
		msg.Channel = w.ID() // 平面路由键（缺省空串会被宿主判 nil 静默丢消息）
		h(*msg)
	}
	reply := `{"msgtype":"text","text":{"content":"已收到，处理中。"}}`
	enc, sig, err := w.Encrypt(reply, "", timestamp, nonce)
	return enc, sig, err
}

// VerifyURL GET 回调验证：解密 echostr 明文返回（企微比对通过才认可回调地址）。
func (w *WecomChannel) VerifyURL(msgSignature, timestamp, nonce, echostr string) (string, error) {
	if !w.VerifySignature(timestamp, nonce, echostr, msgSignature) {
		return "", fmt.Errorf("URL 验证签名校验失败")
	}
	plain, _, err := w.Decrypt(echostr)
	return plain, err
}

// ── 协议小助手 ──

func sha1Sum(s string) string {
	sum := sha1.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func pkcs7Pad(b []byte, blockSize int) []byte {
	pad := blockSize - len(b)%blockSize
	out := make([]byte, len(b)+pad)
	copy(out, b)
	for i := len(b); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

func pkcs7Unpad(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	pad := int(b[len(b)-1])
	if pad == 0 || pad > 32 || pad > len(b) {
		return b
	}
	return b[:len(b)-pad]
}

func atoiDefault(s string) int {
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return v
}

var (
	_ Channel         = (*WecomChannel)(nil)
	_ Sender          = (*WecomChannel)(nil)
	_ CallbackChannel = (*WecomChannel)(nil)
)
