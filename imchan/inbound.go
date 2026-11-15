package imchan

import (
	"context"
	"errors"
	"io"
)

// ChatType 取值（统一入站模型口径；各通道适配器归一到这里）。
const (
	ChatP2P   = "p2p"
	ChatGroup = "group"
)

// Kind 通道类型常量（配置/管理面按名路由；键名与 bianque internal/im 同源，
// 迁移时不需要改配置）。
const (
	KindQQ         = "qq"
	KindWecomAibot = "wecom_aibot"
	KindLark       = "lark"
	KindDingTalk   = "dingtalk"
	KindWecom      = "wecom"
)

// ErrClosed 通道已被 Close。Start 在关闭后调用/被 Close 打断时返回此哨兵
// （ctx 主动取消仍返回 ctx.Err，调用方可据此区分「宿主收摊」与「通道内关」）。
var ErrClosed = errors.New("imchan: 通道已关闭")

// InboundMessage 统一入站模型（各通道适配器归一到此）。
//
// Channel 是通道实例 id（如 lark-1 / loopback），由通道实现填写——宿主按它
// 路由到通道实例；Kind 是通道类型（本包 Kind* 常量）。Subject 是回投目标
// （私聊=用户 id / open_id；群=群 id）；Sender 仅群聊诊断用，私聊可与 Subject
// 相同。
type InboundMessage struct {
	Channel  string // 通道实例 id（必须由通道实现填写）
	Kind     string // 通道类型（qq/wecom_aibot/lark/dingtalk/wecom）
	Subject  string // 回投目标（私聊=用户；群=群 id）
	ChatType string // p2p | group
	Text     string
	Sender   string // 发送者标识（群聊诊断用；私聊=Subject）
	MsgID    string // 通道侧消息 id（去重键）
	// Files 附件（惰性下载）：Name/MimeType 随消息带，Open 由通道适配器闭包
	// 提供（如飞书 message resource 按 message_id+file_key 现取）。宿主在
	// 处理阶段才消费，通道回调线程零 IO。
	Files []InboundFile
}

// InboundFile 通道侧附件。Open 可为 nil（纯元数据场景），调用方需判空。
type InboundFile struct {
	Name     string
	MimeType string
	Open     func() (io.ReadCloser, error)
}

// Channel 入站通道接口：Start 阻塞运行（ctx 取消退出；企微回调形态是唯一
// 例外——它只注册 handler 即返回，回调由宿主 HTTP 端点驱动），入站消息经
// handler 回调。Close 终止通道并释放连接；可重复调用，Start 若被 Close 打断
// 返回 ErrClosed。
type Channel interface {
	ID() string
	Kind() string
	Connected() bool
	Start(ctx context.Context, handler func(InboundMessage)) error
	Close() error
}

// Sender 平台回投能力。与 Channel 分开：入站桥接/测试替身只需实现 Channel；
// 本包五个内置通道都实现了 Sender。chatType 取 ChatP2P / ChatGroup。
type Sender interface {
	Send(subject, chatType, text string) error
}

// CallbackChannel 回调形态通道的扩展接口（企微回调）：宿主 HTTP 端点把
// 回调参数原样交给 HandleCallback / VerifyURL，拿回加密回复体与签名。
type CallbackChannel interface {
	Channel
	// HandleCallback POST 消息回调：验签 → 解密 → 派发 → 同步加密回复。
	HandleCallback(ctx context.Context, msgSignature, timestamp, nonce, body string) (encrypted, signature string, err error)
	// VerifyURL GET 回调验证：验签 → 解密 echostr 明文原样返回。
	VerifyURL(msgSignature, timestamp, nonce, echostr string) (string, error)
}
