package bot

// IM 机器人出向载荷构造器：企业微信群机器人 / 钉钉自定义机器人 / 飞书
// 自定义机器人的 JSON 线格式单源。
//
// # 与同包平台子包的分工（别混用）
//
//	biz/bot/dingtalk|lark|wxwork|lanxin   —— 发送路径：消息结构体 + 签名/
//	                                        关键字安全模式 + HTTP 发送
//	biz/bot（本文件）                      —— 只产字节：纯函数、零网络
//
// 两者线格式在 wecom/feishu 上逐字节一致；**钉钉不同**：平台子包的
// dingtalk.MarkDownMessage 携带 At 字段（@人能力），本文件的
// DingtalkMarkdownPayload 是不带 at 的最小形态——#485 的契约按最小形态
// 钉死。需要 @人 走平台子包，只要载荷字节（自己发、进队列、拼审计）
// 走本文件。
//
// # 边界哲学
//
// 纯函数、零网络、零重试——HTTP 发送、鉴权（钉钉 secret 签名挂在 URL
// query、飞书签名在 payload 外层拼接，两者都属「发送面」）、超长截断都
// 不在本包。长度上限（企微 markdown content ~4096 字节等）随平台漂移，
// 本包不做有损截断——静默截断会把「没发全」伪装成「发完了」，要截断由
// 调用方按自己的审计需求显式决策。
//
// 变体范围：企微 markdown、钉钉 markdown、飞书 text 三种。text/markdown
// 交叉变体与卡片结构（飞书 interactive card 等深水区）按需再进——只有
// 公开稳定的平台约定才进单源。

import (
	"encoding/json"
	"errors"
	"fmt"
)

// 载荷错误哨兵（errors.Is 判定）。
var (
	// ErrUnknownIMChannel BuildIMPayload 查无此渠道（含空渠道名）——
	// 渠道路由是配置问题，与载荷内容问题分属两类。
	ErrUnknownIMChannel = errors.New("bot: 未知 IM 渠道")
	// ErrEmptyIMPayload 必填内容为空串——空内容通知没有意义，构造期
	// 拒绝（fail-fast）。标题不受此限，见各构造器说明。
	ErrEmptyIMPayload = errors.New("bot: IM 载荷内容为空")
)

// IM 渠道名常量：配置驱动的下游按名路由，键名与宿主既有策略表同源。
const (
	ChannelWecom    = "wecom"    // 企业微信群机器人
	ChannelDingtalk = "dingtalk" // 钉钉自定义机器人
	ChannelFeishu   = "feishu"   // 飞书自定义机器人
)

// 企微 markdown 载荷线格式（字段序即字节序，契约测试按此钉住）。
type wecomMarkdownPayload struct {
	MsgType  string `json:"msgtype"`
	Markdown struct {
		Content string `json:"content"`
	} `json:"markdown"`
}

// 钉钉 markdown 载荷线格式（最小形态，不含 At——见包文档分工说明）。
type dingtalkMarkdownPayload struct {
	MsgType  string `json:"msgtype"`
	Markdown struct {
		Title string `json:"title"`
		Text  string `json:"text"`
	} `json:"markdown"`
}

// 飞书 text 载荷线格式（注意 msg_type 是下划线——与企微/钉钉的 msgtype
// 是两种历史拼写，正是本单源要消歧的「谁在用谁」）。
type feishuTextPayload struct {
	MsgType string `json:"msg_type"`
	Content struct {
		Text string `json:"text"`
	} `json:"content"`
}

// WecomMarkdownPayload 企业微信群机器人 markdown 载荷：
//
//	{"msgtype":"markdown","markdown":{"content":"<md>"}}
//
// md 为空串返回包 ErrEmptyIMPayload 的 error。title 形态缺位是企微平台
// 约定——markdown 卡片没有标题字段，会话列表预览取 content 首行，需要
// 标题的调用方自行放进 md 开头。
func WecomMarkdownPayload(md string) ([]byte, error) {
	if md == "" {
		return nil, fmt.Errorf("%w: 企业微信 markdown content", ErrEmptyIMPayload)
	}
	var p wecomMarkdownPayload
	p.MsgType = "markdown"
	p.Markdown.Content = md
	b, err := json.Marshal(&p)
	if err != nil {
		return nil, fmt.Errorf("bot: 企业微信载荷序列化失败: %w", err)
	}
	return b, nil
}

// DingtalkMarkdownPayload 钉钉自定义机器人 markdown 载荷：
//
//	{"msgtype":"markdown","markdown":{"title":"<title>","text":"<md>"}}
//
// title 是会话列表/通知预览的**宿主内容**（卡片文案属宿主，构造器不写
// 死），空串按平台约定放行（钉钉收空标题、预览显示空）；md 为空串返回
// 包 ErrEmptyIMPayload 的 error。
func DingtalkMarkdownPayload(title, md string) ([]byte, error) {
	if md == "" {
		return nil, fmt.Errorf("%w: 钉钉 markdown text", ErrEmptyIMPayload)
	}
	var p dingtalkMarkdownPayload
	p.MsgType = "markdown"
	p.Markdown.Title = title
	p.Markdown.Text = md
	b, err := json.Marshal(&p)
	if err != nil {
		return nil, fmt.Errorf("bot: 钉钉载荷序列化失败: %w", err)
	}
	return b, nil
}

// FeishuTextPayload 飞书自定义机器人 text 载荷：
//
//	{"msg_type":"text","content":{"text":"<text>"}}
//
// text 为空串返回包 ErrEmptyIMPayload 的 error。飞书的 markdown 走
// interactive card 深水区（卡片结构随版本漂移，无稳定公开契约），首版
// 只钉 text 形态。
func FeishuTextPayload(text string) ([]byte, error) {
	if text == "" {
		return nil, fmt.Errorf("%w: 飞书 text content", ErrEmptyIMPayload)
	}
	var p feishuTextPayload
	p.MsgType = "text"
	p.Content.Text = text
	b, err := json.Marshal(&p)
	if err != nil {
		return nil, fmt.Errorf("bot: 飞书载荷序列化失败: %w", err)
	}
	return b, nil
}

// BuildIMPayload 按渠道名分发到对应构造器——配置驱动（渠道名来自配置
// 而非代码分支）的下游用一次调用替代各自的策略表，宿主不必再维护一张
// channel→builder 映射。
//
// 参数语义随渠道而异：wecom 只用 md；dingtalk 用 title+md；feishu 只用
// text——非该渠道用的参数原样忽略，调用方不必按渠道预先拆参数。渠道名
// 未知返回包 ErrUnknownIMChannel 的 error（配置错配在构造期暴露，不静默
// 产出「猜一个」的载荷）。
func BuildIMPayload(channel, title, md, text string) ([]byte, error) {
	switch channel {
	case ChannelWecom:
		return WecomMarkdownPayload(md)
	case ChannelDingtalk:
		return DingtalkMarkdownPayload(title, md)
	case ChannelFeishu:
		return FeishuTextPayload(text)
	case "":
		return nil, fmt.Errorf("%w: 渠道名为空串", ErrUnknownIMChannel)
	}
	return nil, fmt.Errorf("%w: %q", ErrUnknownIMChannel, channel)
}
