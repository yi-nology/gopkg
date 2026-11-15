package openaicompat

import (
	"encoding/json"
	"errors"
	"strings"
)

// OpenAI 对象类型常量（object 字段只在这里定义一份）。
const (
	ObjectChatCompletion      = "chat.completion"
	ObjectChatCompletionChunk = "chat.completion.chunk"
	ObjectList                = "list"
)

// ErrNoInput messages 里没有可用的用户输入文本（请求翻译的唯一拒绝条件）。
var ErrNoInput = errors.New("messages 缺少可用输入文本")

// ChatRequest chat/completions 请求子集（OpenAI 线格式）。
type ChatRequest struct {
	Model    string        `json:"model"`
	Messages []ChatMessage `json:"messages"`
	Stream   bool          `json:"stream"`
}

// ChatMessage content 双形态兼容：纯字符串，或 content parts 数组
// （[{"type":"text","text":"…"}]）。原样保留 JSON，翻译时只抽取 text 部分。
type ChatMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

// Turn 请求翻译后的宿主无关轮次：Input=本轮用户输入，Instruction=历史
// （system/assistant/更早 user）拼成的会话设定段，Model=请求 model 原值
// （专家 slug 或别名，语义归宿主）。宿主把它映射成自家会话创建参数。
type Turn struct {
	Model       string
	Input       string
	Instruction string
	Stream      bool
}

// DecodeChatRequest 解码请求线格式（协议单源入口）。
func DecodeChatRequest(data []byte) (*ChatRequest, error) {
	var req ChatRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

// EncodeChatRequest 编码请求线格式（往返映射测试/代理场景）。
func EncodeChatRequest(req *ChatRequest) ([]byte, error) {
	return json.Marshal(req)
}

// ContentText content 双形态抽取：纯字符串原样；parts 数组只取 type=text
// （或 type 缺省）的 text 拼接；其余形态=空串。图片/音频等非文本部件不进
// 诊断上下文。
func ContentText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &parts); err == nil {
		var sb strings.Builder
		for _, p := range parts {
			if p.Type == "text" || p.Type == "" {
				sb.WriteString(p.Text)
			}
		}
		return sb.String()
	}
	return ""
}

// SplitMessages messages → (本轮输入, 会话设定)：末条 user 当输入；其余
// 有文本的条目按序拼成 "role: text" 会话设定（数据非指令，不得推翻平台
// 纪律）。无 user 条目时用末条内容兜底（单轮补全客户端的常见形态）。
func SplitMessages(msgs []ChatMessage) (input, instruction string) {
	lastUser := -1
	for i, m := range msgs {
		if strings.EqualFold(m.Role, "user") {
			lastUser = i
		}
	}
	if lastUser < 0 && len(msgs) > 0 {
		lastUser = len(msgs) - 1
	}
	var hist []string
	for i, m := range msgs {
		text := strings.TrimSpace(ContentText(m.Content))
		if text == "" {
			continue
		}
		if i == lastUser {
			input = text
			continue
		}
		hist = append(hist, m.Role+": "+text)
	}
	return input, strings.Join(hist, "\n")
}

// TranslateRequest 请求 → Turn（协议翻译单源）。无可用输入返回 ErrNoInput。
func TranslateRequest(req *ChatRequest) (Turn, error) {
	if req == nil {
		return Turn{}, ErrNoInput
	}
	input, instruction := SplitMessages(req.Messages)
	if strings.TrimSpace(input) == "" {
		return Turn{}, ErrNoInput
	}
	return Turn{
		Model:       req.Model,
		Input:       input,
		Instruction: instruction,
		Stream:      req.Stream,
	}, nil
}

// ── 非流式补全对象 ──

// Completion chat.completion 对象。
type Completion struct {
	ID      string             `json:"id"`
	Object  string             `json:"object"`
	Created int64              `json:"created"`
	Model   string             `json:"model"`
	Choices []CompletionChoice `json:"choices"`
}

// CompletionChoice 非流式 choice（message 形态）。
type CompletionChoice struct {
	Index        int        `json:"index"`
	Message      OutMessage `json:"message"`
	FinishReason string     `json:"finish_reason"`
}

// OutMessage assistant 输出消息。
type OutMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// NewCompletion 构造非流式补全（content=终报全文，等价流式累积）。
func NewCompletion(id, model string, created int64, content string) Completion {
	return Completion{
		ID:      id,
		Object:  ObjectChatCompletion,
		Created: created,
		Model:   model,
		Choices: []CompletionChoice{{
			Index:        0,
			Message:      OutMessage{Role: "assistant", Content: content},
			FinishReason: "stop",
		}},
	}
}

// DecodeCompletion 解码非流式补全（往返映射/客户端场景）。
func DecodeCompletion(data []byte) (Completion, error) {
	var c Completion
	if err := json.Unmarshal(data, &c); err != nil {
		return Completion{}, err
	}
	return c, nil
}

// EncodeCompletion 编码非流式补全。
func EncodeCompletion(c Completion) ([]byte, error) {
	return json.Marshal(c)
}

// ── 流式 chunk 帧 ──

// Chunk chat.completion.chunk 帧（OpenAI SSE 形态）。
type Chunk struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []Choice `json:"choices"`
	Usage   *Usage   `json:"usage,omitempty"`
}

// Choice 流式 choice（delta 形态）。
type Choice struct {
	Index        int    `json:"index"`
	Delta        Delta  `json:"delta"`
	FinishReason string `json:"finish_reason,omitempty"` // 空=继续流；"stop"=收口
}

// Delta 增量体。reasoning_content 是 DeepSeek 系扩展字段（OpenAI 兼容生态
// 约定俗成：思考流不进 content，客户端按需取用）。
type Delta struct {
	Content          string `json:"content,omitempty"`
	ReasoningContent string `json:"reasoning_content,omitempty"`
}

// Usage token 用量（OpenAI 惯例只在末帧出现，累计口径）。
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// DecodeChunk 解码流式帧（往返映射/客户端场景）。
func DecodeChunk(data []byte) (Chunk, error) {
	var c Chunk
	if err := json.Unmarshal(data, &c); err != nil {
		return Chunk{}, err
	}
	return c, nil
}

// EncodeChunk 编码流式帧。
func EncodeChunk(c Chunk) ([]byte, error) {
	return json.Marshal(c)
}
