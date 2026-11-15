package openaicompat

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestContentText(t *testing.T) {
	if got := ContentText(json.RawMessage(`"hello"`)); got != "hello" {
		t.Fatalf("string 形态: %q", got)
	}
	parts := `[{"type":"text","text":"a"},{"type":"image_url","image_url":{"url":"x"}},{"type":"text","text":"b"}]`
	if got := ContentText(json.RawMessage(parts)); got != "ab" {
		t.Fatalf("parts 形态只取 text: %q", got)
	}
	if got := ContentText(json.RawMessage(`{"unexpected":1}`)); got != "" {
		t.Fatalf("未知形态应空串: %q", got)
	}
	if got := ContentText(nil); got != "" {
		t.Fatalf("空 content 应空串: %q", got)
	}
}

func TestSplitMessages(t *testing.T) {
	msgs := []ChatMessage{
		{Role: "system", Content: json.RawMessage(`"你是运维专家"`)},
		{Role: "user", Content: json.RawMessage(`"磁盘满了"`)},
		{Role: "assistant", Content: json.RawMessage(`"已定位到 /var"`)},
		{Role: "user", Content: json.RawMessage(`"怎么清理"`)},
	}
	input, instruction := SplitMessages(msgs)
	if input != "怎么清理" {
		t.Fatalf("末条 user 应为输入: %q", input)
	}
	if !strings.Contains(instruction, "system: 你是运维专家") ||
		!strings.Contains(instruction, "user: 磁盘满了") ||
		!strings.Contains(instruction, "assistant: 已定位到 /var") {
		t.Fatalf("前文应入会话设定: %q", instruction)
	}
	if strings.Contains(instruction, "怎么清理") {
		t.Fatalf("输入不应重复入会话设定: %q", instruction)
	}
}

func TestSplitMessagesNoUser(t *testing.T) {
	input, _ := SplitMessages([]ChatMessage{{Role: "assistant", Content: json.RawMessage(`"孤本"`)}})
	if input != "孤本" {
		t.Fatalf("无 user 时末条兜底: %q", input)
	}
}

func TestTranslateRequest(t *testing.T) {
	req, err := DecodeChatRequest([]byte(`{"model":"gpt-4o","stream":true,"messages":[
		{"role":"system","content":"sys"},
		{"role":"user","content":[{"type":"text","text":"问题"}]}
	]}`))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	turn, err := TranslateRequest(req)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if turn.Model != "gpt-4o" || turn.Input != "问题" || turn.Instruction != "system: sys" || !turn.Stream {
		t.Fatalf("Turn 翻译不符: %+v", turn)
	}
}

func TestTranslateRequestNoInput(t *testing.T) {
	if _, err := TranslateRequest(nil); !errors.Is(err, ErrNoInput) {
		t.Fatalf("nil 请求应 ErrNoInput: %v", err)
	}
	req := &ChatRequest{Messages: []ChatMessage{
		{Role: "system", Content: json.RawMessage(`"只有设定"`)},
		{Role: "user", Content: json.RawMessage(`"   "`)},
	}}
	if _, err := TranslateRequest(req); !errors.Is(err, ErrNoInput) {
		t.Fatalf("无 user 文本应 ErrNoInput: %v", err)
	}
}

// TestChatRequestRoundTrip 请求线格式双向映射：decode → encode → decode，
// 字段与文本语义保持不变（content 双形态都覆盖）。
func TestChatRequestRoundTrip(t *testing.T) {
	raw := `{"model":"gpt-4o","stream":true,"messages":[
		{"role":"system","content":"sys"},
		{"role":"user","content":[{"type":"text","text":"a"},{"type":"image_url","image_url":{"url":"x"}},{"type":"text","text":"b"}]}
	]}`
	first, err := DecodeChatRequest([]byte(raw))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	encoded, err := EncodeChatRequest(first)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	second, err := DecodeChatRequest(encoded)
	if err != nil {
		t.Fatalf("Decode roundtrip: %v", err)
	}
	if second.Model != first.Model || second.Stream != first.Stream || len(second.Messages) != len(first.Messages) {
		t.Fatalf("往返字段不一致: first=%+v second=%+v", first, second)
	}
	for i := range first.Messages {
		if second.Messages[i].Role != first.Messages[i].Role {
			t.Fatalf("第 %d 条 role: %q != %q", i, second.Messages[i].Role, first.Messages[i].Role)
		}
		if got, want := ContentText(second.Messages[i].Content), ContentText(first.Messages[i].Content); got != want {
			t.Fatalf("第 %d 条 content 文本: %q != %q", i, got, want)
		}
	}
	if got := ContentText(second.Messages[1].Content); got != "ab" {
		t.Fatalf("parts 往返后文本: %q", got)
	}
}

func TestCompletionRoundTrip(t *testing.T) {
	first := NewCompletion("chatcmpl-1", "gpt-4o", 1700000000, "终报正文")
	encoded, err := EncodeCompletion(first)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	second, err := DecodeCompletion(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("补全对象往返不一致:\n first=%+v\nsecond=%+v", first, second)
	}
	if first.Object != ObjectChatCompletion || first.Choices[0].Message.Role != "assistant" ||
		first.Choices[0].FinishReason != "stop" {
		t.Fatalf("补全对象形态: %+v", first)
	}
}

func TestChunkRoundTrip(t *testing.T) {
	p := NewProjector("chatcmpl-1", "gpt-4o", 1700000000)
	p.Project(Event{Type: EventLLMUsage, Payload: map[string]any{"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}})
	first := p.Finish()
	encoded, err := EncodeChunk(first)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	second, err := DecodeChunk(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("chunk 往返不一致:\n first=%+v\nsecond=%+v", first, second)
	}
	if second.Object != ObjectChatCompletionChunk || second.Usage == nil || second.Usage.TotalTokens != 5 {
		t.Fatalf("chunk 形态: %+v", second)
	}
}
