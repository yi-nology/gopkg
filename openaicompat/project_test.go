package openaicompat

import "testing"

// TestProjectorSequence 全事件序投影（钉测面）：reasoning→思考字段、text/
// report→正文、usage 累计到末帧、turn_ended 才收口。
func TestProjectorSequence(t *testing.T) {
	p := NewProjector("chatcmpl-sess-1", "gpt-4o", 1700000000)
	if p.Done() || p.ContentEmitted() {
		t.Fatal("初始态应无收口无正文")
	}
	ev := func(typ string, payload map[string]any) Event {
		return Event{Type: typ, Payload: payload}
	}
	frames := p.Project(ev(EventReasoningDelta, map[string]any{"text": "思考"}))
	if len(frames) != 1 || frames[0].Choices[0].Delta.ReasoningContent != "思考" ||
		frames[0].Choices[0].Delta.Content != "" {
		t.Fatalf("reasoning 应走思考字段: %+v", frames)
	}
	frames = p.Project(ev(EventTextDelta, map[string]any{"text": "中间答复"}))
	if len(frames) != 1 || frames[0].Choices[0].Delta.Content != "中间答复" {
		t.Fatalf("text 应走正文字段: %+v", frames)
	}
	if !p.ContentEmitted() {
		t.Fatal("正文帧后 ContentEmitted 应真")
	}
	// usage 只累计不外发（float64 形态=JSON 反序列化常态）。
	if frames = p.Project(ev(EventLLMUsage, map[string]any{
		"prompt_tokens": float64(10), "completion_tokens": float64(5), "total_tokens": float64(15)})); frames != nil {
		t.Fatalf("usage 不应逐次外发: %+v", frames)
	}
	if frames = p.Project(ev(EventReportDelta, map[string]any{"text": "终报正文"})); len(frames) != 1 {
		t.Fatalf("report 应走正文: %+v", frames)
	}
	if p.Done() {
		t.Fatal("turn 未关不应 Done")
	}
	p.Project(ev(EventTurnEnded, map[string]any{"status": "succeeded", "closed_by": "loop"}))
	if !p.Done() || p.Status() != "succeeded" {
		t.Fatalf("turn_ended 后应收口: done=%v status=%q", p.Done(), p.Status())
	}
	if got := p.Usage(); got.PromptTokens != 10 || got.CompletionTokens != 5 || got.TotalTokens != 15 {
		t.Fatalf("累计 usage: %+v", got)
	}
	final := p.Finish()
	if final.Choices[0].FinishReason != "stop" {
		t.Fatalf("收口帧 finish_reason: %+v", final.Choices[0])
	}
	if final.Usage == nil || final.Usage.PromptTokens != 10 || final.Usage.CompletionTokens != 5 ||
		final.Usage.TotalTokens != 15 {
		t.Fatalf("末帧 usage 应为累计值: %+v", final.Usage)
	}
	if final.Object != ObjectChatCompletionChunk || final.ID != "chatcmpl-sess-1" || final.Model != "gpt-4o" {
		t.Fatalf("帧头三元组: %+v", final)
	}
}

func TestProjectorIgnoresNoise(t *testing.T) {
	p := NewProjector("chatcmpl-x", "m", 1)
	for _, ev := range []Event{
		{Type: EventToolCall, Payload: map[string]any{"tool": "run_analyzers"}},
		{Type: EventToolResult, Payload: map[string]any{"tool": "run_analyzers"}},
		{Type: EventTextDelta, Payload: map[string]any{"text": ""}},
		{Type: EventReasoning, Payload: map[string]any{"text": "权威快照"}},
		{Type: EventAgentText, Payload: map[string]any{"text": "权威快照"}},
		{Type: EventTurnStarted, Payload: map[string]any{}},
	} {
		if frames := p.Project(ev); frames != nil {
			t.Fatalf("%s 应忽略: %+v", ev.Type, frames)
		}
	}
	if p.ContentEmitted() || p.Done() {
		t.Fatal("噪音不置正文/收口标记")
	}
}

func TestProjectorUsageForms(t *testing.T) {
	p := NewProjector("id", "m", 1)
	p.Project(Event{Type: EventLLMUsage, Payload: map[string]any{
		"prompt_tokens": int(1), "completion_tokens": int64(2), "total_tokens": 3}})
	p.Project(Event{Type: EventLLMUsage, Payload: map[string]any{
		"prompt_tokens": float64(4), "completion_tokens": "bad", "total_tokens": nil}})
	got := p.Usage()
	if got.PromptTokens != 5 || got.CompletionTokens != 2 {
		t.Fatalf("int/int64/float64 三形态累计: %+v", got)
	}
}

func TestContentChunkAndFailureChunk(t *testing.T) {
	p := NewProjector("chatcmpl-1", "gpt-4o", 1700000000)
	if p.ContentEmitted() {
		t.Fatal("初始无正文")
	}
	report := p.ContentChunk("终报全文")
	if report.Object != ObjectChatCompletionChunk || report.Choices[0].Delta.Content != "终报全文" {
		t.Fatalf("终报兜底帧: %+v", report)
	}
	if !p.ContentEmitted() {
		t.Fatal("ContentChunk 应置正文标记")
	}
	failure := p.FailureChunk("failed")
	if failure.Choices[0].Delta.Content != "\n\n[会话未成功: failed]" {
		t.Fatalf("失败说明帧: %+v", failure)
	}
	if got := failureNote(""); got != "\n\n[会话未成功: unknown]" {
		t.Fatalf("空终态兜底: %q", got)
	}
}
