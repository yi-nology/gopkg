package openaicompat

// Projector 事件 → chat.completion.chunk 帧投影器（协议翻译的流式侧单源）。
// 纯状态件：累计 llm_usage 到末帧、turn 终态收口判定、正文兜底标记；不碰
// 编排/会话语义。
type Projector struct {
	ID      string
	Model   string
	Created int64

	usage          Usage
	finishSeen     bool
	status         string // turn_ended 的终态名（succeeded/failed/…）
	contentEmitted bool   // 是否已投影过正文帧（终报兜底判定）
}

// NewProjector 帧头三元组（id=chatcmpl-<session>、model=请求 model 原值、
// created=unix 秒）。
func NewProjector(id, model string, created int64) *Projector {
	return &Projector{ID: id, Model: model, Created: created}
}

// Project 单事件 → 0..n 帧。投影规则（钉测面）：
//   - reasoning_delta → delta.reasoning_content（思考流）；
//   - text_delta / report_delta → delta.content（中间答复与终报打字机同入
//     正文：OpenAI 语义下 content 累积即 assistant 消息全文）；
//   - llm_usage → 只累加（OpenAI usage 惯例只在末帧，不逐次外发）；
//   - turn_ended → 只记状态（收口帧由 Finish 统一发，不在此处外发半截帧）；
//   - 其余事件（含权威快照 reasoning/text、tool_call/tool_result）不投影。
func (p *Projector) Project(ev Event) []Chunk {
	switch ev.Type {
	case EventReasoningDelta:
		if text := payloadText(ev.Payload, "text"); text != "" {
			return []Chunk{p.frame(Delta{ReasoningContent: text})}
		}
	case EventTextDelta, EventReportDelta:
		if text := payloadText(ev.Payload, "text"); text != "" {
			p.contentEmitted = true
			return []Chunk{p.frame(Delta{Content: text})}
		}
	case EventLLMUsage:
		p.usage.PromptTokens += payloadInt(ev.Payload, "prompt_tokens")
		p.usage.CompletionTokens += payloadInt(ev.Payload, "completion_tokens")
		p.usage.TotalTokens += payloadInt(ev.Payload, "total_tokens")
	case EventTurnEnded:
		p.finishSeen = true
		p.status = payloadText(ev.Payload, "status")
	}
	return nil
}

// Done turn 括号已关（EventTurnEnded 到达；恢复/panic 路径同样落 turn_ended，
// 只是 closed_by 不同——投影面一视同仁收口）。
func (p *Projector) Done() bool { return p.finishSeen }

// ContentEmitted 是否已投影过正文帧（终报兜底判定）。
func (p *Projector) ContentEmitted() bool { return p.contentEmitted }

// Status turn_ended 的终态名（成功收尾=succeeded）。
func (p *Projector) Status() string { return p.status }

// Usage 当前累计用量（末帧口径）。
func (p *Projector) Usage() Usage { return p.usage }

// Finish 收口帧：finish_reason=stop + 末帧 usage（累计口径）。失败态也发
// stop——OpenAI 词表无「失败」finish_reason（只有 stop/length/content_filter/
// tool_calls），失败语义由调用方以 FailureChunk 在正文末补状态说明。
func (p *Projector) Finish() Chunk {
	u := p.usage
	c := p.frame(Delta{})
	c.Choices[0].FinishReason = "stop"
	c.Usage = &u
	return c
}

// ContentChunk 正文帧（终报全文兜底/失败说明复用同一帧形态，协议单源）。
func (p *Projector) ContentChunk(text string) Chunk {
	p.contentEmitted = p.contentEmitted || text != ""
	return p.frame(Delta{Content: text})
}

// FailureChunk 失败态正文说明帧（OpenAI 词表无失败 finish_reason，正文如实
// 说明终态）。
func (p *Projector) FailureChunk(status string) Chunk {
	return p.frame(Delta{Content: failureNote(status)})
}

// failureNote 失败态正文说明（非流式与流式共用，终态空串兜底 unknown）。
func failureNote(status string) string {
	if status == "" {
		status = "unknown"
	}
	return "\n\n[会话未成功: " + status + "]"
}

func (p *Projector) frame(d Delta) Chunk {
	return Chunk{
		ID:      p.ID,
		Object:  ObjectChatCompletionChunk,
		Created: p.Created,
		Model:   p.Model,
		Choices: []Choice{{Index: 0, Delta: d}},
	}
}
