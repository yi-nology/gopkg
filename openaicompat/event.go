package openaicompat

// Event 事件总线注入面的通用事件（宿主适配层把自家事件翻成本结构）。
// ID 用于流式投影的幂等去重（回放 + 实时可能重叠；0 表示未编号、不去重）。
type Event struct {
	ID        uint64         `json:"id,omitempty"`
	SessionID string         `json:"session_id,omitempty"`
	Type      string         `json:"type"`
	Payload   map[string]any `json:"payload,omitempty"`
}

// 事件类型词表（与 agent-harness eventbus 同名同值；本包不 import 该模块）。
const (
	EventTurnStarted    = "turn_started"
	EventTurnEnded      = "turn_ended"
	EventReasoning      = "reasoning"
	EventAgentText      = "text"
	EventToolCall       = "tool_call"
	EventToolResult     = "tool_result"
	EventLLMUsage       = "llm_usage"
	EventReasoningDelta = "reasoning_delta"
	EventTextDelta      = "text_delta"
	EventReportDelta    = "report_delta"
)

// payloadText payload 字符串取值（容错：缺键/非字符串=空串）。
func payloadText(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// payloadInt payload 整型取值（容错 float64/int64/int 三形态——JSON 往返与
// 字面量构造各有形态；非数值=0）。
func payloadInt(m map[string]any, key string) int {
	switch v := m[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	}
	return 0
}
