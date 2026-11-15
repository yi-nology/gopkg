// Package openaicompat 提供 OpenAI 兼容 API 网关的协议面：把内部 agent 会话
// 以 chat.completions 形态暴露，任意 OpenAI SDK / IDE / 外部平台可消费。
//
// # 分层（协议翻译单源 + 两条注入缝）
//
//   - 纯函数层（wire.go / project.go）：请求解码翻译（messages → 输入 + 会话
//     设定）、非流式补全对象、流式 chunk 帧、事件 → chunk 投影。全部是无状态
//     纯函数/纯状态机，JSON 线格式只在这里定义一份。
//   - 事件总线缝：EventSource 注入（Subscribe 返回 Event 通道），本包不 import
//     任何外部 bus 实现。
//   - 宿主会话缝：Host 注入（CreateSession / WaitTerminal / Cancel），gorm /
//     引擎 / 产品会话模型留在宿主适配层，本包只承协议帧与 SSE 投影面。
//
// # 事件词表
//
// Event.Type 与 agent-harness eventbus 的词表同名同值（reasoning_delta /
// text_delta / report_delta / llm_usage / turn_ended…），宿主适配层把自家
// 事件翻成 Event 即可。投影规则：reasoning_delta → delta.reasoning_content
// （DeepSeek 扩展字段）；text_delta / report_delta → delta.content；
// llm_usage 只累计到末帧；turn_ended 只记终态、由 Finish 统一收口。权威快照
// （reasoning / text）不投影——与增量同时到达会重复正文，回放/对账以增量序
// 为准。
//
// # 流式与终态对账
//
// SSE 帧为 `data: <chat.completion.chunk>`，末帧 finish_reason=stop + 累计
// usage，随后 `data: [DONE]`；15s 心跳注释帧防中间层空闲超时。EventSource
// 约定从会话起点投递（实现方在 Subscribe 内先回放缓冲/持久化事件），本包按
// Event.ID 幂等去重；仍在 turn_ended 后调 Host.WaitTerminal 对账——成功且
// 一帧正文都没投影时用 final_report 全文兜底，非成功态追加一行状态说明
// （OpenAI 词表无失败 finish_reason）。
//
// # 治理边界
//
// Token 为空且宿主未实现 Authorizer 时 Handler 恒 401（裸奔=任意内网进程可
// 建会话烧 token）；缺省每请求常量时间比对 Bearer，宿主实现 Authorizer 后
// 由产品鉴权策略接管（JWT / 网关头 / 租户校验）。model 字段语义由宿主决定
// （专家 slug / 任意别名），本包不做注册表校验；专家钉住、policy 档位、持久
// 化都是宿主 Host 实现的产品决策。
package openaicompat
