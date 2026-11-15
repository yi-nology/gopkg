// Package acpbridge 承接 ACP（Agent Client Protocol）入站桥协议面：把宿主
// agent 以 ACP agent 形态暴露给 Zed/OpenCode 等 IDE/终端工具。
//
// # 形态
//
// stdio 上的 JSON-RPC 2.0，换行分帧（一行一个 JSON 对象）。协议面是 ACP v1
// 子集：
//
//	initialize       握手，声明 protocolVersion=1 与 capabilities
//	session/new      创建一个 ACP 会话（宿主负责真实会话/引擎）
//	session/prompt   一轮提示；流式内容以 session/update 通知承载
//	session/cancel   取消通知（宿主实现 Canceler 时生效）
//
// 其余方法（session/load、fs/* 等）一律 JSON-RPC method not found
// （-32601）——capabilities 已声明不支持，不假装支持再静默失败。
//
// # 与宿主的接口缝
//
// 本包**不自起引擎、不持有 HTTP 客户端、不认宿主会话存储**。宿主实现
// [Host]：CreateSession 建真实会话并返回不透明 id，Prompt 执行一轮并把
// 增量文本经 emit 回调交回桥（桥转成 agent_message_chunk 通知）。宿主可以
// 把 Prompt 实现成「打自家 HTTP API + 轮询终态」，这是宿主决策；协议帧、
// 方法分发、错误码、capabilities 声明随包走。
//
// # 健壮性
//
// stdio 可能被 IDE 反复拉起、混入非 JSON 噪声：空行与解析失败的行跳过而
// 不是退出进程；单行上限默认 4MB（粘贴日志/长上下文），可用
// [Server.MaxLineBytes] 调整。写出错误（IDE 关管道）立即终止 Serve。
//
// # 与 oekit retry 的关系
//
// 原实现轮询终态用了 oekit/concurrency/retry；本仓零依赖，轮询骨架由宿主
// 在 Prompt 里自行实现（time.Ticker/context 即可）。本包只负责 JSON-RPC
// 帧与 ACP 语义，不替宿主做重试策略。
package acpbridge
