// Package acp 提供 ACP（Agent Client Protocol）入站桥的协议面：stdio 换行
// 分帧的 JSON-RPC 2.0 帧处理 + initialize / session/new / session/prompt
// 方法路由 + agent_message_chunk 通知。宿主（自家会话 API / 引擎 / 平台治理）
// 经 Host 三个方法注入，协议逻辑零宿主依赖——把任意 agent 以 ACP agent 形态
// 暴露给 Zed/OpenCode 等 IDE/终端工具时复用本包。
//
// # 协议子集
//
// 与 bianque internal/acp 的 v1 子集一致：initialize（protocolVersion=1、
// loadSession=false、promptCapabilities={}）、session/new（派发 ACP 会话号）、
// session/prompt（首问惰性建宿主会话、续问投递 input、轮询终态取定稿报告）。
// 其余方法（session/load、fs/*、session/cancel…）一律 method not found
// （-32601）——capabilities 已声明不支持，客户端不应调用。
//
// promptCapabilities 是空对象：不声明 image/audio/embeddedContext 能力。
// session/prompt 的 prompt 参数同时接受 ACP 标准的 content block 数组
// （[{"type":"text","text":"…"}]）与简写字符串，只消费 text 部分。
//
// # 帧与错误
//
// 每行一个 JSON-RPC 消息（消息内不得含裸换行）；读侧上限默认 4 MiB（长提示
// 粘贴日志）。按 JSON-RPC 2.0 回错误帧：-32700 parse error（id=null）、
// -32600 invalid request、-32601 method not found、-32602 invalid params、
// -32603 internal error。通知（无 id）照常执行但永不回包——未知通知静默丢弃。
// 非 JSON 行回 -32700 后继续服务（桥进程被 IDE 反复拉起，健壮优先）。
//
// # 进程 I/O 注入
//
// Serve / (*Bridge).Serve 接收 io.Reader / io.Writer，生产用 os.Stdin /
// os.Stdout，测试用内存管道——进程 I/O 与协议逻辑解耦，不依赖真实 stdin。
//
// # 并发
//
// Bridge 串行处理帧（与 bianque 桥一致）：一帧处理完再读下一帧，sessions
// 映射无需加锁。同一 Bridge 不可被多个 goroutine 并发 Serve。
package acp
