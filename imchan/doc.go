// Package imchan — IM 入站通道协议族（gopkg#5）：QQ / 企微智能机器人 /
// 飞书 / 钉钉 / 企微回调五个通道的统一入站模型、连接生命周期与断链重连
// 退避单源。
//
// # 与 bot 包的划界
//
//	bot/    出向载荷构造（纯 JSON 线格式、纯函数、零网络、零重试）
//	imchan/ 入站通道协议（长连接/长轮询生命周期 + 协议编解码 + 重连 +
//	        平台回投语义）
//
// 两者都贴着 IM 平台，但威胁模型与生命周期完全不同：bot 只产字节，调用方
// 自己决定怎么发；imchan 持有凭证、维持长连接、解析平台推送，并按平台语义
// 回投（QQ 被动回复窗、钉钉 sessionWebhook、企微 aibot WS ack 等）——这些
// 语义无法用 bot 的纯载荷函数表达。imchan 不消费 bot 的载荷构造器。
//
// # 不在本包的范围
//
// 会话绑定（channel:subject:chat_type → 宿主会话）、去重、同键串行、连发
// 合并、轮询终态、审批提醒——这些是宿主平面编排（bianque internal/im 的
// Manager 那半）。本包只做通道协议层：Start 阻塞运行/回调注册、入站消息归一、
// 平台回投；SessionAPI 接口缝由宿主注入。
//
// # 通道形态
//
//   - QQ：官方 WS 网关长连接（手写网关循环，被动回复带 msg_id/msg_seq）。
//   - 企微智能机器人：aibot WS 长连接（四帧协议，认证失败哨兵 + 终态阈值）。
//   - 飞书：官方 oapi-sdk-go WS 长连接（SDK 内置重连/心跳）。
//   - 钉钉：官方 Stream 模式 SDK 长连接（sessionWebhook 回投）。
//   - 企微回调：HTTP 回调形态（无公网自建长连接；Start 仅注册 handler，
//     验签/解密/加密回复由 CallbackChannel 扩展接口暴露给宿主 HTTP 端点）。
//
// # 依赖说明
//
//   - gorilla/websocket：QQ / 企微 aibot 手写网关循环所需；stdlib 无
//     WebSocket 客户端。钉版 v1.5.3（GO-2026-6278 修复版本）。
//   - larksuite/oapi-sdk-go/v3：飞书 WS 帧是 protobuf 编码 + 租约/心跳/
//     重连状态机，官方 SDK 是唯一可维护实现；v3.12.2 与 bianque 生产同版。
//   - open-dingtalk/dingtalk-stream-sdk-go：钉钉 Stream 是厂商私有协议
//     （HTTP 换票 + WS 帧 + ACK），SDK 依赖面小（uuid + gorilla），
//     v0.9.1 与 bianque 生产同版。
//
// 三个依赖都限定在通道协议层，不向宿主泄漏 SDK 类型（唯一例外：
// LarkChannel.ParseLarkMessage 的事件类型来自官方 SDK，供宿主在自定义
// dispatcher 场景复用；正常使用走 Start 即可）。
//
// # 断链重连
//
// 手写长连接通道（QQ / 企微 aibot）统一走 Reconnecter + Backoff 单源；
// 飞书/钉钉的自动重连由官方 SDK 内置（其退避参数不可注入），本包不重复
// 包装。退避等待经 Clock 注入，契约测试用假时钟验证序列，不 sleep 真等。
package imchan
