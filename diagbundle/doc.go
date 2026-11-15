// Package diagbundle 提供「一键诊断支持包」的骨架：头部信息 + 分节注册遍历 +
// 脱敏辅助 + 审计链校验入包（单源）。
//
// 售后/支持取证包是企业级自托管产品的通用诉求：版本、配置摘要、存储与表计数、
// 迁移账本、审计链校验、健康、近期错误、会话统计。分节内容因产品而异，骨架却
// 同构——各仓重写会导致包形态漂移（支持侧无法跨版本读包）、脱敏红线漏项（配置
// 密钥随包外泄）、审计链断链/截断信息丢失（支持侧不能一眼定性）。本包收骨架与
// 红线辅助；各分节的领域内容（stages 档位、admission 台账口径等）留宿主。
//
// # 支持包最小形态
//
// [Builder.Build] 产出 map[string]any（JSON 友好）：
//
//	generated_at  生成时刻 UTC RFC3339
//	version       宿主构建注入的版本号
//	hostname      主机名（可用 [WithHostname] 注入）
//	go_version    runtime.Version()
//	config        宿主装配期收的白名单摘要（恒为非 nil map）
//	<section>     每个已注册分节的 return 值
//	<section>_error 分节返回 error 或 panic 时的错误串
//	audit_chain   审计链 Verify 结果（[Builder.SetAuditChain] 成功时）
//	audit_chain_error 审计链 Verify 失败时的错误串
//
// 分节 provider 是 `func(ctx) (any, error)`：error/panic 只让该节变成
// `<name>_error`，其余分节照常入包——支持包不能因单节故障整体不可用。分节名
// 不得为空、不得与头部/审计键冲突、不得以 `_error` 结尾（与错误落包键撞名）。
//
// # 脱敏红线（宿主必须遵守）
//
//   - **只收白名单摘要，不整配置序列化**：[WhitelistSummary] 只保留显式列出的键；
//     绝不把整个配置对象先序列化再修剪。
//   - webhook URL/密钥引用/DNS token 一律不进包：URL/地址用 [URLPresent] 记
//     非空布尔（包内只说明「配了没有」，不暴露目标）。
//   - 事件 payload 用 [CompactEvents] / [TruncatePayload] 截断，防包体爆炸。
//   - 审计链校验结果直接入包（断链/截断档可见）；导出动作本身入审计链是宿主的
//     责任（词表如 diagnostics.export 属产品域，本包不定义）。
//   - 支持包与用户导出同敏感度：handler 必须 **admin-only**，并确保包体只经
//     授权响应返回（不得落公开对象存储/日志）。
//
// # 用法
//
//	b := diagbundle.New(version,
//	    diagbundle.WithConfigSummary(diagbundle.WhitelistSummary(candidate,
//	        "mode", "storage_mode", "auth_enabled", "audit_enabled")),
//	)
//	b.SetAuditChain(func(ctx context.Context) (any, error) {
//	    return auditSvc.Verify(ctx, 0, auditSvc.GenesisAnchored())
//	})
//	_ = b.RegisterSection("storage", func(ctx context.Context) (any, error) {
//	    return storageSection(ctx)
//	})
//	out, err := b.Build(ctx)
package diagbundle
