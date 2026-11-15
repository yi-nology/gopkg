// Package approvalflow 提供审批流状态机与领域红线：提审、决策、挂起等待、
// 一次性执行凭据核销、超时清扫与未通知催办。存储、事件发布、IM 卡片文案与
// 通道、数据库迁移都留宿主；本包只收「状态怎么迁移、什么情况下必须拒绝」。
//
// # 状态机
//
//	pending ──approve──▶ approved ──consume token──▶ approved + token_used_at
//	       ├─reject───▶ rejected
//	       ├─cancel───▶ cancelled
//	       └─timeout──▶ expired
//
// 只有 pending 可迁移；approved/rejected/expired/cancelled 都是终态。所有迁移
// 由 [Store] 的条件更新（CAS）裁定，本包不做内存状态账本——多副本/重启后
// 以存储为准。
//
// # 领域红线
//
//   - **deny by default**：审批窗口到期后 approve 一律拒绝（[ErrExpired]），
//     并把 pending 行惰性收敛为 expired；reject 是安全方向，过期单仍允许。
//     [ExpiredFor]/[ExpiredForAt] 是这条判据的单源谓词。
//   - **一次性核销**：approve 时用 tokenx 签执行凭据（载荷绑定 approval_id/
//     case_id/plan_hash），只把 sha256 哈希落库；[Service.ConsumeToken] 先做
//     tokenx 验签（MAC/绑定/时效）再做存储的一次性 CAS，二次核销必败。明文
//     凭据不落库。
//   - **审批人≠提审人**：开启 RequireSeparateApprover 后，approve 的决策人
//     不得等于 CreatedBy；reject 不受限；CreatedBy 为空（鉴权关闭期）或决策
//     人匿名时不生效。
//   - **快速通道只改超时档**：risk <= MaxRisk 走更短的审批窗口，但 L4 双确认、
//     审批分离、过期拒绝、一次性核销全部照旧——任何决策语义都不因快速通道
//     放宽。
//   - **L4 双确认**：risk >= 4 的 approve 必须精确携带 [L4Phrase]；首次携带
//     只记 L4FirstAt 并保持 pending，第二次携带才落 approved/签发凭据。错误
//     提示**不得回显正确短语**（已由哨兵错误保证）。L4 永不接受策略代批
//     （[Service.DecideSystem] 直接拒绝）。
//   - **ask_user 窗口**：构造函数强制 AskTimeout < Timeout——轮内等待受单轮
//     预算钳制，提问卡窗口必须短于审批窗；ask_user 行 RiskLevel=1、CreatedBy
//     恒空（引擎自提，无自批面）。
//
// # 存储契约
//
// [Store] 的每个迁移方法都必须是原子的条件更新（SQL UPDATE ... WHERE status
// = 'pending' / token_used_at IS NULL），返回 RowsAffected>0 的布尔语义；
// Decide 在 approve（tokenHash 非空）时必须同时要求 expires_at > now——服务
// 层检查与并发窗口双保险。Due 只返回已到期 pending 的 approval_id；服务层
// 再逐条 Expire + 发事件（避免「批量改状态但漏发事件/漏唤醒」）。具体条件
// 见接口方法注释。
//
// [Publisher] 接收终态事件（决策/过期/取消），[Notifier] 接收「请求创建/催办」
// 推送请求——IM 文案与通道由宿主实现，本包不拼卡片。二者均可为 nil（no-op）。
//
// # 并发与多副本
//
// 超时定时器与 AwaitDecision 唤醒表是**进程内**的best-effort：状态正确性由
// Store CAS 保证，[Service.SweepExpired] 是跨重启/多副本的兜底扫描；
// AwaitDecision 同时轮询存储，因此其他副本的决策也能被观察到。Publisher
// 在终态迁移成功后以脱离请求取消的上下文调用（决策已落库，通知不能因请求
// ctx 取消而丢）。
//
// # 执行凭据时效
//
// tokenx 的 exp 取审批行的 ExpiresAt + 可选 TokenGrace：同一审批行在任何副本
// 都能确定性签出同一凭据（AwaitDecision 无需保存明文）。宿主应保证批准后的
// 执行在 exp 前完成；需要更长窗口时配置 TokenGrace，而不是去掉时效校验。
package approvalflow
