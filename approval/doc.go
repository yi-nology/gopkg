// Package approval 审批流状态机（human-in-the-loop 挂起面）：提审、决策、
// 阻塞等待、超时清扫与执行凭据一次性核销。存储与事件出口由宿主注入，
// 本包只管状态迁移与审批域红线。
//
// # 领域红线（与「定时器怎么跑」「DB 怎么写」正交）
//
//   - **deny by default**：过期单不得批准。approve 方向在服务层与存储层
//     双重设闸（[ExpiredFor] 谓词单源），超时即 expired；reject/取消是
//     deny 方向，恒允许（对「已过期但尚未被 sweep 收敛」的 pending 行，
//     reject 仍可落定）；
//   - **一次性核销**：批准时签发与审批行字段绑定的执行凭据，行上只存
//     sha256 哈希；[Service.ConsumeToken] 先验签+绑定再 CAS 置
//     token_used_at，第二次必然失败；
//   - **审批分离**：开启后 approve 的决策人不得等于提审人（reject 不受
//     限）；提审人无身份（CreatedBy 空）时不生效；
//   - **L4 双确认**：risk >= [RiskL4] 的批准需要两次，第一次只记
//     L4FirstAt 并保持 pending，第二次须精确携带 [L4Phrase]；L4 永不接受
//     策略代批；
//   - **快速通道只改超时档**：risk <= MaxRisk 走短超时，决策语义与红线
//     不变；
//   - **ask_user 窗口短于审批窗**：提问卡窗口缺省 5m（可配），比审批窗
//     短是硬约束——轮内等待受单轮预算钳制。ask_user 单的 CreatedBy 恒空
//     （引擎自提，无自提自批面）。
//
// # 执行凭据
//
// 令牌面复用 [github.com/yi-nology/gopkg/tokenx]：载荷绑定
// approval_id/case_id/plan_hash/expires_at 四键 + exp，行上存
// sha256(token)。[Service.AwaitDecision] 与 [Service.ConsumeToken] 都由
// 审批行字段确定性复算，不依赖决策落在哪个副本。exp 绑定的是**审批窗口**
// （expires_at）而不是执行窗口：凭据的实际生命周期由「审批行仍是 approved
// 且未被核销」决定——这与源码语义一致（批准后引擎取走并消费，不因墙钟
// 越过审批 deadline 而让已批准的变更失效）。
//
// # 宿主边界
//
//   - [Store]：审批行读写与全部 CAS 迁移（pending 守卫、token 一次性
//     核销、L4 首确认、到期批量收敛）。宿主用自己的 DB/事务实现；
//   - [Publisher]：决策/过期/取消事件出口。宿主接审计与指标；IM 推送
//     卡文案、审批中心页面与审计词表都在宿主（本包不含任何渠道依赖）；
//   - 超时机制：本包**不**为每张单起宿主的 timer。宿主按自己的节奏调
//     [Service.SweepExpired]（建议至少每秒一次并做 leader 选主），
//     [Service.AwaitDecision] 内部也有惰性收敛兜底；
//   - 催办（approvalRemindAfter 一类未通知扫描）是「事件表标记 + IM
//     推送」的宿主编排，不在状态机内核内。
//
// # 用法
//
//	svc, err := approval.New(approval.Config{
//		Store:     hostStore,      // 实现 approval.Store
//		Publisher: hostPublisher,  // 实现 approval.Publisher（可 nil）
//		Secret:    cfg.HMACSecret, // 空=启动期随机（重启后旧凭据全部失效）
//		Timeout:   30 * time.Minute,
//	})
//	id, err := svc.Submit(ctx, approval.SubmitInput{
//		CaseID: "cs-7", SessionID: "s-1", RequestType: "restart",
//		RiskLevel: 2, PlanReport: planJSON, CreatedBy: "alice",
//	})
//	dec, err := svc.AwaitDecision(ctx, id) // 阻塞直到 approved/rejected/expired/cancelled
//	if dec.Status == approval.StatusApproved {
//		ok, err := svc.ConsumeToken(ctx, id, dec.Token)
//	}
package approval
