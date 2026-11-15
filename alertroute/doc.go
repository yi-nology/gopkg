// Package alertroute 提供告警入站的两个判定核：标签匹配路由与 fingerprint 幂等键
// （单源）。
//
// 告警接入的通用形态是「webhook 入站 → 路由 → 受理去重」：路由按 severity/source/
// labels 选链与团队，fingerprint 决定重投是否新开事件。这两个判定一旦在接入面与
// 运维工具/清理面各写一份，重投语义与路由命中就会分叉——同一告警可能建两个会话
// （重复诊断、通知风暴），或该命中的团队路由静默漏配（会话落全局）。本包只收
// 判定语义；路由 CRUD、会话创建、落库与并发占坑留宿主。
//
// # 标签匹配
//
// [RouteLabelsMatch] 对路由行 labels（JSON map 字符串）与入站标签做全键值匹配：
//
//   - 空/空白路由 = 全匹配（缺省路由）；
//   - 坏 JSON = 不命中（写面已校验 labels，热路径对历史脏行防御——规则故障不得
//     吞告警，也不得放大成全匹配）；
//   - 规则内每个键值都命中才算匹配，入站多余标签不影响；
//   - 缺失标签按空串参与比较（与 Prometheus matcher 同族语义：env="" 命中无
//     env 标签的告警）。
//
// # fingerprint 幂等
//
// 幂等锚点是 (fingerprint, starts_at) 精确对，不是滑动时间窗口：
//
//   - fingerprint 由告警源给出，必填（TrimSpace 后非空）。本包不重算指纹——重算
//     是第二份算法，源侧一旦改变分组规则就会与既有行失配，重投语义随之分叉。
//   - starts_at 是告警事件的发生时刻（RFC3339 文本，原样精确比对）；空值由服务端
//     补当前 UTC 时刻。空值即无锚点：发送侧每次重投都会得到新的 starts_at，因此
//     **会被视为新事件**——要幂等的源必须回传同一 starts_at（Alertmanager 重投
//     同 startsAt 是标准形态）。
//   - 同一 fingerprint + 同一 starts_at 即同一次受理；fingerprint 相同但 starts_at
//     不同是新一轮告警（恢复后重发/再次触发），必须新开。
//
// 本包给出键的规范化与比较；唯一索引、先占坑后干活、并发败者等待回填等受理机制
// 留宿主（依赖 DB 事务与唯一约束）。
//
// # 用法
//
//	// 路由匹配（规则行 labels 来自 DB，入站标签来自 webhook）：
//	if alertroute.RouteLabelsMatch(route.Labels, in.Labels) {
//	    // 首条命中：severity/source 空档与 labels 全键值的组合判定留宿主
//	}
//
//	// 幂等键（受理前规范化，落库与查询都用同一对值）：
//	key, err := alertroute.NewDedupeKey(in.Fingerprint, in.StartsAt, time.Now())
//	if errors.Is(err, alertroute.ErrFingerprintRequired) {
//	    // 400：fingerprint 是幂等锚点，缺了就无法受理
//	}
//	prev, err := repo.FindAlert(ctx, key.Fingerprint, key.StartsAt)
package alertroute
