// Package eventsrc 通用 webhook 事件源五段管道（鉴权→限频→过滤→模板→留痕）。
//
// 定位于「机制留框架仓、产品域进 gopkg」的分界示范：验签复用
// github.com/oekit/pkg/webhook 的 HMAC 族、限频复用
// github.com/oekit/concurrency/ratelimit 的滑动窗口，本包只做把它们按事件源
// 产品语义编排起来的那一层：
//
//   - 源配置：鉴权模式（Bearer token / HMAC-SHA256 二选一）、每源限频、
//     确定性过滤条目、{{path}} 模板、留痕保留窗口；
//   - 五段管道：[Service.Ingest] 依次执行 鉴权 → 限频 → 载荷解析 → 过滤 →
//     模板渲染 → 投递回调，每一步拒绝都写一条 [Event] 留痕（原因码词表在
//     本包内固定，管理面「最近触发」与拒绝溯源共用）；
//   - 存储接口化：[SourceStore]、[EventStore] 由宿主实现（表是宿主资产），
//     第五段「建会话」是宿主回调 [Sink]，本包不认会话、不认数据库；
//   - 管理面原语：源配置校验、密钥生成/轮换、留痕清扫（保留窗口）随包提供，
//     管理 HTTP handler 与鉴权/团队作用域留宿主。
//
// 边界：本包不做 HTTP 服务器、不读请求体上限之外的传输层配置、不实现
// SSRF/出口守卫（host 的 Sink 与存储实现各自负责）；模板语义是确定性
// 占位替换而非 text/template（未知路径必须替换为空串而不是报错）。
//
// 依赖说明：HMAC 验签与滑动窗口限频按 issue 划界直接复用 oekit 原语，避免
// 在业务仓重造安全敏感实现；除此之外只用标准库（net/http、encoding/json、
// regexp）。
package eventsrc
