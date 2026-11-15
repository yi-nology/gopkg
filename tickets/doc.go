// Package tickets 提供工单平台的契约适配器：Jira REST v2（Cloud/Server
// 同构路径）与 PagerDuty Events API v2 的回写/取单面。零第三方依赖：
// net/http + encoding/json；HTTP 客户端由宿主注入（*http.Client 或实现
// [Doer] 的任意包装），超时、代理、出站 SSRF 闸（netguard/egress）都在
// 注入的 Transport/Doer 上兑现。
//
// # 机制与宿主职责
//
//   - [Target] 只携带 adapter/baseURL/CredentialRef；凭证由 [CredentialProvider]
//     按引用解析（凭证平面 / vault / KMS），本包不持有任何密钥，也不把
//     凭证写进错误文本。
//   - 每次请求都重新解析凭证：支持凭证轮换；引用解析失败按 fail-closed 中止。
//   - 适配器无状态：HTTP 语义、无重试、无后台循环。重试由调用方（webhook
//     重投 / 任务队列）承担——静默重试会让工单评论重复。
//   - 基准 URL 归一：[NormalizeBaseURL] 接受带 `/rest/api/2`（或 `/rest/api/3`，
//     请求统一走 v2 协议面）后缀的 Jira 地址、带 `/v2/enqueue` 后缀的
//     PagerDuty 地址；含 userinfo/query/fragment 的 URL 一律拒绝（凭证不得
//     入 URL）。
//
// # Jira 契约
//
//   - 评论：POST /rest/api/2/issue/{key}/comment，Basic user:token。
//   - 建单：POST /rest/api/2/issue，返回 id/key/self。
//   - 流转：POST /rest/api/2/issue/{key}/transitions；按名称时先 GET 同路径
//     的 transitions 列表做精确匹配，零命中/多重命中都报错（fail-closed）。
//   - 取单：POST/GET /rest/api/2/search 的 JQL 透传；[Client.SearchAllJiraIssues]
//     逐页拉取并在响应 startAt 不前进时判定分页停滞（防死循环）。
//
// # PagerDuty 契约
//
// Events API v2 的 routing key（凭证面）、event_action（trigger/
// acknowledge/resolve）与 dedup_key（事件去重键）约定由本包钉住。
// trigger 必填 summary/source（source 可由 Target.Source 兜底），summary
// 上限 1024 字符；acknowledge/resolve 必填 dedup_key。响应 status 非
// "success" 视为失败（fail-closed）。
//
// [Client.PostComment] 对 PagerDuty 目标映射为一条 trigger 事件：
// dedup_key = issueKey、summary = body、source = Target.Source。需要长正文
// 时调用方应自行 [Client.SendPagerDutyEvent] 并把正文放 CustomDetails。
//
// # 取单轮询骨架
//
// [Poller] 按 [Source] 逐源串行：单源 Search 失败只记入该源回执、不阻塞
// 其它源；每条工单先经 [Ledger] 唯一索引 Claim 去重，再交 [Handler] 处理，
// 成功后调用 Source.WriteBack 回写闭环。Claim 失败按 fail-closed 中止该源
// （无法判重时继续处理会制造重复会话）。
//
// # 典型用法
//
//	client, err := tickets.NewClient(
//	    tickets.Target{
//	        Adapter:       tickets.AdapterJira,
//	        BaseURL:       "https://jira.example.com/jira",
//	        CredentialRef: "vault://ops/jira-bot",
//	    },
//	    credentials.Resolve, // func(ctx, ref) (tickets.Credentials, error)
//	    httpClient,          // 宿主带超时/SSRF 闸的 *http.Client
//	)
//	if err != nil {
//	    return err
//	}
//	if _, err := client.PostComment(ctx, "OPS-42", "诊断结论：磁盘 inode 耗尽"); err != nil {
//	    return err
//	}
//
//	poller := &tickets.Poller[tickets.Source]{
//	    Sources: sources, Ledger: linkTable, Handler: openSession,
//	}
//	report, err := poller.Poll(ctx)
package tickets
