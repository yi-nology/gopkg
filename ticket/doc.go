// Package ticket 工单域适配器：Jira REST / PagerDuty Events API v2 回写与取单原语。
//
// 覆盖「告警→诊断→回写工单」闭环末段与反向取单：
//
//   - Jira：评论回写、创建工单、状态流转、JQL 搜索（单页 + 自动翻页）；
//     Cloud 与 Server/DC 路径同构（/rest/api/2/...，Basic user:token）；
//   - PagerDuty：Events API v2 备注（annotate，dedup_key=会话 id）；
//   - 取单轮询骨架 [Poller]：逐源串行、唯一索引去重（Seen 回调）、单源失败
//     不阻塞其他源，Item 类型由宿主定义。
//
// 边界（与 bianque internal/service/ticket 的划界）：
//   - 出站 SSRF 闸、重定向策略、连接池由宿主注入的 *http.Client（Transport）
//     负责；本包只提供 10s 超时 + 不跟随重定向的缺省 client（fail-loud 的
//     起点，不是安全边界）；
//   - 凭证平面引用解析留宿主：Target.Credential 是已解析的明文形态
//     （Jira "user:token" / PagerDuty routing key），本包不读凭证库；
//   - 会话创建、链路行唯一索引、表结构、管理面 handler 留宿主；
//   - 回写正文的脱敏/PII 由宿主在组装 [Payload] 前完成，本包只做长度截断。
//
// 适配器无状态（HTTP 语义）；重试由调用方 webhook 重投或轮询下一轮承担。
package ticket
