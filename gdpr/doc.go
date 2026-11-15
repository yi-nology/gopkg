// Package gdpr 提供 GDPR 数据主体权利面的机制骨架：归属键注册表驱动的
// 导出（subject access）与删除（right to erasure）。零第三方依赖，纯
// stdlib；数据库查询、迁移、审计词表由宿主注入。
//
// # 注册制而非手排清单
//
// 每个纳入个人数据面的表都要登记一条 [Entry]：表名、归属列、策略位，以及
// 该策略对应的闭包（采集/分块删除/匿名化）。骨架按注册表遍历，**新表上线
// 漏登记会直接表现为导出/删除结果里没有该表**——登记面是单源，替代散落
// 在各处的逐表 SQL 手排。注册表校验 fail-closed：空注册表、重复表、零策略、
// 缺闭包、Exempt 与其它策略混用一律构造期拒绝。
//
// 策略位（可组合，Exempt 除外）：
//
//	PolicyExport    —— 采集该表归属键等于主体的记录
//	PolicyErase     —— 按归属键分块硬删（防长事务锁表）
//	PolicyAnonymize —— 按归属键把主体标识改写为匿名值（行保留）
//	PolicyExempt    —— 显式豁免：不采集、不删除，但会出现在回执的 Exempt 列表
//
// Exempt 是「有意不纳入」的显式声明，不能与其它策略组合：漏登记与显式
// 豁免在回执上是两种可见状态，不能互相伪装。
//
// # 脱敏红线（fail-closed）
//
// 凭证类数据不属于「关于主体的信息」：口令哈希、API token、私钥引用等
// 字段在导出时被剔除。默认 [DenyListRedactor] 按字段名片段（password/
// passwd/secret/token/credential/apikey/private_key/session_key/
// authorization/cookie/salt）逐层递归剔除，嵌套 map/slice 同样处理。
// 导出**必须**经过 Redactor：注册表默认安装 deny-list，宿主可注入更严格
// 的实现，但不存在「不脱敏导出」的开关。遇到无法安全判定的值类型
// （struct、json.RawMessage、channel 等）直接报错，而不是原样透出。
//
// # 删除红线（fail-closed）
//
//   - 分块删除默认 [DefaultChunkSize]（400），宿主可调；<=0 构造期拒绝。
//   - 任一分块/匿名化失败立即中止并返回**已执行部分**的回执 + 错误；
//     失败不是成功，墓碑不追加。
//   - 全部表处理成功后追加墓碑（[TombstoneStore.AppendErasedUser]），
//     幂等：已存在时 already=true，回执如实记录，不重复追加。
//   - 匿名化替换值默认 erased-<subject>，可注入；空值或与主体原名相同
//     视为匿名化未生效，拒绝执行（这不是删除）。
//
// # 宿主职责（不进本包）
//
// 表迁移与索引、归属键 SQL、采集字段白名单（Redactor 之外的业务裁剪）、
// 审计词表（user.export / user.erase 由宿主 Record）、服务层守卫（admin
// 或本人导出、admin-only 删除）、HTTP handler、凭证平面引用解析、墓碑表
// 结构与唯一索引。闭包拿到 ctx 与主体字符串即可执行，本包不猜任何 SQL 方言。
//
// # 典型用法
//
//	reg, err := gdpr.NewRegistry([]gdpr.Entry{
//	    {
//	        Table: "users", OwnerColumn: "id", Policies: gdpr.PolicyExport | gdpr.PolicyAnonymize,
//	        Collector: func(ctx context.Context, col, subject string) ([]gdpr.Record, error) {
//	            return loadUserRows(ctx, subject)
//	        },
//	        Anonymizer: func(ctx context.Context, col, subject, replacement string) (int, error) {
//	            return renameUser(ctx, subject, replacement)
//	        },
//	    },
//	    {
//	        Table: "sessions", OwnerColumn: "creator", Policies: gdpr.PolicyErase,
//	        Deleter: func(ctx context.Context, col, subject string, limit int) (int, error) {
//	            return deleteSessionsChunk(ctx, subject, limit)
//	        },
//	    },
//	    {Table: "audit_chain", Policies: gdpr.PolicyExempt,
//	        Description: "审计追溯不指向真人，按合规豁免面保留"},
//	}, gdpr.WithTombstone(tombstones))
//	if err != nil {
//	    return err // 注册表配错必须启动期暴露
//	}
//
//	export, err := reg.ExportUserData(ctx, subject)
//	report, err := reg.EraseUserData(ctx, subject)
//
// 导出结果与删除回执都带 JSON tag，宿主可直接序列化给数据主体/审计面。
package gdpr
