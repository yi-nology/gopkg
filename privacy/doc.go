// Package privacy 提供数据主体权利面的注册制骨架：GDPR 式导出（subject
// access）与删除（right to erasure）。表清单不再逐表手排——宿主把每张
// 个人数据表登记进 [Registry]（表名、归属列、策略、采集/删除/匿名化
// 闭包），导出与删除都按注册表遍历；新表上线漏登记从此是注册表上可见的
// 空白，而不是静默漏导/漏删。
//
// # 策略
//
// [Policy] 是位集合，登记时可以组合：
//
//   - [Export]：导出时采集该表（需 Collect 闭包）；
//   - [Erase]：删除时清除该表（需 Erase 闭包）；
//   - [Anonymize]：清除后把保留行匿名化（需 Anonymize 闭包，返回匿名称）；
//   - [Exempt]：导出与删除都跳过，必须填 Reason（法定义务/审计链等），
//     且不能与其他策略组合。
//
// 常见的 `Export|Erase` 表示「既导出又硬删」；`Export|Anonymize` 表示
// 「导出、但删除时保留匿名行」（user 行即此形态）；`Erase` 单独出现表示
// 只删不导。登记顺序 = 执行顺序：删除时子表先于父表，墓碑在全部清除后、
// 匿名化之前追加。
//
// # 剔除判据
//
// 凭证类数据（口令哈希、加密载荷、API key 密文等）不属于「关于主体的
// 信息」——导出无意义且是泄漏面。字段级剔除由 [Table.Omit] 声明（按
// JSON 字段名从对象或对象数组的每个元素删除），整表级剔除由 [Exempt]
// 声明。典型登记：
//
//	{Name: "user", OwnerColumn: "id", Policy: privacy.Export | privacy.Anonymize,
//	 Omit: []string{"pwd_hash"}, Collect: ..., Anonymize: ...}
//
// 审计链/审批决策记录属于「法定/运营留存优先」面，登记为 Exempt 并写明
// Reason；user 行匿名化保留（如 erased-<id>）让审计 actor 字符串保持可
// 追溯但不再指向真人。
//
// # 分块删除与墓碑
//
// [ChunkDelete] 是长表删除原语：按批（缺省 [DefaultChunkSize]=400）调用
// 宿主删除闭包，避免长事务锁表；返回**跨批累加**的行数（源码逐批覆盖
// 回执的缺陷在此收口）。[AppendTombstone] 幂等追加墓碑名（宿主用
// setting/名册等 KV 实现 [TombstoneStore]），让「旧名查无此人」可被身份
// 解析面精确识别为已删除，而不是当作从未存在的运维身份。
//
// # 宿主边界
//
// 表迁移、SQL/ORM 查询、附件磁盘文件删除、审计词表（user.export /
// user.erase）与 HTTP 守卫都在宿主。本包只给注册表、遍历、回执与上述
// 原语；Collect/Erase/Anonymize 闭包由宿主按自己的存储实现。
package privacy
