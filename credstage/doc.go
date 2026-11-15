// Package credstage 凭证物化 Stager：引用解析 + via 递归 + 原子落盘 + env 组装 +
// 写-后-剪，以及模板渲染族（Interpolate / SSH / datasource / kubeconfig）。
//
// 平台契约（从 bianque internal/credentials 下沉）：
//
//   - 引用语法 "type:name" / "type:*"（无 name 同通配）；type:* 只展开全局档
//     启用实例——物化进平台级子进程的凭证是平台面，个人/团队档不得被通配展开；
//   - via 链递归展开（类型字段 kind=credential_ref 指向另一实例），被引用者
//     先物化；链上任一环不可用 → 根整体跳过并留痕；环检测 fail-loud；
//   - 跳过降级哲学：缺失/禁用/解密失败属运行数据问题，SkipNote 留痕不报错；
//     ref 类型未声明/renderer 未注册/落盘失败属配置或环境错误，返回 error；
//   - 写-后-剪：resync 期间运行中会话在读 staging，先删后写会读到空目录。本包
//     原子写全部新文件（tmp 0600 + rename），成功后再剪除清单外的陈旧文件与
//     .tmp 残留；剪除失败 fail-loud（凭证目录不留未追踪文件）；
//   - per-instance 目录（root/<instance>/<server>）防双副本互踩；env 同名值
//     去重后按 ":" 拼接（KUBECONFIG 多文件语义）；仅含 ${staging_dir} 的 base
//     条目按绑定类型恒注入（零实例也注入，宿主懒拉起子进程的 env 首次烘焙）。
//
// 边界：加密面（AAD 信封/主密钥/密文格式）留宿主——[Decryptor] 按名返回明文
// 字段；类型声明词表（YAML/pack 加载/字段校验）经 [Registry] 注入；MCP server
// 装配、表结构与反查接线留宿主。
package credstage
