// Package stager 承接凭证物化 Stager：引用解析（type:name / type:*）→ via
// 递归展开 → 落盘文件 + 组装 env → 写-后-剪，以及凭证模板渲染族。它解决
// 的是「凭证 → 子进程可用的文件与环境」这段平台契约，不碰加密。
//
// # 与加密面的划界
//
// 加密（AAD 信封、密钥保管、解密失败语义）留宿主：[Decryptor] 只按实例名
// 返回**明文字段**，本包不知道密文格式、不持有密钥。引用类型词表、when
// 条件、实例启停与作用域由宿主 [Registry] 声明；本包只执行物化编排。
//
// # 物化契约（从参考实现承接的实弹不变量）
//
//   - **跳过降级**：实例缺失/禁用/解密失败/引用链断裂属运行数据问题——
//     跳过并留 [SkipNote]，不阻塞其他实例；**类型未声明/类型不符/路径
//     逃逸/renderer 未注册**属配置错误——fail-fast 返回 error。
//   - **写-后-剪**：resync 期间运行中的子进程可能正在读 staging 目录，
//     先删后写会读到空目录。本包先原子写全部新文件（同目录临时文件 +
//     rename），成功后只剪除本次清单之外的陈旧文件与空目录。
//   - **via 递归**：字段 kind=credential_ref 的值是另一个实例名；被引用者
//     先物化，链上任一环不可用则根实例整体跳过。引用环/超过深度上限
//     （默认 3）都按跳过处理并留原因，不会死循环。
//   - **env 组装**：只含 ${staging_dir} 的 base 条目按绑定类型恒注入（零
//     实例也在——懒拉起子进程的 env 在首次调用烘焙，晚补文件的前提是 env
//     已就位）；含 ${name}/${field} 的 per-instance 条目随实例追加。同名
//     值去重后按 ":" 拼接（KUBECONFIG 多文件语义）。
//   - **per-instance 目录**：<root>/<instanceID>/<server>，多副本共享 data
//     目录时互不践踏。构造时清扫本实例 staging 根（boot 时子进程未起）。
//   - **写侧限界**：相对路径插值后做逃逸检查，只允许落在 server 目录内；
//     文件权限只接受 0600/0644。
//
// # 模板渲染族
//
// [Interpolate]（${name}/${staging_dir}/${field}）、[SkipByWhen]（
// "<field> != ”"）、[RenderSSHHost]（OpenSSH Host 块）、
// [RenderDatasourcesYAML]（可观测数据源声明 YAML）、[KubeconfigServer]
// （从 kubeconfig 提取 API server 地址）。YAML 输出由 stdlib 手写（只产出
// 受控结构，不引 yaml 库）；KubeconfigServer 用最小缩进解析器，覆盖常见
// 块式 kubeconfig 与 JSON 形态，不完整解析 YAML 规范。
//
// # 典型用法
//
//	st, err := stager.NewStager(stager.Config{
//	    Registry:  hostRegistry,  // 类型声明 + 实例元数据
//	    Decryptor: hostDecryptor, // 按实例名取明文字段
//	    Root:      "/data/run/credentials",
//	    InstanceID: "replica-1",
//	})
//	staged, err := st.Stage(ctx, "mcp-ssh", []string{"ssh:*", "token:api"})
//	// staged.Env 直接并入子进程 env；staged.Files 用于审计/展示
//
// 凭证变更后调用 RestageBindings 即时重物化全部已绑定 server；ssh 类消费
// 端每次建连重读文件即生效，env 绑定具体实例路径的新增实例仍需进程重启
// （返回值如实呈现，不假装热生效）。
package stager
