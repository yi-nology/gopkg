# gopkg

> yi-nology 业务侧 Go 共享包——归档仓 [`yi-nology/common`](https://github.com/yi-nology/common) 的 `biz/*` 接档者，
> 并承接从框架仓改道过来的产品域内核。

## 定位与边界

三个 Go 组织的分工（本仓在最右）：

| 组织 | 职责 | 例子 |
|---|---|---|
| `oekit` | 框架原语——纯机制、零领域词、宿主注入策略 | logx / httpx / redisx / pkg |
| `oagentkit` | AI agent 框架 | llm / guardx / queue |
| **`yi-nology/gopkg`** | **业务共享件——产品能力、平台契约、领域内核** | IM 载荷 / license / 审批令牌 |

**判据**：机制留框架仓，产品域概念进本仓。2026-11-14 的七个下沉提案按此分流——
`auditchain`/`sse`/`canon`/`forward` 落 `oekit/pkg`，`im_payload`/`licensx`/`tokenx`
改道至此（[gopkg#1](../../issues/1) / [#2](../../issues/2) / [#3](../../issues/3)）。

## 包清单

| 包 | 说明 | 来源 |
|---|---|---|
| `bot` | IM 机器人统一门面（企微/钉钉/飞书/蓝信）：`BotOne` 发送路径 + `payload.go` 纯载荷构造（`BuildIMPayload` 按渠道分发，纯函数零网络） | common/biz/bot 接档 + oekit/pkg#485 改道（gopkg#1） |
| `imchan` | IM **入站**通道协议族：QQ / 企微智能机器人 / 飞书 / 钉钉长连接 + 企微回调；统一 `InboundMessage` + 断链重连退避单源（`Backoff`/`Clock` 可注入）。会话绑定/去重/串行/合并仍留宿主 | bianque `internal/im` 通道协议层（gopkg#5） |
| `licensx` | Ed25519 license 签发/验签——载荷泛型 + 类型化哨兵 | oekit/pkg#486 改道（gopkg#2） |
| `tokenx` | 签名能力令牌（HMAC 载荷绑定 + 命令集规范化哈希） | oekit/pkg#487 改道（gopkg#3） |
| `eventsrc` | 通用 webhook 事件源五段管道（鉴权→限频→过滤→模板→留痕）：Bearer/HMAC 二选一鉴权、每源滑动窗口、`eq/ne/contains/exists/regex` 过滤、`{{path}}` 模板、留痕与拒绝原因词表；`SourceStore`/`EventStore`/`Sink` 由宿主实现，管理面 CRUD/密钥轮换/清扫随包 | bianque internal/service/webhook 下沉（gopkg#14） |
| `ticket` | 工单域适配器：Jira REST（评论/创建/流转/JQL 分页搜索，Cloud/Server 同构）+ PagerDuty Events v2 备注；`Poller` 逐源串行取单骨架（唯一索引去重、单源失败不阻塞） | bianque internal/service/ticket 下沉（gopkg#15） |
| `credstage` | 凭证物化 Stager：`type:*`/`type:name` 引用解析、via 递归与环检测、原子落盘+写-后-剪、env 组装；渲染族 Interpolate/SSH/datasource/kubeconfig；加密面与类型词表由宿主注入 | bianque internal/credentials stage+render 下沉（gopkg#18） |
| `kbgroup` | 知识组键提取与团队档路径判定：案例标题行 → 组键（去空白+小写归一）单源，写入去重与存量清理共用；`TeamSlugOf` 统一团队档路径语义（防跨队泄漏） | bianque `internal/kbgroup` 下沉（gopkg#10） |
| `alertroute` | 告警入站判定核：标签路由匹配（空白路由=全匹配、坏 JSON=不命中）+ `(fingerprint, starts_at)` 幂等键（精确锚点，非滑动窗口） | bianque `internal/service/alert` 下沉（gopkg#9） |
| `diagbundle` | 一键诊断支持包骨架：分节注册/遍历、配置白名单摘要与 URL 布尔化、事件截断、审计链校验结果/错误入包 | bianque `internal/service/hostdiag` 下沉（gopkg#17） |

下沉提案里的 `biz/<x>` 目标包按本仓已废弃 `biz/*` 的约定落顶层 `<x>/`（与 `bot` 提升同律）。

`bot` 自 `biz/bot` 提升为顶层包（2026-11-15）：业务侧的「平台线格式契约」归它一个门面，
其余承自 `common/biz/*` 的模块经核查**全仓零引用**，已删除（见下方「与 common 的关系」）。

`imchan`（gopkg#5）按 issue 目标包 `biz/imchan` 落地为顶层包，与本仓 `bot` 的提升同构。
两者划界：`bot` 只产**出向载荷字节**（纯 JSON、零网络、零重试）；`imchan` 管**入站连接生命周期**
（凭证、长连接/回调、协议编解码、重连、平台回投语义）。`imchan` 不消费 `bot` 的载荷构造器——
QQ 被动回复窗、钉钉 sessionWebhook、企微 aibot WS ack 这些回投语义无法用纯载荷函数表达。

## 与 common 的关系（2026-11-14 接档 → 2026-11-15 收口）

接档自 `common` 的内容只保留 `bot`（IM 机器人门面）。未接档 / 已删除的：

- `utils/*`（xstrings/xtime/xjson…）**不接档**——`common` 归档时通用工具已交棒 `oekit/pkg`
  （stringx/timex/encoding…），重复接档只会造第二份单源。
- `biz/lock` **退役**——自造 SetNX + 自旋改用 `oekit/redisx/distlock`（契约 `oekit/pkg/distlock`）。
  原实现三缺陷：`UpWait` 收 ctx 却从不检查、固定 100ms 自旋无退避无上限、`Down` 无条件 DEL 无法校验持有者。
- `biz/email` / `biz/git` / `biz/online-git` / `biz/zentao` / `biz/gps` / `biz/identity` /
  `biz/phone` / `biz/vehicle` **已删除**：接档后全仓零引用，属归档仓的业务残留，不在本仓定位内。
  需要时按「产品域内核」判据单独立单下沉，不整包搬运。
- `bot` 的 HTTP **不动**：四家已有正确的 `Timeout: 5s`，换 `oekit/httpx` 要把超时交给分项上限、
  且要调用方传 Prometheus registry 才有收益——对 fire-and-forget 的 webhook 发送是净负担。

## 迁移自 common

```diff
- import "github.com/yi-nology/common/biz/bot"
+ import "github.com/yi-nology/gopkg/bot"
```

## 开发

```bash
go build ./...
go vet ./...
gofmt -l .
go test ./... -count=1
```