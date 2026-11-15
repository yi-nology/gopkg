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
| `approval` | 审批流状态机：Submit/Decide/Await/Sweep，deny-by-default、审批分离、L4 双确认、执行凭据一次性核销（token 面复用 `tokenx`） | bianque `internal/service/approval`（gopkg#13） |
| `bot` | IM 机器人统一门面（企微/钉钉/飞书/蓝信）：`BotOne` 发送路径 + `payload.go` 纯载荷构造（`BuildIMPayload` 按渠道分发，纯函数零网络） | common/biz/bot 接档 + oekit/pkg#485 改道（gopkg#1） |
| `licensx` | Ed25519 license 签发/验签——载荷泛型 + 类型化哨兵 | oekit/pkg#486 改道（gopkg#2） |
| `oidc` | OIDC 登录客户端：发现文档 + PKCE S256 + code 交换 + RS256 JWKS 验签（未知 kid 强刷一次）+ nonce 对账 + flow state TTL | bianque `internal/auth/oidc.go`（gopkg#8） |
| `privacy` | GDPR 数据主体导出/删除骨架：归属键注册表（export/erase/anonymize/exempt）+ 字段剔除 + 分块删 + 墓碑 | bianque `internal/repo/repo_userdata.go`（gopkg#16） |
| `tokenx` | 签名能力令牌（HMAC 载荷绑定 + 命令集规范化哈希） | oekit/pkg#487 改道（gopkg#3） |

2026-11-15 三件业务内核从 bianque 下沉（[#8](../../issues/8) / [#13](../../issues/13) / [#16](../../issues/16)）：
`oidc` / `approval` / `privacy` 均落顶层包（incubator 期写 `biz/<x>` 的约定已废止），
存储、IM 推送、账号映射与审计词表等宿主侧资产不入仓。

`bot` 自 `biz/bot` 提升为顶层包（2026-11-15）：业务侧的「平台线格式契约」归它一个门面，
其余承自 `common/biz/*` 的模块经核查**全仓零引用**，已删除（见下方「与 common 的关系」）。

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