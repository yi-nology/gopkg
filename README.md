# gopkg

> yi-nology 业务侧 Go 共享包——归档仓 [`yi-nology/common`](https://github.com/yi-nology/common) 的 `biz/*` 接档者，
> 并承接从框架仓改道过来的产品域内核。

## 定位与边界

三个 Go 组织的分工（本仓在最右）：

| 组织 | 职责 | 例子 |
|---|---|---|
| `oekit` | 框架原语——纯机制、零领域词、宿主注入策略 | logx / httpx / redisx / pkg |
| `oagentkit` | AI agent 框架 | llm / guardx / queue |
| **`yi-nology/gopkg`** | **业务共享件——产品能力、平台契约、领域内核** | IM 载荷 / license / 审批令牌 / 禅道 SDK |

**判据**：机制留框架仓，产品域概念进本仓。2026-11-14 的七个下沉提案按此分流——
`auditchain`/`sse`/`canon`/`forward` 落 `oekit/pkg`，`im_payload`/`licensx`/`tokenx`
改道至此（[gopkg#1](../../issues/1) / [#2](../../issues/2) / [#3](../../issues/3)）。

## 包清单

### 业务能力（承自 `common/biz/*`）

| 包 | 说明 |
|---|---|
| `biz/bot` | IM 机器人统一门面（企微/钉钉/飞书/蓝信），`BotOne` 接口 + 安全模式 |
| `biz/email` | SMTP 发送器 |
| `biz/git` | 本地 git 仓库分支/标签读写与打 tag 推送 |
| `biz/online-git` | GitHub / GitLab / Gitea 平台统一 API 门面（provider 注册表） |
| `biz/zentao` | 禅道 API 客户端 |
| `biz/gps` `biz/identity` `biz/phone` `biz/vehicle` | 车牌 / 身份证 / 手机号校验 |

> `common/biz/lock` **已退役**，未接档——见下方重构表。

### 产品域内核（自 `oekit/pkg` 改道）

| 包 | 说明 | 来源 |
|---|---|---|
| `licensx` | Ed25519 license 签发/验签——载荷泛型 + 类型化哨兵 | oekit/pkg#486 |
| `tokenx` | 签名能力令牌（HMAC 载荷绑定 + 命令集规范化哈希） | oekit/pkg#487 |

## 依赖 oekit 的重构（2026-11-14）

本仓是 `common` 归档后的重建，顺手把 `common` 里手搓的件换成 oekit 单源：

| 原实现 | 现在 | 动因 |
|---|---|---|
| `utils/xlogger`（7 行自造接口） | **`oekit/logx`**，包级 `logx.Delegating("组件名")` | 红线：库包级 logger 必须 `Delegating`，禁 `Default()`/`WithService`（service name 属消费方） |
| `biz/lock`（自造 SetNX + 自旋） | **退役 → `oekit/redisx/distlock`**（契约 `oekit/pkg/distlock`） | 原实现三缺陷：`UpWait` 收 ctx 却从不检查、固定 100ms 自旋无退避无上限、`Down` 无条件 DEL 无法校验持有者 |
| 三家 provider 裸 `&http.Client{}` | **`oekit/httpx`** 受治理客户端（`biz/online-git/httpclient.go` 单源） | gitlab/gitea **完全零超时**，对端挂起即永久阻塞；gitea 还只在 `InsecureSkipTLS` 分支才下发自定义 client |

未替换的部分与理由：

- **`biz/bot` 的 HTTP 不动**：四家已有正确的 `Timeout: 5s`，换 httpx 反而要把超时交给
  httpx 分项上限、且要调用方传 Prometheus registry 才有额外收益——对 fire-and-forget 的
  webhook 发送是净负担。等真需要指标/链路时再接。
- **165 处 `fmt.Errorf` 未批量改 `oekit/pkg/errors`**：`BizError` 是服务 handler 出口的
  载体，对本仓这类库是错配；纯换 `%w` 包装是零收益 churn。

## 迁移自 `common`

```diff
- import "github.com/yi-nology/common/biz/bot"
+ import "github.com/yi-nology/gopkg/biz/bot"
```

- `utils/*`（xstrings/xtime/xjson…）**不接档**——`common` 归档时通用工具已交棒 `oekit/pkg`
  （stringx/timex/encoding…），重复接档只会造第二份单源。
- `biz/lock` 不再提供，直接用 `oekit/redisx/distlock`。
- `biz/vehicle`、`biz/git` 的方法签名去掉了 `log` 参数（logger 归包，不归调用点）。

## 开发

```bash
go build ./...
go vet ./...
gofmt -l .
go test ./... -count=1
```

CI 见 `.github/workflows/ci.yml`（push main / tag / PR 触发）。
