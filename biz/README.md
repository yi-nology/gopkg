# Biz - 业务功能模块

本目录包含企业级应用的各类业务功能模块，提供开箱即用的集成能力。

## 📚 模块列表

### 🤖 智能机器人 (bot)

企业即时通讯平台机器人集成，支持多种消息类型和交互能力。

#### 支持的平台

| 平台 | 目录 | 功能特性 |
|------|------|----------|
| 钉钉 | [dingtalk](bot/dingtalk) | 文本、Markdown、链接、Feed卡片、ActionCard |
| 蓝信 | [lanxin](bot/lanxin) | 文本、Markdown |
| 飞书 | [lark](bot/lark) | 文本、图片、富文本、交互式卡片 |
| 企业微信 | [wxwork](bot/wxwork) | 文本、Markdown、图片、图文、模板卡片、媒体文件 |

**使用示例:**
```go
// 钉钉机器人发送Markdown消息
bot := dingtalk.NewRobot("your_webhook_url")
err := bot.SendMarkdown("标题", "**加粗文本**\n- 列表项")

// 飞书机器人发送交互卡片
bot := lark.NewRobot("your_webhook_url")
card := lark.NewInteractiveCard()
card.AddTitle("通知标题").AddField("字段1", "值1")
err := bot.SendInteractive(card)
```

---

### 📧 邮件服务 (email)

功能完整的SMTP邮件发送SDK，支持各类邮件场景。

**核心功能:**
- ✅ SMTP协议支持(TLS/SSL)
- ✅ HTML/纯文本邮件
- ✅ 多附件支持
- ✅ 批量发送
- ✅ 优先级设置
- ✅ 自动重试机制

**快速开始:**
```go
import "github.com/yi-nology/gopkg/biz/email"

config := &email.Config{
    Host:      "smtp.example.com",
    Port:      587,
    Username:  "user@example.com",
    Password:  "password",
    FromEmail: "sender@example.com",
}

sender, _ := email.NewSMTPSender(config)
message := &email.Message{
    To:      []string{"recipient@example.com"},
    Subject: "测试邮件",
    Text:    "邮件内容",
}

sender.Send(context.Background(), message)
```

**详细文档:** 查看 [example_test.go](email/example_test.go) 获取更多示例

---

### 🔗 在线Git服务 (online-git)

统一的Git托管平台SDK，支持多平台无缝切换。

**支持的平台:**
- ✅ Gitea
- ✅ GitHub
- ✅ GitLab

**功能特性:**
- 📦 仓库管理 - 获取仓库信息
- 🌿 分支管理 - 列表、创建、删除、保护、比较
- 🔀 Pull Request - 创建、查询、合并、评论
- 📝 提交管理 - 查询提交历史和详情
- 🚀 CI/CD Pipeline - 触发、查询、取消、重试流水线

**使用示例:**
```go
import "github.com/yi-nology/gopkg/biz/online-git"

config := &onlinegit.ProviderConfig{
    Platform: onlinegit.PlatformGitHub,
    BaseURL:  "https://api.github.com",
    Token:    "your_token",
    Owner:    "username",
    Repo:     "repository",
}

provider, _ := onlinegit.NewProvider(config)

// 获取仓库信息
repo, _ := provider.GetRepository(ctx)

// 列出分支
branches, _ := provider.ListBranches(ctx, &onlinegit.ListOptions{Page: 1, PerPage: 10})

// 触发Pipeline
pipeline, _ := provider.TriggerPipeline(ctx, &onlinegit.TriggerPipelineOptions{
    Ref: "main",
})
```

**详细文档:** 查看 [online-git/README.md](online-git/README.md)

---

### 🛠️ 禅道集成 (zentao)

禅道项目管理系统的完整API封装。

**功能模块:**
- 📋 产品管理 (products)
- 📊 项目管理 (projects)
- 🎯 任务管理 (tasks)
- 📖 需求管理 (stories)
- 🐛 缺陷管理 (bugs)
- 📦 版本发布 (releases)
- 🧪 测试计划 (plans)
- 🏗️ 构建管理 (builds)
- ⏱️ 工时管理 (effort)
- 👥 用户管理 (users)

**使用示例:**
```go
import "github.com/yi-nology/gopkg/biz/zentao"

client := zentao.NewClient("http://zentao.example.com", "username", "password")

// 获取产品列表
products, _ := client.GetProducts()

// 创建任务
task := &zentao.Task{
    Project: 1,
    Name:    "任务名称",
    Type:    "开发",
}
taskID, _ := client.CreateTask(task)

// 更新Bug状态
err := client.UpdateBug(bugID, map[string]interface{}{
    "status": "resolved",
})
```

**详细文档:** 查看 [zentao/README.md](zentao/README.md)

---

### 🔧 其他服务

#### Git 操作 (git)
本地Git仓库操作封装

```go
import "github.com/yi-nology/gopkg/biz/git"

repo, _ := git.OpenRepository("/path/to/repo")
commits, _ := repo.GetCommits("main", 10)
```

#### GPS 定位 (gps)
地理位置处理工具

```go
import "github.com/yi-nology/gopkg/biz/gps"

distance := gps.Distance(lat1, lon1, lat2, lon2)
```

#### 身份认证 (identity)
身份信息验证（身份证等）

```go
import "github.com/yi-nology/gopkg/biz/identity"

isValid := identity.ValidateIDCard("身份证号码")
```

#### 分布式锁 (lock) —— 已退役

`common/biz/lock` **不再接档**：原实现有三个缺陷（`UpWait` 收 ctx 却从不检查、
固定 100ms 自旋无退避无上限、`Down` 无条件 DEL 无法校验持有者），且 oekit 已有
更完整的实现。直接用：

```go
import (
    "github.com/oekit/redisx/distlock"
    pkgdistlock "github.com/oekit/pkg/distlock"
)

locker := distlock.NewRedisLocker(rdb) // *distlock.RedisLocker 实现 pkgdistlock.Locker

ownerID, err := locker.Lock(ctx, "lock_key", ttl, timeout) // 阻塞获取，带超时
defer locker.Unlock(ctx, "lock_key", ownerID)              // ownerID 必须匹配——只有持有者能释放
```

契约与哨兵（`ErrLockNotAcquired` / `ErrLockTimeout` / `ErrLockNotHeld`）单源在
`oekit/pkg/distlock`，`errors.Is` 跨包判定正确。

#### 手机号服务 (phone)
手机号码处理和验证

```go
import "github.com/yi-nology/gopkg/biz/phone"

isValid := phone.ValidateMobile("13800138000")
operator := phone.GetOperator("13800138000")
```

#### 车辆管理 (vehicle)
车辆信息处理

```go
import "github.com/yi-nology/gopkg/biz/vehicle"

isValid := vehicle.ValidatePlate("京A12345")
```

---

## 🚀 快速开始

### 安装

```bash
go get github.com/yi-nology/gopkg/biz
```

### 导入使用

```go
import (
    "github.com/yi-nology/gopkg/biz/bot/dingtalk"
    "github.com/yi-nology/gopkg/biz/email"
    "github.com/yi-nology/gopkg/biz/online-git"
    "github.com/yi-nology/gopkg/biz/zentao"
)
```

---

## 📖 设计理念

### 1. 统一接口
所有同类服务提供统一的接口定义，降低学习成本和切换成本。

### 2. 开箱即用
提供合理的默认配置，简单场景无需复杂配置即可使用。

### 3. 模块化设计
每个模块职责单一，按功能拆分文件，代码清晰易维护。

### 4. 完善的错误处理
统一的错误类型定义，便于错误判断和处理。

### 5. 丰富的示例
每个模块都提供详细的使用示例和测试用例。

---

## 🤝 贡献

欢迎提交Issue和Pull Request来帮助改进这个项目。

---

## 📄 许可证

本项目采用 [项目许可证] 开源协议。

---

## 📞 联系方式

如有问题或建议，请通过以下方式联系：
- Issue: [GitHub Issues](https://github.com/yi-nology/gopkg/issues)
- Email: [项目联系邮箱]
