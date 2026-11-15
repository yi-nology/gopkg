package imchan

import (
	"context"
	"time"
)

// 断链重连退避单源（gopkg#5）。bianque internal/im 在 QQ / 企微 aibot 两处
// 各写了一份「1s 倍增到 60s」的循环（qq.go、wecom_aibot.go）；本文件把参数
// 与等待抽成一份，并用 Clock 注入把「等多久」从「测什么」里拆开——契约测试
// 用假时钟验证完整序列，不 sleep 真等。
const (
	// DefaultInitialBackoff 首次断链后的等待。
	DefaultInitialBackoff = time.Second
	// DefaultMaxBackoff 退避上限。
	DefaultMaxBackoff = 60 * time.Second
	// DefaultBackoffFactor 每次失败后的倍增系数。
	DefaultBackoffFactor = 2.0
)

// Backoff 重连退避参数（单源）。零值字段取默认：Initial=1s、Max=60s、
// Factor=2。序列：1s → 2s → 4s → 8s → 16s → 32s → 60s → 60s…
//
// 不掺随机抖动：抖动会让「同样的断链序列」在测试与线上产生不同等待，破坏
// 确定性；多副本惊群由平台侧连接互踢语义消化（QQ/aibot 都是单连接模型）。
type Backoff struct {
	Initial time.Duration // 首次等待（<=0 取默认）
	Max     time.Duration // 上限（<=0 取默认；小于 Initial 时取 Initial）
	Factor  float64       // 倍增系数（<1 取默认）
}

// Normalize 返回补齐默认值后的参数（导出给管理面展示/校验用）。
func (b Backoff) Normalize() Backoff {
	if b.Initial <= 0 {
		b.Initial = DefaultInitialBackoff
	}
	if b.Max <= 0 {
		b.Max = DefaultMaxBackoff
	}
	if b.Max < b.Initial {
		b.Max = b.Initial
	}
	if b.Factor < 1 {
		b.Factor = DefaultBackoffFactor
	}
	return b
}

// First 返回首次重连等待。
func (b Backoff) First() time.Duration { return b.Normalize().Initial }

// Next 返回上一档之后的下一次等待（prev<=0 视作首次；溢出/越界钳到 Max）。
func (b Backoff) Next(prev time.Duration) time.Duration {
	b = b.Normalize()
	if prev <= 0 {
		return b.Initial
	}
	next := time.Duration(float64(prev) * b.Factor)
	if next < prev || next > b.Max {
		return b.Max
	}
	return next
}

// Clock 重连等待时钟。生产用 RealClock；测试注入假时钟让退避序列瞬时可验。
type Clock interface {
	// Sleep 等待 d；ctx 取消时立即返回 ctx.Err()。
	Sleep(ctx context.Context, d time.Duration) error
}

// RealClock 真实时钟（time.Timer，可被 ctx 打断）。
type RealClock struct{}

// Sleep 实现 Clock。
func (RealClock) Sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Reconnecter 断链重连循环（单源）。一次 Start 持一个实例；不要跨通道共享
// （Backoff/Clock 可变字段的并发语义不属于本类型）。
type Reconnecter struct {
	Backoff Backoff
	Clock   Clock
	// OnRetry 每次安排重连前回调（日志/指标缝；nil=静默）。
	OnRetry func(err error, delay time.Duration)
	// Fatal 错误分类：返回非 nil 即终止循环并把它作为 Start 的返回值
	//（如「连续认证失败达阈值」）；返回 nil 继续退避重连。nil=全部重试。
	Fatal func(error) error
}

// Run 反复调用 session 直到 ctx 取消或 Fatal 判定终态。session 返回后
// （无论 nil 还是 error）只要 ctx 仍存活就按退避重连——长连接通道的
// 「返回即断链」由调用方的 session 语义保证。
func (r Reconnecter) Run(ctx context.Context, session func(context.Context) error) error {
	if session == nil {
		return nil
	}
	b := r.Backoff.Normalize()
	clock := r.Clock
	if clock == nil {
		clock = RealClock{}
	}
	delay := b.Initial
	for {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		err := session(ctx)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if r.Fatal != nil {
			if fatalErr := r.Fatal(err); fatalErr != nil {
				return fatalErr
			}
		}
		if r.OnRetry != nil {
			r.OnRetry(err, delay)
		}
		if sleepErr := clock.Sleep(ctx, delay); sleepErr != nil {
			return sleepErr
		}
		delay = b.Next(delay)
	}
}
