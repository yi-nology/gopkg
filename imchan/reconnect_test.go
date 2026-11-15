package imchan

// 断链重连退避契约测试：序列单源（1s→2s→4s→…→60s 封顶）、参数归一、
// 假时钟完整序列、Fatal 终态、ctx 取消。全部不 sleep 真等。

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBackoffSequence(t *testing.T) {
	b := Backoff{} // 零值取默认
	want := []time.Duration{
		1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second,
		16 * time.Second, 32 * time.Second, 60 * time.Second, 60 * time.Second,
	}
	if got := b.First(); got != want[0] {
		t.Fatalf("首次等待错: got %v want %v", got, want[0])
	}
	cur := b.First()
	for i := 1; i < len(want); i++ {
		cur = b.Next(cur)
		if cur != want[i] {
			t.Fatalf("第 %d 档错: got %v want %v", i, cur, want[i])
		}
	}
}

func TestBackoffNormalize(t *testing.T) {
	// Max 小于 Initial 时抬到 Initial，避免「上限反而更短」的锯齿。
	b := Backoff{Initial: 5 * time.Second, Max: time.Second, Factor: 2}.Normalize()
	if b.Max != 5*time.Second {
		t.Fatalf("Max 应抬到 Initial: %+v", b)
	}
	// 非法 Factor 回默认。
	if got := (Backoff{Factor: 0.5}).Normalize().Factor; got != DefaultBackoffFactor {
		t.Fatalf("非法 Factor 应回默认: %v", got)
	}
	// 自定义参数序列。
	c := Backoff{Initial: 100 * time.Millisecond, Max: 350 * time.Millisecond, Factor: 2}
	if got := c.Next(100 * time.Millisecond); got != 200*time.Millisecond {
		t.Fatalf("自定义倍增减: %v", got)
	}
	if got := c.Next(200 * time.Millisecond); got != 350*time.Millisecond {
		t.Fatalf("自定义上限钳制: %v", got)
	}
	// prev<=0 视作首次。
	if got := c.Next(0); got != 100*time.Millisecond {
		t.Fatalf("prev=0 应回首次: %v", got)
	}
}

// fakeClock 记录每次等待并按 stopAt 返回终止哨兵——退避序列瞬时可验。
type fakeClock struct {
	delays []time.Duration
	stopAt int
	err    error
}

func (c *fakeClock) Sleep(_ context.Context, d time.Duration) error {
	c.delays = append(c.delays, d)
	if c.stopAt > 0 && len(c.delays) >= c.stopAt {
		return c.err
	}
	return nil
}

func TestReconnecterSequenceWithFakeClock(t *testing.T) {
	stop := errors.New("stop-test")
	clock := &fakeClock{stopAt: 7, err: stop}
	r := Reconnecter{Clock: clock}
	sessionErr := errors.New("断开")
	calls := 0
	err := r.Run(context.Background(), func(context.Context) error {
		calls++
		return sessionErr
	})
	if !errors.Is(err, stop) {
		t.Fatalf("应返回时钟终止哨兵: %v", err)
	}
	want := []time.Duration{
		1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second,
		16 * time.Second, 32 * time.Second, 60 * time.Second,
	}
	if len(clock.delays) != len(want) {
		t.Fatalf("等待次数错: got %v want %v", clock.delays, want)
	}
	for i := range want {
		if clock.delays[i] != want[i] {
			t.Fatalf("第 %d 次等待错: got %v want %v", i, clock.delays[i], want[i])
		}
	}
	if calls != len(want) {
		t.Fatalf("session 调用次数错: got %d want %d", calls, len(want))
	}
}

func TestReconnecterFatalStopsImmediately(t *testing.T) {
	fatalErr := errors.New("凭证被吊销")
	authErr := errors.New("认证失败")
	clock := &fakeClock{}
	r := Reconnecter{
		Clock: clock,
		Fatal: func(err error) error {
			if errors.Is(err, authErr) {
				return fatalErr
			}
			return nil
		},
	}
	err := r.Run(context.Background(), func(context.Context) error {
		return authErr
	})
	if !errors.Is(err, fatalErr) {
		t.Fatalf("Fatal 应终止循环: %v", err)
	}
	if len(clock.delays) != 0 {
		t.Fatalf("Fatal 后不应等待: %v", clock.delays)
	}
}

func TestReconnecterCtxCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := Reconnecter{}
	if err := r.Run(ctx, func(context.Context) error {
		t.Fatal("ctx 已取消不应再调用 session")
		return nil
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("应返回 ctx.Err: %v", err)
	}

	// session 返回后 ctx 取消：返回 ctx.Err，不进入等待。
	ctx2, cancel2 := context.WithCancel(context.Background())
	r2 := Reconnecter{Clock: &fakeClock{}}
	if err := r2.Run(ctx2, func(context.Context) error {
		cancel2()
		return errors.New("断开")
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("session 后取消应返回 ctx.Err: %v", err)
	}
}

func TestReconnecterOnRetryObserves(t *testing.T) {
	clock := &fakeClock{stopAt: 2, err: errors.New("stop")}
	var got []time.Duration
	r := Reconnecter{
		Clock: clock,
		OnRetry: func(_ error, d time.Duration) {
			got = append(got, d)
		},
	}
	_ = r.Run(context.Background(), func(context.Context) error { return errors.New("断开") })
	want := []time.Duration{1 * time.Second, 2 * time.Second}
	if len(got) != len(want) {
		t.Fatalf("OnRetry 次数错: %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("OnRetry 第 %d 档错: %v want %v", i, got[i], want[i])
		}
	}
}

func TestRealClockCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (RealClock{}).Sleep(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("RealClock 应被 ctx 打断: %v", err)
	}
	// 零等待立即返回（ctx 存活时无错误）。
	if err := (RealClock{}).Sleep(context.Background(), 0); err != nil {
		t.Fatalf("零等待不应报错: %v", err)
	}
}
