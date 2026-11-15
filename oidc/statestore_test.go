package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// captureStateStore 记录 Save 入参，Take 按 state 单次返回（模拟任意后端）。
type captureStateStore struct {
	mu       sync.Mutex
	state    string
	flow     Flow
	ttl      time.Duration
	consumed bool
}

func (s *captureStateStore) Save(_ context.Context, state string, f Flow, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state, s.flow, s.ttl, s.consumed = state, f, ttl, false
	return nil
}

func (s *captureStateStore) Take(_ context.Context, state string) (Flow, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.consumed || state != s.state {
		return Flow{}, false, nil
	}
	s.consumed = true
	return s.flow, true, nil
}

func (s *captureStateStore) saved() (string, Flow, time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state, s.flow, s.ttl
}

// stateStoreFunc 用函数拼一个 StateStore（只实现被测路径，其余走零值）。
type stateStoreFunc struct {
	save func(context.Context, string, Flow, time.Duration) error
	take func(context.Context, string) (Flow, bool, error)
}

func (s stateStoreFunc) Save(ctx context.Context, state string, f Flow, ttl time.Duration) error {
	if s.save != nil {
		return s.save(ctx, state, f, ttl)
	}
	return nil
}

func (s stateStoreFunc) Take(ctx context.Context, state string) (Flow, bool, error) {
	if s.take != nil {
		return s.take(ctx, state)
	}
	return Flow{}, false, nil
}

// TestSharedStateStoreAcrossClients 验收（gopkg#29）：两个 Client 共享同一
// StateStore——A BeginLogin、B CompleteLogin 成功；state 单次消费，Take 二次
// 调用返回空。
func TestSharedStateStoreAcrossClients(t *testing.T) {
	i := newIDP(t)
	store := NewMemoryStateStore()
	cfg := func(cfg *Config) { cfg.StateStore = store }
	a := newTestClient(i, cfg)
	b := newTestClient(i, cfg)

	_, state, nonce, _ := begin(t, a, "browser-7")
	i.setNonce(nonce)

	res, err := complete(b, state)
	if err != nil {
		t.Fatalf("B CompleteLogin（共享 StateStore）: %v", err)
	}
	if res.Subject != "user-1" || res.Anchor != "browser-7" {
		t.Fatalf("result = %+v", res)
	}
	if _, _, token := i.counts(); token != 1 {
		t.Fatalf("token 端点请求次数 = %d, want 1", token)
	}

	// 重放（换回 A）不得到达 token 端点。
	if _, err := complete(a, state); !errors.Is(err, ErrFlowInvalid) {
		t.Fatalf("replay err = %v, want ErrFlowInvalid", err)
	}
	if _, _, token := i.counts(); token != 1 {
		t.Fatalf("token 端点请求次数 = %d, want 1（重放不得触网）", token)
	}

	// Store 层原子单次消费：二次 Take 返回空。
	if f, ok, err := store.Take(context.Background(), state); err != nil || ok {
		t.Fatalf("二次 Take = (%+v, %v, %v), want 空", f, ok, err)
	}
}

// TestBeginLoginSavesFlowSnapshot 验收（gopkg#29）：Flow 快照字段可导出、
// 可被宿主持久化——BeginLogin 把 nonce/verifier/anchor/created_at 与 FlowTTL
// 交给 StateStore，verifier 与授权 URL 的 S256 challenge 对应。
func TestBeginLoginSavesFlowSnapshot(t *testing.T) {
	i := newIDP(t)
	store := &captureStateStore{}
	c := newTestClient(i, func(cfg *Config) {
		cfg.StateStore = store
		cfg.FlowTTL = 3 * time.Minute
	})

	_, state, nonce, challenge := begin(t, c, "anchor-9")
	savedState, f, ttl := store.saved()
	if savedState != state {
		t.Fatalf("Save state = %q, want %q", savedState, state)
	}
	if f.Nonce != nonce {
		t.Fatalf("Flow.Nonce = %q, want %q", f.Nonce, nonce)
	}
	if f.Anchor != "anchor-9" {
		t.Fatalf("Flow.Anchor = %q, want anchor-9", f.Anchor)
	}
	if f.CreatedAt.IsZero() {
		t.Fatal("Flow.CreatedAt 不应为零值")
	}
	if f.Verifier == "" {
		t.Fatal("Flow.Verifier 不应为空")
	}
	sum := sha256.Sum256([]byte(f.Verifier))
	if got := base64.RawURLEncoding.EncodeToString(sum[:]); got != challenge {
		t.Fatalf("Flow.Verifier 与授权 URL challenge 不对应: %q != %q", got, challenge)
	}
	if ttl != 3*time.Minute {
		t.Fatalf("Save ttl = %v, want 3m", ttl)
	}
}

// TestStateStoreErrorsAreDistinguishable 验收（gopkg#29）：Store 读失败与
// state 不存在可区分——前者错误链挂 ErrStateStore（并保留底层 error），
// 后者保持 ErrFlowInvalid。
func TestStateStoreErrorsAreDistinguishable(t *testing.T) {
	boom := errors.New("state store down")

	t.Run("Take 失败 → ErrStateStore，不触网", func(t *testing.T) {
		i := newIDP(t)
		c := newTestClient(i, func(cfg *Config) {
			cfg.StateStore = stateStoreFunc{
				take: func(context.Context, string) (Flow, bool, error) {
					return Flow{}, false, boom
				},
			}
		})
		_, err := complete(c, "state")
		if !errors.Is(err, ErrStateStore) {
			t.Fatalf("err = %v, want ErrStateStore", err)
		}
		if errors.Is(err, ErrFlowInvalid) {
			t.Fatalf("err = %v, Store 读失败不应与 state 不存在混淆", err)
		}
		if !errors.Is(err, boom) {
			t.Fatalf("err = %v, 应保留 Store 底层错误链", err)
		}
		if disco, _, token := i.counts(); disco != 0 || token != 0 {
			t.Fatalf("Store 读失败不应触网: disco=%d token=%d", disco, token)
		}
	})

	t.Run("state 不存在 → ErrFlowInvalid", func(t *testing.T) {
		i := newIDP(t)
		c := newTestClient(i, nil)
		_, err := complete(c, "never-issued")
		if !errors.Is(err, ErrFlowInvalid) {
			t.Fatalf("err = %v, want ErrFlowInvalid", err)
		}
		if errors.Is(err, ErrStateStore) {
			t.Fatalf("err = %v, state 不存在不应挂 Store 失败哨兵", err)
		}
	})

	t.Run("Save 失败 → ErrStateStore，无授权 URL", func(t *testing.T) {
		i := newIDP(t)
		c := newTestClient(i, func(cfg *Config) {
			cfg.StateStore = stateStoreFunc{
				save: func(context.Context, string, Flow, time.Duration) error {
					return boom
				},
			}
		})
		u, err := c.BeginLogin(context.Background(), "https://app/cb", "")
		if u != "" {
			t.Fatalf("Save 失败仍返回授权 URL: %q", u)
		}
		if !errors.Is(err, ErrStateStore) || !errors.Is(err, boom) {
			t.Fatalf("err = %v, want ErrStateStore 包装 %v", err, boom)
		}
	})
}

// TestCompleteLoginRechecksCreatedAtTTL 验收（gopkg#29）：即使 StateStore
// 完全忽略 ttl（模拟后端过期策略失效），Client 仍用 CreatedAt 复核 FlowTTL。
func TestCompleteLoginRechecksCreatedAtTTL(t *testing.T) {
	i := newIDP(t)
	store := &captureStateStore{} // Take 无视 ttl，永远返回保存的 Flow
	now := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	c := newTestClient(i, func(cfg *Config) {
		cfg.StateStore = store
		cfg.FlowTTL = 10 * time.Minute
		cfg.Now = func() time.Time { return now }
	})

	_, state, nonce, _ := begin(t, c, "")
	i.setNonce(nonce)
	now = now.Add(10*time.Minute + time.Second)

	if _, err := complete(c, state); !errors.Is(err, ErrFlowInvalid) {
		t.Fatalf("err = %v, want ErrFlowInvalid（Client 侧 CreatedAt 复核 TTL）", err)
	}
	if _, _, token := i.counts(); token != 0 {
		t.Fatalf("过期 flow 不应触达 token 端点: %d", token)
	}
}

// TestMemoryStateStoreSingleUseAndTTL MemoryStateStore 契约：单次消费、
// 过期剔除、缺失返回空、零值可用。
func TestMemoryStateStoreSingleUseAndTTL(t *testing.T) {
	ctx := context.Background()
	f := Flow{Nonce: "nonce-1", Verifier: "verifier-1", Anchor: "anchor-1", CreatedAt: time.Now()}

	t.Run("单次消费", func(t *testing.T) {
		store := NewMemoryStateStore()
		if err := store.Save(ctx, "state-1", f, time.Minute); err != nil {
			t.Fatalf("Save: %v", err)
		}
		got, ok, err := store.Take(ctx, "state-1")
		if err != nil || !ok {
			t.Fatalf("Take = (%+v, %v, %v), want 命中", got, ok, err)
		}
		if got.Nonce != f.Nonce || got.Verifier != f.Verifier || got.Anchor != f.Anchor ||
			!got.CreatedAt.Equal(f.CreatedAt) {
			t.Fatalf("Take flow = %+v, want %+v", got, f)
		}
		if _, ok, err := store.Take(ctx, "state-1"); err != nil || ok {
			t.Fatalf("二次 Take = (ok=%v, err=%v), want 空", ok, err)
		}
	})

	t.Run("TTL 到期", func(t *testing.T) {
		store := NewMemoryStateStore()
		if err := store.Save(ctx, "state-2", f, 10*time.Millisecond); err != nil {
			t.Fatalf("Save: %v", err)
		}
		time.Sleep(40 * time.Millisecond)
		if _, ok, err := store.Take(ctx, "state-2"); err != nil || ok {
			t.Fatalf("过期 Take = (ok=%v, err=%v), want 空", ok, err)
		}
	})

	t.Run("不存在的 state", func(t *testing.T) {
		store := NewMemoryStateStore()
		if _, ok, err := store.Take(ctx, "never-issued"); err != nil || ok {
			t.Fatalf("Take = (ok=%v, err=%v), want 空", ok, err)
		}
	})

	t.Run("零值可用", func(t *testing.T) {
		var store MemoryStateStore
		if err := store.Save(ctx, "state-3", f, time.Minute); err != nil {
			t.Fatalf("零值 Save: %v", err)
		}
		if _, ok, err := store.Take(ctx, "state-3"); err != nil || !ok {
			t.Fatalf("零值 Take = (ok=%v, err=%v), want 命中", ok, err)
		}
	})
}

// TestMemoryStateStoreConcurrentTake 原子单次消费：并发 Take 只有一个成功。
func TestMemoryStateStoreConcurrentTake(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStateStore()
	f := Flow{Nonce: "n", Verifier: "v", Anchor: "a", CreatedAt: time.Now()}
	if err := store.Save(ctx, "state", f, time.Minute); err != nil {
		t.Fatalf("Save: %v", err)
	}

	const n = 16
	var wg sync.WaitGroup
	var wins atomic.Int32
	for k := 0; k < n; k++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok, err := store.Take(ctx, "state"); err == nil && ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := wins.Load(); got != 1 {
		t.Fatalf("并发 Take 成功次数 = %d, want 1", got)
	}
}
