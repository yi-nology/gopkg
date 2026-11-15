package webhooksrc

import (
	"context"
	"sync"
	"time"
)

// 留痕状态。
const (
	EventAccepted = "accepted"
	EventRejected = "rejected"
)

// 拒绝原因码（稳定词表；管理面按此聚合/告警，不要匹配文案）。
const (
	ReasonUnknownSource = "unknown_source"
	ReasonDisabled      = "disabled"
	ReasonBadConfig     = "bad_config"
	ReasonBadToken      = "bad_token"
	ReasonBadSignature  = "bad_signature"
	ReasonRateLimited   = "rate_limited"
	ReasonBadPayload    = "bad_payload"
	ReasonFiltered      = "filtered"
	ReasonSinkError     = "error"
)

// Event 一次接入的留痕条目（宿主表结构自行加 ID/租户等列）。
type Event struct {
	Source    string    `json:"source"`
	Status    string    `json:"status"` // accepted | rejected
	Reason    string    `json:"reason,omitempty"`
	Input     string    `json:"input,omitempty"`
	Payload   string    `json:"payload,omitempty"` // 快照（默认原文截断；宿主可注入脱敏）
	CreatedAt time.Time `json:"created_at"`
}

// MemoryEventStore 进程内留痕实现（测试/单机；生产用宿主数据库表）。
type MemoryEventStore struct {
	mu     sync.Mutex
	events []Event
}

// Record 追加一条留痕。
func (m *MemoryEventStore) Record(_ context.Context, ev *Event) error {
	if ev == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, *ev)
	return nil
}

// Prune 删除 CreatedAt 早于 before 的条目，返回删除数。
func (m *MemoryEventStore) Prune(_ context.Context, before time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := m.events[:0]
	var n int64
	for _, ev := range m.events {
		if ev.CreatedAt.Before(before) {
			n++
			continue
		}
		kept = append(kept, ev)
	}
	m.events = kept
	return n, nil
}

// Events 返回留痕快照（拷贝）。
func (m *MemoryEventStore) Events() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Event(nil), m.events...)
}

// MemorySourceStore 进程内源配置实现（测试/单机）。
type MemorySourceStore struct {
	mu      sync.Mutex
	sources map[string]*Source
}

// NewMemorySourceStore 构造并灌入初始源（nil 元素忽略）。
func NewMemorySourceStore(sources ...*Source) *MemorySourceStore {
	m := &MemorySourceStore{sources: make(map[string]*Source, len(sources))}
	for _, s := range sources {
		if s != nil {
			m.sources[s.Name] = cloneSource(s)
		}
	}
	return m
}

// Get 按名取源（返回拷贝，调用方改不动存储）。
func (m *MemorySourceStore) Get(_ context.Context, name string) (*Source, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sources[name]
	if !ok {
		return nil, nil
	}
	return cloneSource(s), nil
}

// Save 覆盖/新增源。
func (m *MemorySourceStore) Save(_ context.Context, src *Source) error {
	if src == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sources[src.Name] = cloneSource(src)
	return nil
}

func cloneSource(s *Source) *Source {
	cp := *s
	cp.Filters = append([]Filter(nil), s.Filters...)
	return &cp
}
