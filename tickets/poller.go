package tickets

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"
)

// Item 取单条目：Source 产出的最小工单面，细节放 Data。
type Item struct {
	Key       string         `json:"key"`
	Title     string         `json:"title,omitempty"`
	URL       string         `json:"url,omitempty"`
	UpdatedAt time.Time      `json:"updated_at,omitempty"`
	Data      map[string]any `json:"data,omitempty"`
}

// Source 取单源（issue 里 Poller[Source] 的 Source 契约）：启停、搜索、
// 回写三面都由宿主实现。Search 内部分页/查询由宿主适配具体平台客户端；
// WriteBack 必须是幂等的（同一 outcome 重投不产生重复评论）。
type Source interface {
	Name() string
	Enabled() bool
	Search(ctx context.Context) ([]Item, error)
	WriteBack(ctx context.Context, item Item, outcome string) error
}

// Ledger 链路去重账本：以 (source, item.Key) 唯一索引 Claim 处理权。
// 首次 Claim 返回 true；已存在返回 false（跳过）。实现应使用 INSERT ...
// ON CONFLICT DO NOTHING 或等价原子形态——先查后插会在并发轮询下重复建会话。
type Ledger interface {
	Claim(ctx context.Context, source string, item Item) (claimed bool, err error)
}

// Handler 工单消费函数：建会话/诊断等宿主动作，返回回写正文 outcome。
type Handler func(ctx context.Context, item Item) (outcome string, err error)

// Poller 取单轮询骨架：逐源串行、单源失败不阻塞其它源、唯一索引去重、
// 成功后回写闭环。S 由宿主选择（[Source] 或自己的具体实现类型）。
type Poller[S Source] struct {
	Sources []S
	Ledger  Ledger
	Handler Handler
	// Now 时钟注入（测试/快照；nil = time.Now）。
	Now func() time.Time
}

// SourceReport 单源轮询回执。Errors 非空表示该源本次有失败（不阻塞其它源）。
type SourceReport struct {
	Source      string   `json:"source"`
	Disabled    bool     `json:"disabled,omitempty"`
	Found       int      `json:"found"`
	Claimed     int      `json:"claimed"`
	Skipped     int      `json:"skipped"`
	Handled     int      `json:"handled"`
	WrittenBack int      `json:"written_back"`
	Errors      []string `json:"errors,omitempty"`
}

// PollReport 一轮轮询汇总回执。
type PollReport struct {
	StartedAt   time.Time      `json:"started_at"`
	FinishedAt  time.Time      `json:"finished_at"`
	Found       int            `json:"found"`
	Claimed     int            `json:"claimed"`
	Skipped     int            `json:"skipped"`
	Handled     int            `json:"handled"`
	WrittenBack int            `json:"written_back"`
	Sources     []SourceReport `json:"sources"`
}

// Poll 执行一轮轮询。配置错误（无源/缺 Ledger/Handler）在开始前返回；
// ctx 取消返回已执行部分 + ctx.Err()。单源 Search/Claim/Handler/WriteBack
// 失败只记入该源 Errors，不阻塞其它源。
func (p *Poller[S]) Poll(ctx context.Context) (PollReport, error) {
	now := p.Now
	if now == nil {
		now = time.Now
	}
	report := PollReport{StartedAt: now()}
	finish := func() {
		report.FinishedAt = now()
		for _, sr := range report.Sources {
			report.Found += sr.Found
			report.Claimed += sr.Claimed
			report.Skipped += sr.Skipped
			report.Handled += sr.Handled
			report.WrittenBack += sr.WrittenBack
		}
	}
	if len(p.Sources) == 0 {
		finish()
		return report, ErrNoSources
	}
	if p.Ledger == nil || p.Handler == nil {
		finish()
		return report, ErrPollerNotConfigured
	}

	for _, src := range p.Sources {
		sr := SourceReport{}
		report.Sources = append(report.Sources, sr)
		idx := len(report.Sources) - 1
		if isNilSource(src) {
			report.Sources[idx].Errors = append(report.Sources[idx].Errors, "source 为 nil")
			continue
		}
		name := src.Name()
		if strings.TrimSpace(name) == "" {
			report.Sources[idx].Errors = append(report.Sources[idx].Errors, "source 名称为空")
			continue
		}
		report.Sources[idx].Source = name
		if err := ctx.Err(); err != nil {
			report.Sources[idx].Errors = append(report.Sources[idx].Errors, err.Error())
			finish()
			return report, err
		}
		if !src.Enabled() {
			report.Sources[idx].Disabled = true
			continue
		}
		items, err := src.Search(ctx)
		if err != nil {
			report.Sources[idx].Errors = append(report.Sources[idx].Errors, fmt.Sprintf("search: %v", err))
			continue
		}
		report.Sources[idx].Found = len(items)

		for _, item := range items {
			if err := ctx.Err(); err != nil {
				report.Sources[idx].Errors = append(report.Sources[idx].Errors, err.Error())
				finish()
				return report, err
			}
			if strings.TrimSpace(item.Key) == "" {
				report.Sources[idx].Errors = append(report.Sources[idx].Errors, "item key 为空")
				continue
			}
			claimed, err := p.Ledger.Claim(ctx, report.Sources[idx].Source, item)
			if err != nil {
				// 无法判重时中止该源：继续处理会制造重复会话。
				report.Sources[idx].Errors = append(report.Sources[idx].Errors, fmt.Sprintf("claim %s: %v", item.Key, err))
				break
			}
			if !claimed {
				report.Sources[idx].Skipped++
				continue
			}
			report.Sources[idx].Claimed++

			outcome, err := p.Handler(ctx, item)
			if err != nil {
				report.Sources[idx].Errors = append(report.Sources[idx].Errors, fmt.Sprintf("handle %s: %v", item.Key, err))
				continue
			}
			report.Sources[idx].Handled++

			if err := src.WriteBack(ctx, item, outcome); err != nil {
				report.Sources[idx].Errors = append(report.Sources[idx].Errors, fmt.Sprintf("writeback %s: %v", item.Key, err))
				continue
			}
			report.Sources[idx].WrittenBack++
		}
	}
	finish()
	return report, nil
}

// isNilSource 识别 nil 接口与 typed-nil 指针（泛型 S 可能为具体类型，
// 不能直接与 nil 比较）。
func isNilSource[S Source](src S) bool {
	v := any(src)
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}
