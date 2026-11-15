package ticket

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Source 取单源（宿主实现）：Enabled 决定本轮是否扫描，Search 取一批工单，
// Seen 是唯一索引去重（已处理过返回 true），Handle 执行建会话/回写等动作。
// 单源/单条失败只进报告，不阻塞其他源与条目。
type Source[Item any] interface {
	Name() string
	Enabled() bool
	Search(ctx context.Context) ([]Item, error)
	Seen(ctx context.Context, item Item) (bool, error)
	Handle(ctx context.Context, item Item) error
}

// PollError 一轮轮询中的单点失败（source+phase 定位）。
type PollError struct {
	Source string
	Phase  string // search|seen|handle|context
	Err    error
}

func (e PollError) Error() string {
	return fmt.Sprintf("取单源 %s %s 失败: %v", e.Source, e.Phase, e.Err)
}

func (e PollError) Unwrap() error { return e.Err }

// PollReport 单轮轮询报告（宿主日志/指标消费）。
type PollReport struct {
	Sources         int // 本轮源总数
	DisabledSources int // 跳过（Enabled=false）
	Searched        int // Search 返回的条目数
	Duplicates      int // Seen=true 跳过的条目数
	Handled         int // Handle 成功的条目数
	Errors          []PollError
}

// Err 聚合报告中的错误（无错误返回 nil）。
func (r PollReport) Err() error {
	if len(r.Errors) == 0 {
		return nil
	}
	errs := make([]error, 0, len(r.Errors))
	for _, e := range r.Errors {
		errs = append(errs, e)
	}
	return errors.Join(errs...)
}

// Poller 取单轮询骨架（无状态；泛型 Item 由宿主定义）。逐源串行执行，
// 单源失败/单条失败不阻塞其他源与其他条目——有损原则。
type Poller[Item any] struct{}

// NewPoller 构造轮询器。
func NewPoller[Item any]() *Poller[Item] { return &Poller[Item]{} }

// Poll 执行一轮：按 sources 顺序逐源串行；Enabled=false 跳过；Search 失败
// 记录后进入下一源；每条先 Seen 去重再 Handle。
func (p *Poller[Item]) Poll(ctx context.Context, sources []Source[Item]) PollReport {
	var rep PollReport
	rep.Sources = len(sources)
	for _, src := range sources {
		if src == nil {
			continue
		}
		if err := ctx.Err(); err != nil {
			rep.Errors = append(rep.Errors, PollError{Source: src.Name(), Phase: "context", Err: err})
			return rep
		}
		if !src.Enabled() {
			rep.DisabledSources++
			continue
		}
		items, err := src.Search(ctx)
		if err != nil {
			rep.Errors = append(rep.Errors, PollError{Source: src.Name(), Phase: "search", Err: err})
			continue
		}
		rep.Searched += len(items)
		for _, item := range items {
			if err := ctx.Err(); err != nil {
				rep.Errors = append(rep.Errors, PollError{Source: src.Name(), Phase: "context", Err: err})
				return rep
			}
			seen, err := src.Seen(ctx, item)
			if err != nil {
				// 去重状态未知时宁可不处理，避免重复建会话/重复回写。
				rep.Errors = append(rep.Errors, PollError{Source: src.Name(), Phase: "seen", Err: err})
				continue
			}
			if seen {
				rep.Duplicates++
				continue
			}
			if err := src.Handle(ctx, item); err != nil {
				rep.Errors = append(rep.Errors, PollError{Source: src.Name(), Phase: "handle", Err: err})
				continue
			}
			rep.Handled++
		}
	}
	return rep
}

// String 报告摘要（日志友好）。
func (r PollReport) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "sources=%d disabled=%d searched=%d duplicates=%d handled=%d errors=%d",
		r.Sources, r.DisabledSources, r.Searched, r.Duplicates, r.Handled, len(r.Errors))
	return b.String()
}
