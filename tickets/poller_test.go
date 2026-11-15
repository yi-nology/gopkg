package tickets

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

var pollNow = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

type fakeSource struct {
	name       string
	enabled    bool
	items      []Item
	searchErr  error
	writeErr   error
	searches   int
	writeBacks []Item
	outcomes   []string
}

func (f *fakeSource) Name() string  { return f.name }
func (f *fakeSource) Enabled() bool { return f.enabled }
func (f *fakeSource) Search(context.Context) ([]Item, error) {
	f.searches++
	return f.items, f.searchErr
}
func (f *fakeSource) WriteBack(_ context.Context, item Item, outcome string) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	f.writeBacks = append(f.writeBacks, item)
	f.outcomes = append(f.outcomes, outcome)
	return nil
}

type fakeLedger struct {
	existing  map[string]bool
	claims    []string
	calls     int
	failAt    int
	err       error
	errSource string
}

func newFakeLedger(existing ...string) *fakeLedger {
	l := &fakeLedger{existing: make(map[string]bool, len(existing))}
	for _, key := range existing {
		l.existing[key] = true
	}
	return l
}

func (l *fakeLedger) Claim(_ context.Context, source string, item Item) (bool, error) {
	l.calls++
	matchesSource := l.errSource == "" || l.errSource == source
	if l.err != nil && matchesSource && (l.failAt == 0 || l.calls == l.failAt) {
		return false, l.err
	}
	key := source + "/" + item.Key
	if l.existing[key] {
		return false, nil
	}
	l.existing[key] = true
	l.claims = append(l.claims, key)
	return true, nil
}

// TestPollerSuccess 轮询闭环：禁用源跳过、已存在链路跳过、Claim→Handle→
// WriteBack 顺序、汇总回执与注入时钟。
func TestPollerSuccess(t *testing.T) {
	disabled := &fakeSource{name: "disabled", enabled: false}
	active := &fakeSource{
		name:    "jira",
		enabled: true,
		items: []Item{
			{Key: "OPS-1", Title: "one"},
			{Key: "OPS-2", Title: "two"},
		},
	}
	ledger := newFakeLedger("jira/OPS-1")
	var handled []string
	p := &Poller[Source]{
		Sources: []Source{disabled, active},
		Ledger:  ledger,
		Handler: func(_ context.Context, item Item) (string, error) {
			handled = append(handled, item.Key)
			return "已诊断 " + item.Key, nil
		},
		Now: func() time.Time { return pollNow },
	}
	report, err := p.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(handled) != 1 || handled[0] != "OPS-2" {
		t.Fatalf("handler 处理 = %v", handled)
	}
	if len(active.writeBacks) != 1 || active.writeBacks[0].Key != "OPS-2" || active.outcomes[0] != "已诊断 OPS-2" {
		t.Fatalf("回写失真: %+v / %+v", active.writeBacks, active.outcomes)
	}
	if len(report.Sources) != 2 {
		t.Fatalf("源回执数 = %d", len(report.Sources))
	}
	if !report.Sources[0].Disabled || report.Sources[0].Source != "disabled" {
		t.Fatalf("禁用源回执失真: %+v", report.Sources[0])
	}
	sr := report.Sources[1]
	if sr.Found != 2 || sr.Claimed != 1 || sr.Skipped != 1 || sr.Handled != 1 || sr.WrittenBack != 1 {
		t.Fatalf("jira 回执失真: %+v", sr)
	}
	if report.Found != 2 || report.Claimed != 1 || report.Skipped != 1 || report.Handled != 1 || report.WrittenBack != 1 {
		t.Fatalf("汇总失真: %+v", report)
	}
	if !report.StartedAt.Equal(pollNow) || !report.FinishedAt.Equal(pollNow) {
		t.Fatalf("时钟未注入: %+v", report)
	}
	if disabled.searches != 0 {
		t.Fatal("禁用源不应被 Search")
	}
}

// TestPollerSingleSourceFailureDoesNotBlock 单源 Search 失败不阻塞后续源；
// Claim 失败按 fail-closed 中止该源（后续条目不再处理）但仍继续下一源。
func TestPollerSingleSourceFailureDoesNotBlock(t *testing.T) {
	broken := &fakeSource{name: "broken", enabled: true, searchErr: errors.New("jira 503")}
	healthy := &fakeSource{name: "healthy", enabled: true, items: []Item{{Key: "H-1"}}}
	var handled []string
	p := &Poller[Source]{
		Sources: []Source{broken, healthy},
		Ledger:  newFakeLedger(),
		Handler: func(_ context.Context, item Item) (string, error) {
			handled = append(handled, item.Key)
			return "ok", nil
		},
	}
	report, err := p.Poll(context.Background())
	if err != nil {
		t.Fatalf("单源失败不应让整轮报错: %v", err)
	}
	if len(report.Sources[0].Errors) == 0 || !strings.Contains(report.Sources[0].Errors[0], "jira 503") {
		t.Fatalf("失败源应记录错误: %+v", report.Sources[0])
	}
	if report.Sources[1].Handled != 1 || len(handled) != 1 {
		t.Fatalf("后续源应继续处理: %+v", report.Sources[1])
	}

	claimFail := &fakeSource{name: "claimfail", enabled: true, items: []Item{{Key: "C-1"}, {Key: "C-2"}}}
	ledger := newFakeLedger()
	ledger.err = errors.New("unique index unavailable")
	ledger.errSource = "claimfail" // 只让该源 Claim 失败，健康源仍可去重
	handled = nil
	p = &Poller[Source]{
		Sources: []Source{claimFail, healthy},
		Ledger:  ledger,
		Handler: func(_ context.Context, item Item) (string, error) {
			handled = append(handled, item.Key)
			return "ok", nil
		},
	}
	report, err = p.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if ledger.calls != 2 {
		t.Fatalf("claimfail 首次失败即中止该源、健康源继续 Claim，calls=%d", ledger.calls)
	}
	if len(report.Sources[0].Errors) == 0 || !strings.Contains(report.Sources[0].Errors[0], "unique index") {
		t.Fatalf("Claim 失败应记录: %+v", report.Sources[0])
	}
	if len(handled) != 1 || handled[0] != "H-1" {
		t.Fatalf("Claim 失败源不应调用 handler，健康源应处理: %v", handled)
	}
	if report.Sources[1].Handled != 1 {
		t.Fatalf("下一源应继续: %+v", report.Sources[1])
	}
}

// TestPollerItemFailures Handler/WriteBack/空 key 失败面：计数如实、不阻断
// 同源后续条目、不虚构回写。
func TestPollerItemFailures(t *testing.T) {
	handlerErr := errors.New("session create failed")
	writeErr := errors.New("comment post failed")
	src := &fakeSource{
		name: "jira", enabled: true,
		items: []Item{{Key: "E-1"}, {Key: ""}, {Key: "E-2"}},
	}
	ledger := newFakeLedger()
	var handled []string
	p := &Poller[Source]{
		Sources: []Source{src},
		Ledger:  ledger,
		Handler: func(_ context.Context, item Item) (string, error) {
			handled = append(handled, item.Key)
			if item.Key == "E-1" {
				return "", handlerErr
			}
			return "ok", nil
		},
	}
	report, err := p.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	sr := report.Sources[0]
	if sr.Found != 3 || sr.Claimed != 2 || sr.Handled != 1 || sr.WrittenBack != 1 {
		t.Fatalf("计数失真: %+v", sr)
	}
	if len(sr.Errors) != 2 {
		t.Fatalf("应记录空 key + handler 失败两条错误: %+v", sr.Errors)
	}
	if len(handled) != 2 || handled[0] != "E-1" || handled[1] != "E-2" {
		t.Fatalf("后续条目应继续: %v", handled)
	}

	// WriteBack 失败：Handle 已发生，但 WrittenBack 不增。
	src = &fakeSource{name: "jira", enabled: true, items: []Item{{Key: "W-1"}}, writeErr: writeErr}
	p = &Poller[Source]{
		Sources: []Source{src},
		Ledger:  newFakeLedger(),
		Handler: func(context.Context, Item) (string, error) { return "ok", nil },
	}
	report, err = p.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if report.Sources[0].Handled != 1 || report.Sources[0].WrittenBack != 0 {
		t.Fatalf("回写失败计数失真: %+v", report.Sources[0])
	}
	if len(report.Sources[0].Errors) != 1 || !strings.Contains(report.Sources[0].Errors[0], "comment post failed") {
		t.Fatalf("回写失败应记录: %+v", report.Sources[0].Errors)
	}
}

// TestPollerConfigAndNilFailClosed 配置错误、nil 源（含 typed-nil）、空源名、
// ctx 取消。
func TestPollerConfigAndNilFailClosed(t *testing.T) {
	handler := func(context.Context, Item) (string, error) { return "ok", nil }
	ledger := newFakeLedger()

	empty := &Poller[Source]{Ledger: ledger, Handler: handler}
	if _, err := empty.Poll(context.Background()); !errors.Is(err, ErrNoSources) {
		t.Fatalf("无源应 ErrNoSources，got %v", err)
	}
	src := &fakeSource{name: "s", enabled: true}
	if _, err := (&Poller[Source]{Sources: []Source{src}, Handler: handler}).Poll(context.Background()); !errors.Is(err, ErrPollerNotConfigured) {
		t.Fatalf("缺 Ledger 应 ErrPollerNotConfigured，got %v", err)
	}
	if _, err := (&Poller[Source]{Sources: []Source{src}, Ledger: ledger}).Poll(context.Background()); !errors.Is(err, ErrPollerNotConfigured) {
		t.Fatalf("缺 Handler 应 ErrPollerNotConfigured，got %v", err)
	}

	var nilIface Source
	p := &Poller[Source]{Sources: []Source{nilIface}, Ledger: ledger, Handler: handler}
	report, err := p.Poll(context.Background())
	if err != nil {
		t.Fatalf("nil 源不应让整轮报错: %v", err)
	}
	if len(report.Sources[0].Errors) != 1 || report.Sources[0].Errors[0] != "source 为 nil" {
		t.Fatalf("nil 源回执失真: %+v", report.Sources[0])
	}

	typedNil := &Poller[*fakeSource]{
		Sources: []*fakeSource{nil},
		Ledger:  ledger,
		Handler: handler,
	}
	report, err = typedNil.Poll(context.Background())
	if err != nil {
		t.Fatalf("typed-nil 不应让整轮报错: %v", err)
	}
	if len(report.Sources[0].Errors) != 1 || report.Sources[0].Errors[0] != "source 为 nil" {
		t.Fatalf("typed-nil 回执失真: %+v", report.Sources[0])
	}

	noName := &fakeSource{name: "  ", enabled: true, items: []Item{{Key: "N-1"}}}
	report, err = (&Poller[Source]{Sources: []Source{noName}, Ledger: ledger, Handler: handler}).Poll(context.Background())
	if err != nil {
		t.Fatalf("空源名不应让整轮报错: %v", err)
	}
	if noName.searches != 0 || report.Sources[0].Found != 0 {
		t.Fatalf("空源名应跳过 Search: searches=%d report=%+v", noName.searches, report.Sources[0])
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	src = &fakeSource{name: "s", enabled: true, items: []Item{{Key: "X-1"}}}
	report, err = (&Poller[Source]{Sources: []Source{src}, Ledger: ledger, Handler: handler}).Poll(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("取消应返回 context.Canceled，got %v", err)
	}
	if src.searches != 0 {
		t.Fatal("取消后不应 Search")
	}
	if report.FinishedAt.IsZero() {
		t.Fatal("取消回执应带 FinishedAt")
	}
}
