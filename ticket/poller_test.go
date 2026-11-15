package ticket

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type fakeSource struct {
	name        string
	enabled     bool
	items       []int
	searchErr   error
	seen        map[int]bool
	seenErrAt   int
	handleErrAt int
	log         *[]string
}

func (f *fakeSource) Name() string  { return f.name }
func (f *fakeSource) Enabled() bool { return f.enabled }

func (f *fakeSource) Search(context.Context) ([]int, error) {
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	return f.items, nil
}

func (f *fakeSource) Seen(_ context.Context, item int) (bool, error) {
	if f.seenErrAt == item {
		return false, errors.New("seen store down")
	}
	return f.seen[item], nil
}

func (f *fakeSource) Handle(_ context.Context, item int) error {
	if f.handleErrAt == item {
		return fmt.Errorf("handle %d down", item)
	}
	*f.log = append(*f.log, fmt.Sprintf("%s:%d", f.name, item))
	return nil
}

func TestPollerSerialAndIsolation(t *testing.T) {
	var log []string
	a := &fakeSource{name: "a", enabled: true, items: []int{1, 2, 3}, seen: map[int]bool{2: true}, log: &log}
	b := &fakeSource{name: "b", enabled: false, items: []int{9}, log: &log}
	c := &fakeSource{name: "c", enabled: true, searchErr: errors.New("jira down"), log: &log}
	d := &fakeSource{name: "d", enabled: true, items: []int{1, 2}, seenErrAt: 1, log: &log}
	e := &fakeSource{name: "e", enabled: true, items: []int{1, 2}, handleErrAt: 1, log: &log}

	rep := NewPoller[int]().Poll(context.Background(), []Source[int]{a, b, c, d, e})
	if got := strings.Join(log, ","); got != "a:1,a:3,d:2,e:2" {
		t.Fatalf("处理顺序/隔离错误: %s", got)
	}
	if rep.Sources != 5 || rep.DisabledSources != 1 {
		t.Fatalf("report=%+v", rep)
	}
	if rep.Searched != 3+2+2 {
		t.Fatalf("Searched=%d", rep.Searched)
	}
	if rep.Duplicates != 1 {
		t.Fatalf("Duplicates=%d", rep.Duplicates)
	}
	if rep.Handled != 4 {
		t.Fatalf("Handled=%d", rep.Handled)
	}
	if len(rep.Errors) != 3 {
		t.Fatalf("errors=%+v", rep.Errors)
	}
	var phases []string
	for _, pe := range rep.Errors {
		phases = append(phases, pe.Source+":"+pe.Phase)
	}
	if strings.Join(phases, ",") != "c:search,d:seen,e:handle" {
		t.Fatalf("phases=%v", phases)
	}
	if err := rep.Err(); err == nil || !strings.Contains(err.Error(), "jira down") {
		t.Fatalf("Err()=%v", err)
	}
	if !strings.Contains(rep.String(), "handled=4") {
		t.Fatalf("String()=%s", rep.String())
	}
}

func TestPollerContextCanceled(t *testing.T) {
	var log []string
	a := &fakeSource{name: "a", enabled: true, items: []int{1}, log: &log}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rep := NewPoller[int]().Poll(ctx, []Source[int]{a})
	if len(rep.Errors) != 1 || rep.Errors[0].Phase != "context" || !errors.Is(rep.Errors[0], context.Canceled) {
		t.Fatalf("report=%+v", rep)
	}
	if len(log) != 0 {
		t.Fatalf("取消后不应处理: %v", log)
	}
}

func TestPollerEmpty(t *testing.T) {
	rep := NewPoller[string]().Poll(context.Background(), nil)
	if rep.Sources != 0 || rep.Err() != nil || rep.String() == "" {
		t.Fatalf("report=%+v", rep)
	}
}

func TestPollerNilSource(t *testing.T) {
	rep := NewPoller[int]().Poll(context.Background(), []Source[int]{nil})
	if rep.Sources != 1 || len(rep.Errors) != 0 {
		t.Fatalf("report=%+v", rep)
	}
}
