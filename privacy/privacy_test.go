package privacy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

type orderLog struct {
	mu      sync.Mutex
	entries []string
}

func (l *orderLog) add(s string) {
	l.mu.Lock()
	l.entries = append(l.entries, s)
	l.mu.Unlock()
}

func (l *orderLog) list() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.entries))
	copy(out, l.entries)
	return out
}

func (l *orderLog) reset() {
	l.mu.Lock()
	l.entries = nil
	l.mu.Unlock()
}

type memTombstones struct {
	mu    sync.Mutex
	names []string
	saves int
	log   *orderLog
	err   error
}

func (m *memTombstones) Load(context.Context) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return nil, m.err
	}
	out := make([]string, len(m.names))
	copy(out, m.names)
	return out, nil
}

func (m *memTombstones) Save(_ context.Context, names []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.names = append([]string(nil), names...)
	m.saves++
	if m.log != nil {
		m.log.add("tombstone")
	}
	return nil
}

func mustRegistry(t *testing.T, tables ...Table) *Registry {
	t.Helper()
	r := NewRegistry()
	for _, tb := range tables {
		if err := r.Register(tb); err != nil {
			t.Fatalf("Register(%s): %v", tb.Name, err)
		}
	}
	return r
}

func TestRegistryValidation(t *testing.T) {
	collect := func(context.Context, string) (any, error) { return nil, nil }
	erase := func(context.Context, string, int) (int64, error) { return 0, nil }
	anon := func(context.Context, string) (string, error) { return "", nil }

	valid := Table{Name: "t", OwnerColumn: "creator", Policy: Export | Erase, Collect: collect, Erase: erase}
	r := NewRegistry()
	if err := r.Register(valid); err != nil {
		t.Fatalf("valid register: %v", err)
	}
	if err := r.Register(valid); !errors.Is(err, ErrDuplicateTable) {
		t.Errorf("duplicate err = %v", err)
	}
	if got := r.Names(); len(got) != 1 || got[0] != "t" {
		t.Errorf("Names = %v", got)
	}

	cases := map[string]Table{
		"empty name":             {OwnerColumn: "creator", Policy: Export, Collect: collect},
		"reserved name":          {Name: KeySubject, OwnerColumn: "creator", Policy: Export, Collect: collect},
		"missing owner column":   {Name: "x", Policy: Export, Collect: collect},
		"zero policy":            {Name: "x", OwnerColumn: "creator"},
		"unknown policy bit":     {Name: "x", OwnerColumn: "creator", Policy: Policy(1 << 7)},
		"exempt combined":        {Name: "x", OwnerColumn: "creator", Policy: Exempt | Export, Reason: "r"},
		"exempt without reason":  {Name: "x", OwnerColumn: "creator", Policy: Exempt},
		"exempt with hook":       {Name: "x", OwnerColumn: "creator", Policy: Exempt, Reason: "r", Erase: erase},
		"export without collect": {Name: "x", OwnerColumn: "creator", Policy: Export},
		"erase without closure":  {Name: "x", OwnerColumn: "creator", Policy: Erase},
		"anonymize without hook": {Name: "x", OwnerColumn: "creator", Policy: Anonymize},
		"omit without export":    {Name: "x", OwnerColumn: "creator", Policy: Erase, Omit: []string{"pwd_hash"}, Erase: erase},
	}
	for name, tb := range cases {
		t.Run(name, func(t *testing.T) {
			if err := NewRegistry().Register(tb); !errors.Is(err, ErrInvalidTable) {
				t.Errorf("err = %v, want ErrInvalidTable", err)
			}
		})
	}

	// 合法组合。
	for _, tb := range []Table{
		{Name: "a", OwnerColumn: "creator", Policy: Export, Collect: collect},
		{Name: "b", OwnerColumn: "creator", Policy: Erase, Erase: erase},
		{Name: "c", OwnerColumn: "creator", Policy: Anonymize, Anonymize: anon},
		{Name: "d", OwnerColumn: "creator", Policy: Exempt, Reason: "审计链不可挖行"},
		{Name: "e", OwnerColumn: "creator", Policy: Export | Erase | Anonymize, Collect: collect, Erase: erase, Anonymize: anon},
	} {
		if err := NewRegistry().Register(tb); err != nil {
			t.Errorf("Register(%s): %v", tb.Name, err)
		}
	}
}

func TestPolicyString(t *testing.T) {
	tests := map[Policy]string{
		0:                  "none",
		Export:             "export",
		Export | Erase:     "export|erase",
		Exempt:             "exempt",
		Anonymize | Export: "export|anonymize",
	}
	for p, want := range tests {
		if got := p.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", p, got, want)
		}
	}
	if Exempt.Has(Export) || !(Export | Erase).Has(Erase) {
		t.Error("Policy.Has 语义错误")
	}
}

func fixedNow() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }

func newExporter(t *testing.T, tables ...Table) *SubjectExporter {
	t.Helper()
	exp, err := NewSubjectExporter(ExporterConfig{Registry: mustRegistry(t, tables...), Now: fixedNow})
	if err != nil {
		t.Fatalf("NewSubjectExporter: %v", err)
	}
	return exp
}

func TestExportTraversesRegistry(t *testing.T) {
	exp := newExporter(t,
		Table{
			Name: "user", OwnerColumn: "id", Policy: Export | Anonymize,
			Omit: []string{"pwd_hash", "payload_enc"},
			Collect: func(context.Context, string) (any, error) {
				return []map[string]any{{
					"username": "alice", "pwd_hash": "bcrypt-hash", "payload_enc": "ciphertext",
				}}, nil
			},
			Anonymize: func(context.Context, string) (string, error) { return "erased-9", nil },
		},
		Table{
			Name: "sessions", OwnerColumn: "creator", Policy: Export | Erase,
			Collect: func(_ context.Context, subject string) (any, error) {
				if subject != "alice" {
					t.Errorf("collect subject = %q", subject)
				}
				return []map[string]any{{"session_id": "s1"}}, nil
			},
			Erase: func(context.Context, string, int) (int64, error) { return 1, nil },
		},
		Table{Name: "audit_log", OwnerColumn: "actor", Policy: Exempt, Reason: "审计链哈希衔接不可挖行"},
		Table{Name: "erase_only", OwnerColumn: "creator", Policy: Erase, Erase: func(context.Context, string, int) (int64, error) { return 0, nil }},
		Table{Name: "anon_only", OwnerColumn: "id", Policy: Anonymize, Anonymize: func(context.Context, string) (string, error) { return "", nil }},
	)

	bundle, err := exp.Export(context.Background(), "alice")
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if bundle[KeySubject] != "alice" || bundle[KeyExportedAt] != "2026-01-02T03:04:05Z" {
		t.Errorf("元数据 = %v / %v", bundle[KeySubject], bundle[KeyExportedAt])
	}
	users, ok := bundle["user"].([]any)
	if !ok || len(users) != 1 {
		t.Fatalf("user 载荷 = %#v", bundle["user"])
	}
	row, ok := users[0].(map[string]any)
	if !ok {
		t.Fatalf("user[0] = %#v", users[0])
	}
	if _, exists := row["pwd_hash"]; exists {
		t.Error("pwd_hash 未剔除（凭证类数据不属于关于主体的信息）")
	}
	if _, exists := row["payload_enc"]; exists {
		t.Error("payload_enc 未剔除")
	}
	if row["username"] != "alice" {
		t.Errorf("username = %v", row["username"])
	}
	if _, ok := bundle["sessions"]; !ok {
		t.Error("sessions 未导出")
	}
	for _, absent := range []string{"audit_log", "erase_only", "anon_only"} {
		if _, ok := bundle[absent]; ok {
			t.Errorf("%s 不应进导出包", absent)
		}
	}
}

func TestExportOmitTopLevelObject(t *testing.T) {
	exp := newExporter(t, Table{
		Name: "user", OwnerColumn: "id", Policy: Export, Omit: []string{"pwd_hash"},
		Collect: func(context.Context, string) (any, error) {
			return map[string]any{"username": "alice", "pwd_hash": "h"}, nil
		},
	})
	bundle, err := exp.Export(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	row := bundle["user"].(map[string]any)
	if _, ok := row["pwd_hash"]; ok {
		t.Error("pwd_hash 未剔除")
	}
}

func TestExportErrors(t *testing.T) {
	exp := newExporter(t, Table{
		Name: "sessions", OwnerColumn: "creator", Policy: Export,
		Collect: func(context.Context, string) (any, error) { return nil, errors.New("db down") },
	})
	if _, err := exp.Export(context.Background(), "alice"); err == nil || !strings.Contains(err.Error(), "db down") {
		t.Errorf("采集错误未透出: %v", err)
	}
	if _, err := exp.Export(context.Background(), "  "); !errors.Is(err, ErrSubject) {
		t.Errorf("空 subject err = %v", err)
	}
	if _, err := NewSubjectExporter(ExporterConfig{}); !errors.Is(err, ErrNoRegistry) {
		t.Errorf("nil registry err = %v", err)
	}

	// 取消的 ctx：遍历前直接失败。
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := exp.Export(ctx, "alice"); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled ctx err = %v", err)
	}

	// 不可 JSON 序列化的采集结果 → Omit 阶段报错。
	exp2 := newExporter(t, Table{
		Name: "bad", OwnerColumn: "id", Policy: Export, Omit: []string{"x"},
		Collect: func(context.Context, string) (any, error) { return func() {}, nil },
	})
	if _, err := exp2.Export(context.Background(), "alice"); err == nil {
		t.Error("不可序列化载荷未报错")
	}
}

func TestEraseOrderReportAndTombstone(t *testing.T) {
	log := &orderLog{}
	tomb := &memTombstones{log: log}
	reg := mustRegistry(t,
		Table{
			Name: "bq_event", OwnerColumn: "session_id", Policy: Erase,
			Erase: func(context.Context, string, int) (int64, error) {
				log.add("erase:bq_event")
				return 12, nil
			},
		},
		Table{
			Name: "bq_session", OwnerColumn: "creator", Policy: Erase,
			Erase: func(context.Context, string, int) (int64, error) {
				log.add("erase:bq_session")
				return 3, nil
			},
		},
		Table{
			Name: "user", OwnerColumn: "id", Policy: Export | Anonymize,
			Collect: func(context.Context, string) (any, error) { return nil, nil },
			Anonymize: func(_ context.Context, subject string) (string, error) {
				log.add("anonymize:user")
				return "erased-9", nil
			},
		},
		Table{Name: "audit_log", OwnerColumn: "actor", Policy: Exempt, Reason: "审计链"},
		Table{
			Name: "export_only", OwnerColumn: "creator", Policy: Export,
			Collect: func(context.Context, string) (any, error) { return nil, nil },
		},
	)
	eraser, err := NewSubjectEraser(EraserConfig{Registry: reg, Tombstones: tomb})
	if err != nil {
		t.Fatalf("NewSubjectEraser: %v", err)
	}
	report, alias, err := eraser.Erase(context.Background(), "alice")
	if err != nil {
		t.Fatalf("Erase: %v", err)
	}
	if alias != "erased-9" {
		t.Errorf("alias = %q", alias)
	}
	if report["bq_event"] != 12 || report["bq_session"] != 3 || report["user"] != 1 {
		t.Errorf("report = %v", report)
	}
	if report.Total() != 16 {
		t.Errorf("Total = %d", report.Total())
	}
	if _, ok := report["audit_log"]; ok {
		t.Error("Exempt 表进了回执")
	}
	if _, ok := report["export_only"]; ok {
		t.Error("Export-only 表进了删除回执")
	}
	want := []string{"erase:bq_event", "erase:bq_session", "tombstone", "anonymize:user"}
	if got := log.list(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("执行顺序 = %v, want %v", got, want)
	}
	names, _ := tomb.Load(context.Background())
	if len(names) != 1 || names[0] != "alice" {
		t.Errorf("墓碑 = %v", names)
	}

	// 幂等追加：第二次删除不再写墓碑（同名已在名册）。
	log.reset()
	if _, _, err := eraser.Erase(context.Background(), "alice"); err != nil {
		t.Fatalf("second Erase: %v", err)
	}
	for _, entry := range log.list() {
		if entry == "tombstone" {
			t.Error("重复写墓碑")
		}
	}
	if tomb.saves != 1 {
		t.Errorf("Save 次数 = %d, want 1", tomb.saves)
	}
}

func TestEraseWithoutTombstoneStore(t *testing.T) {
	eraser, err := NewSubjectEraser(EraserConfig{Registry: mustRegistry(t, Table{
		Name: "sessions", OwnerColumn: "creator", Policy: Erase,
		Erase: func(context.Context, string, int) (int64, error) { return 2, nil },
	})})
	if err != nil {
		t.Fatal(err)
	}
	report, alias, err := eraser.Erase(context.Background(), "alice")
	if err != nil || alias != "" || report["sessions"] != 2 {
		t.Fatalf("Erase = %v, %q, %v", report, alias, err)
	}
}

func TestEraseErrors(t *testing.T) {
	boom := errors.New("boom")
	eraser, err := NewSubjectEraser(EraserConfig{Registry: mustRegistry(t,
		Table{Name: "sessions", OwnerColumn: "creator", Policy: Erase,
			Erase: func(context.Context, string, int) (int64, error) { return 0, boom }},
		Table{Name: "user", OwnerColumn: "id", Policy: Anonymize,
			Anonymize: func(context.Context, string) (string, error) { return "", boom }},
	)})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := eraser.Erase(context.Background(), "alice"); !errors.Is(err, boom) {
		t.Errorf("erase 错误未透出: %v", err)
	}
	if _, _, err := eraser.Erase(context.Background(), ""); !errors.Is(err, ErrSubject) {
		t.Errorf("空 subject err = %v", err)
	}
	if _, err := NewSubjectEraser(EraserConfig{}); !errors.Is(err, ErrNoRegistry) {
		t.Errorf("nil registry err = %v", err)
	}

	// 匿名化失败也不返回半截回执。
	tomb := &memTombstones{}
	eraser2, _ := NewSubjectEraser(EraserConfig{Registry: mustRegistry(t,
		Table{Name: "sessions", OwnerColumn: "creator", Policy: Erase,
			Erase: func(context.Context, string, int) (int64, error) { return 1, nil }},
		Table{Name: "user", OwnerColumn: "id", Policy: Anonymize,
			Anonymize: func(context.Context, string) (string, error) { return "", boom }},
	), Tombstones: tomb})
	report, alias, err := eraser2.Erase(context.Background(), "alice")
	if !errors.Is(err, boom) || report != nil || alias != "" {
		t.Errorf("匿名化失败返回 = %v, %q, %v", report, alias, err)
	}
}

func TestTombstoneHelpers(t *testing.T) {
	store := &memTombstones{}
	ctx := context.Background()
	if err := AppendTombstone(ctx, store, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := AppendTombstone(ctx, store, "alice"); err != nil {
		t.Fatal(err)
	}
	if store.saves != 1 {
		t.Errorf("重复追加写入 %d 次, want 1", store.saves)
	}
	if err := AppendTombstone(ctx, store, ""); !errors.Is(err, ErrSubject) {
		t.Errorf("空 subject err = %v", err)
	}
	if err := AppendTombstone(ctx, nil, "alice"); !errors.Is(err, ErrNoTombstoneStore) {
		t.Errorf("nil store err = %v", err)
	}

	bad := &memTombstones{err: errors.New("kv down")}
	if err := AppendTombstone(ctx, bad, "alice"); err == nil {
		t.Error("存储错误未透出")
	}
}

func TestChunkDelete(t *testing.T) {
	keys := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	var chunks [][]int
	total, err := ChunkDelete(context.Background(), keys, 3, func(_ context.Context, chunk []int) (int64, error) {
		chunks = append(chunks, append([]int(nil), chunk...))
		return int64(len(chunk)), nil
	})
	if err != nil || total != 10 {
		t.Fatalf("ChunkDelete = %d, %v", total, err)
	}
	want := [][]int{{1, 2, 3}, {4, 5, 6}, {7, 8, 9}, {10}}
	if fmt.Sprint(chunks) != fmt.Sprint(want) {
		t.Errorf("chunks = %v, want %v", chunks, want)
	}

	// batch <= 0 落缺省 400。
	many := make([]int, 450)
	for i := range many {
		many[i] = i
	}
	var sizes []int
	total, err = ChunkDelete(context.Background(), many, 0, func(_ context.Context, chunk []int) (int64, error) {
		sizes = append(sizes, len(chunk))
		return int64(len(chunk)), nil
	})
	if err != nil || total != 450 || fmt.Sprint(sizes) != fmt.Sprint([]int{400, 50}) {
		t.Errorf("default batch = %d, %v, sizes=%v", total, err, sizes)
	}

	// 空表不调闭包。
	called := false
	total, err = ChunkDelete(context.Background(), []int(nil), 10, func(context.Context, []int) (int64, error) {
		called = true
		return 0, nil
	})
	if err != nil || total != 0 || called {
		t.Errorf("empty = %d, %v, called=%v", total, err, called)
	}

	if _, err := ChunkDelete[int](context.Background(), keys, 3, nil); !errors.Is(err, ErrNoDelete) {
		t.Errorf("nil del err = %v", err)
	}
}

func TestChunkDeleteMidwayErrorAndCancel(t *testing.T) {
	boom := errors.New("delete failed")
	calls := 0
	total, err := ChunkDelete(context.Background(), []int{1, 2, 3, 4, 5}, 2, func(_ context.Context, chunk []int) (int64, error) {
		calls++
		if calls == 2 {
			return 1, boom
		}
		return int64(len(chunk)), nil
	})
	if !errors.Is(err, boom) || total != 3 { // 2 + 1（失败批已删的行也计入）
		t.Errorf("midway = %d, %v", total, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	if _, err := ChunkDelete(ctx, []int{1}, 1, func(context.Context, []int) (int64, error) {
		called = true
		return 0, nil
	}); !errors.Is(err, context.Canceled) || called {
		t.Errorf("canceled = %v, called=%v", err, called)
	}
}
