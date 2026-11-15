package gdpr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)

// fakeTombstone 记录调用次数并按配置返回幂等命中/错误。
type fakeTombstone struct {
	calls   int
	subject string
	already bool
	err     error
}

func (f *fakeTombstone) AppendErasedUser(_ context.Context, subject string) (bool, error) {
	f.calls++
	f.subject = subject
	if f.err != nil {
		return false, f.err
	}
	return f.already, nil
}

func noopTombstone() *fakeTombstone { return &fakeTombstone{} }

func fixedClock() func() time.Time { return func() time.Time { return testNow } }

// TestNewRegistryRejectsBadConfig 注册表 fail-closed：空表、重复表、零/未知
// 策略、Exempt 混用、缺闭包、缺墓碑、坏分块大小、坏 Option 全部构造期拒绝。
func TestNewRegistryRejectsBadConfig(t *testing.T) {
	collect := func(context.Context, string, string) ([]Record, error) { return nil, nil }
	del := func(context.Context, string, string, int) (int, error) { return 0, nil }
	anon := func(context.Context, string, string, string) (int, error) { return 0, nil }

	validExport := Entry{Table: "t", OwnerColumn: "owner", Policies: PolicyExport, Collector: collect}
	validErase := Entry{Table: "t", OwnerColumn: "owner", Policies: PolicyErase, Deleter: del}
	validAnonymize := Entry{Table: "t", OwnerColumn: "owner", Policies: PolicyAnonymize, Anonymizer: anon}
	validExempt := Entry{Table: "t", Policies: PolicyExempt}

	cases := []struct {
		name    string
		entries []Entry
		opts    []Option
		want    error
	}{
		{"空注册表", nil, nil, ErrEmptyRegistry},
		{"缺表名", []Entry{{OwnerColumn: "owner", Policies: PolicyExport, Collector: collect}}, nil, ErrBadEntry},
		{"重复表", []Entry{validExport, validExport}, nil, ErrDuplicateTable},
		{"零策略", []Entry{{Table: "t", OwnerColumn: "owner"}}, nil, ErrBadPolicy},
		{"未知策略位", []Entry{{Table: "t", OwnerColumn: "owner", Policies: Policy(1 << 7)}}, nil, ErrBadPolicy},
		{"Exempt 混用", []Entry{{Table: "t", Policies: PolicyExempt | PolicyExport, Collector: collect}}, nil, ErrBadPolicy},
		{"非豁免缺归属列", []Entry{{Table: "t", Policies: PolicyExport, Collector: collect}}, nil, ErrBadEntry},
		{"导出缺 Collector", []Entry{{Table: "t", OwnerColumn: "owner", Policies: PolicyExport}}, nil, ErrMissingCollector},
		{"删除缺 Deleter", []Entry{{Table: "t", OwnerColumn: "owner", Policies: PolicyErase}}, []Option{WithTombstone(noopTombstone())}, ErrMissingDeleter},
		{"匿名化缺 Anonymizer", []Entry{{Table: "t", OwnerColumn: "owner", Policies: PolicyAnonymize}}, []Option{WithTombstone(noopTombstone())}, ErrMissingAnonymizer},
		{"删除缺墓碑", []Entry{validErase}, nil, ErrNoTombstone},
		{"匿名化缺墓碑", []Entry{validAnonymize}, nil, ErrNoTombstone},
		{"坏分块大小 0", []Entry{validErase}, []Option{WithTombstone(noopTombstone()), WithChunkSize(0)}, ErrBadChunkSize},
		{"坏分块大小负数", []Entry{validErase}, []Option{WithTombstone(noopTombstone()), WithChunkSize(-1)}, ErrBadChunkSize},
		{"nil Redactor", []Entry{validExport}, []Option{WithRedactor(nil)}, ErrNoRedactor},
		{"nil 墓碑", []Entry{validExport}, []Option{WithTombstone(nil)}, ErrNoTombstone},
		{"nil 匿名名", []Entry{validAnonymize}, []Option{WithTombstone(noopTombstone()), WithAnonymizeName(nil)}, ErrBadReplacement},
		{"nil 时钟", []Entry{validExport}, []Option{WithClock(nil)}, errors.New("时钟")},
		{"nil Option", []Entry{validExport}, []Option{nil}, errors.New("Option 为 nil")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewRegistry(c.entries, c.opts...)
			if err == nil {
				t.Fatal("应构造失败")
			}
			if c.want != nil && !errors.Is(err, c.want) {
				// 文本型哨兵（nil 时钟/Option）按子串兜底判定。
				if !strings.Contains(err.Error(), c.want.Error()) {
					t.Fatalf("错误 = %v，应命中 %v", err, c.want)
				}
			}
		})
	}

	// 合法形态：仅导出、仅豁免、导出+匿名化均可构造。
	if _, err := NewRegistry([]Entry{validExport}); err != nil {
		t.Fatalf("仅导出应可构造: %v", err)
	}
	if _, err := NewRegistry([]Entry{validExempt}); err != nil {
		t.Fatalf("仅豁免应可构造: %v", err)
	}
	if _, err := NewRegistry([]Entry{validAnonymize}, WithTombstone(noopTombstone())); err != nil {
		t.Fatalf("匿名化+墓碑应可构造: %v", err)
	}
}

// TestExportUserData 导出闭环：注册表遍历、Redactor 逐层脱敏、Exempt 显式
// 列出、原始记录不被修改、回执时间可注入。
func TestExportUserData(t *testing.T) {
	users := []Record{{
		"id":            1,
		"username":      "alice",
		"password_hash": "argon2id$...",
		"profile": map[string]any{
			"email":     "alice@example.com",
			"api_token": "tok-123",
		},
		"labels": map[string]string{"team": "ops", "session_secret": "s"},
		"roles":  []any{"admin", map[string]any{"name": "ops", "credential_id": "c1"}},
	}}
	events := []Record{
		{"id": "e1", "detail": "ok"},
		{"id": "e2", "detail": "ok"},
	}

	reg, err := NewRegistry([]Entry{
		{
			Table: "users", OwnerColumn: "username", Policies: PolicyExport | PolicyAnonymize,
			Collector: func(context.Context, string, string) ([]Record, error) { return users, nil },
			Anonymizer: func(context.Context, string, string, string) (int, error) {
				return 1, nil
			},
		},
		{
			Table: "events", OwnerColumn: "actor", Policies: PolicyExport,
			Collector: func(context.Context, string, string) ([]Record, error) { return events, nil },
		},
		{Table: "audit_chain", Policies: PolicyExempt, Description: "审计追溯不指向真人"},
	}, WithTombstone(noopTombstone()), WithClock(fixedClock()))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	got, err := reg.ExportUserData(context.Background(), "alice")
	if err != nil {
		t.Fatalf("ExportUserData: %v", err)
	}
	if !got.GeneratedAt.Equal(testNow) {
		t.Fatalf("GeneratedAt = %v，应为 %v", got.GeneratedAt, testNow)
	}
	if len(got.Tables) != 2 {
		t.Fatalf("导出表数 = %d，应为 2（Exempt 不采集）", len(got.Tables))
	}
	first := got.Tables[0]
	if first.Table != "users" || first.OwnerColumn != "username" || first.Count != 1 {
		t.Fatalf("users 表回执失真: %+v", first)
	}
	row := first.Records[0]
	for _, key := range []string{"password_hash", "api_token", "session_secret", "credential_id"} {
		if _, exists := findKey(row, key); exists {
			t.Fatalf("敏感字段 %q 未剔除: %+v", key, row)
		}
	}
	if row["username"] != "alice" || row["id"] != 1 {
		t.Fatalf("普通字段被误删: %+v", row)
	}
	profile, ok := row["profile"].(Record)
	if !ok || profile["email"] != "alice@example.com" {
		t.Fatalf("嵌套普通字段失真: %+v", row["profile"])
	}
	labels, ok := row["labels"].(Record)
	if !ok || labels["team"] != "ops" {
		t.Fatalf("map[string]string 脱敏形态失真: %+v", row["labels"])
	}
	roles, ok := row["roles"].([]any)
	if !ok || len(roles) != 2 {
		t.Fatalf("slice 形态失真: %+v", row["roles"])
	}
	if _, exists := findKey(roles[1].(Record), "credential_id"); exists {
		t.Fatalf("slice 内嵌敏感字段未剔除: %+v", roles[1])
	}
	if len(got.Exempt) != 1 || got.Exempt[0] != "audit_chain" {
		t.Fatalf("Exempt = %v，应显式列出 audit_chain", got.Exempt)
	}

	// 原始记录不被脱敏器修改。
	if users[0]["password_hash"] != "argon2id$..." {
		t.Fatal("Redactor 不得修改入参记录")
	}

	// JSON 可编码（回执直接给数据主体/审计面）。
	if _, err := json.Marshal(got); err != nil {
		t.Fatalf("导出回执应可 JSON 编码: %v", err)
	}
}

// findKey 递归查找字段名（验证敏感字段在任何嵌套层都不存在）。
func findKey(v any, key string) (any, bool) {
	switch x := v.(type) {
	case Record:
		if got, ok := x[key]; ok {
			return got, true
		}
		for _, child := range x {
			if got, ok := findKey(child, key); ok {
				return got, true
			}
		}
	case map[string]any:
		return findKey(Record(x), key)
	case []any:
		for _, child := range x {
			if got, ok := findKey(child, key); ok {
				return got, true
			}
		}
	}
	return nil, false
}

// TestExportFailClosed 导出失败面：空主体、空导出面、采集失败、脱敏失败。
func TestExportFailClosed(t *testing.T) {
	empty := func(context.Context, string, string) ([]Record, error) { return nil, nil }
	deleteOnly := func(context.Context, string, string, int) (int, error) { return 0, nil }

	noCollect := func(context.Context, string, string) ([]Record, error) {
		return nil, errors.New("db down")
	}
	regCollectErr, err := NewRegistry([]Entry{
		{Table: "t", OwnerColumn: "owner", Policies: PolicyExport, Collector: noCollect},
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	regUnsupported, err := NewRegistry([]Entry{
		{Table: "t", OwnerColumn: "owner", Policies: PolicyExport, Collector: func(context.Context, string, string) ([]Record, error) {
			return []Record{{"id": 1, "blob": []byte("secret")}}, nil
		}},
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	regNoExport, err := NewRegistry([]Entry{
		{Table: "t", OwnerColumn: "owner", Policies: PolicyErase, Deleter: deleteOnly},
		{Table: "x", Policies: PolicyExempt},
	}, WithTombstone(noopTombstone()))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	regEmptyCollect, err := NewRegistry([]Entry{
		{Table: "t", OwnerColumn: "owner", Policies: PolicyExport, Collector: empty},
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	cases := []struct {
		name string
		reg  *Registry
		subj string
		want error
	}{
		{"空主体", regCollectErr, "  ", ErrNoSubject},
		{"无导出项", regNoExport, "alice", ErrNoExporters},
		{"采集失败", regCollectErr, "alice", ErrCollect},
		{"值类型不可脱敏", regUnsupported, "alice", ErrRedact},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := c.reg.ExportUserData(context.Background(), c.subj)
			if !errors.Is(err, c.want) {
				t.Fatalf("错误 = %v，应 %v", err, c.want)
			}
			if got.Subject != c.subj {
				t.Fatalf("失败回执应带主体: %+v", got)
			}
		})
	}
	if _, err := regUnsupported.ExportUserData(context.Background(), "alice"); !errors.Is(err, ErrUnsupportedValue) {
		t.Fatalf("应可判 ErrUnsupportedValue，got %v", err)
	}

	// 空采集结果是合法成功（表已登记、确实没有该主体数据）。
	got, err := regEmptyCollect.ExportUserData(context.Background(), "alice")
	if err != nil {
		t.Fatalf("空采集应成功: %v", err)
	}
	if len(got.Tables) != 1 || got.Tables[0].Count != 0 {
		t.Fatalf("空采集回执应含该表: %+v", got)
	}

	var nilReg *Registry
	if _, err := nilReg.ExportUserData(context.Background(), "alice"); !errors.Is(err, ErrEmptyRegistry) {
		t.Fatalf("nil 注册表应 ErrEmptyRegistry，got %v", err)
	}
}

// TestEraseUserData 删除闭环：分块 400/400/150、匿名化 erased-<id>、Exempt
// 列名、墓碑只在全成功后追加、幂等命中如实回执。
func TestEraseUserData(t *testing.T) {
	var (
		limits      []int
		anonSubject string
		anonReplace string
		remaining   = 950
	)
	tomb := noopTombstone()
	reg, err := NewRegistry([]Entry{
		{
			Table: "sessions", OwnerColumn: "creator", Policies: PolicyErase,
			Deleter: func(_ context.Context, ownerColumn, subject string, limit int) (int, error) {
				if ownerColumn != "creator" || subject != "alice" {
					t.Fatalf("归属键传参失真: %s=%s", ownerColumn, subject)
				}
				limits = append(limits, limit)
				n := limit
				if remaining < n {
					n = remaining
				}
				remaining -= n
				return n, nil
			},
		},
		{
			Table: "users", OwnerColumn: "username", Policies: PolicyAnonymize,
			Anonymizer: func(_ context.Context, ownerColumn, subject, replacement string) (int, error) {
				anonSubject, anonReplace = subject, replacement
				return 1, nil
			},
		},
		{Table: "audit_chain", Policies: PolicyExempt},
	}, WithTombstone(tomb), WithClock(fixedClock()))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	got, err := reg.EraseUserData(context.Background(), "alice")
	if err != nil {
		t.Fatalf("EraseUserData: %v", err)
	}
	wantLimits := []int{400, 400, 400}
	if fmt.Sprint(limits) != fmt.Sprint(wantLimits) {
		t.Fatalf("分块调用 = %v，应为 %v（400+400+150）", limits, wantLimits)
	}
	// 950 = 400+400+150，第三次余数小于块大小即收口。
	if got.TotalDeleted != 950 {
		t.Fatalf("TotalDeleted = %d，应为 950", got.TotalDeleted)
	}
	if got.TotalAnonymized != 1 {
		t.Fatalf("TotalAnonymized = %d，应为 1", got.TotalAnonymized)
	}
	if anonSubject != "alice" || anonReplace != "erased-alice" {
		t.Fatalf("匿名化传参失真: %q -> %q", anonSubject, anonReplace)
	}
	if len(got.Tables) != 2 {
		t.Fatalf("回执表数 = %d，应为 2", len(got.Tables))
	}
	if got.Tables[0].Table != "sessions" || got.Tables[0].Deleted != 950 {
		t.Fatalf("sessions 回执失真: %+v", got.Tables[0])
	}
	if got.Tables[1].Table != "users" || got.Tables[1].Anonymized != 1 {
		t.Fatalf("users 回执失真: %+v", got.Tables[1])
	}
	if len(got.Exempt) != 1 || got.Exempt[0] != "audit_chain" {
		t.Fatalf("Exempt = %v", got.Exempt)
	}
	if !got.Tombstone.Requested || !got.Tombstone.Appended || got.Tombstone.Already {
		t.Fatalf("墓碑回执失真: %+v", got.Tombstone)
	}
	if tomb.calls != 1 || tomb.subject != "alice" {
		t.Fatalf("墓碑应追加一次: calls=%d subject=%q", tomb.calls, tomb.subject)
	}
	if !got.StartedAt.Equal(testNow) || !got.FinishedAt.Equal(testNow) {
		t.Fatalf("回执时间未走注入时钟: %+v", got)
	}

	// 幂等命中：already=true，回执不声称新追加。
	tomb.already = true
	again, err := reg.EraseUserData(context.Background(), "alice")
	if err != nil {
		t.Fatalf("幂等删除应成功: %v", err)
	}
	if !again.Tombstone.Already || again.Tombstone.Appended {
		t.Fatalf("幂等回执失真: %+v", again.Tombstone)
	}
}

// TestEraseFailClosed 删除失败面：分块中途失败、匿名化失败、墓碑失败、
// 坏替换值、空主体、无删除项——全部带已执行部分 + 错误，墓碑不追加。
func TestEraseFailClosed(t *testing.T) {
	delOK := func(context.Context, string, string, int) (int, error) { return 0, nil }
	anonOK := func(context.Context, string, string, string) (int, error) { return 1, nil }

	boom := errors.New("db down")
	var failAfterOneCalls int
	delFailAfterOne := func(_ context.Context, _, _ string, _ int) (int, error) {
		failAfterOneCalls++
		if failAfterOneCalls == 1 {
			return 400, nil
		}
		return 0, boom
	}
	// 第一次返回满块，第二次失败：验证已删部分保留在回执。
	var calls int
	delFailSecond := func(_ context.Context, _, _ string, _ int) (int, error) {
		calls++
		if calls == 1 {
			return 400, nil
		}
		return 0, boom
	}
	anonFail := func(context.Context, string, string, string) (int, error) { return 0, boom }

	regChunkFail, err := NewRegistry([]Entry{
		{Table: "events", OwnerColumn: "creator", Policies: PolicyErase, Deleter: delFailAfterOne},
		{Table: "sessions", OwnerColumn: "creator", Policies: PolicyErase, Deleter: delFailSecond},
	}, WithTombstone(noopTombstone()))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	regAnonFail, err := NewRegistry([]Entry{
		{Table: "users", OwnerColumn: "username", Policies: PolicyAnonymize, Anonymizer: anonFail},
	}, WithTombstone(noopTombstone()))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	regBadReplace, err := NewRegistry([]Entry{
		{Table: "users", OwnerColumn: "username", Policies: PolicyAnonymize, Anonymizer: anonOK},
	}, WithTombstone(noopTombstone()), WithAnonymizeName(func(string) string { return "" }))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	regSameReplace, err := NewRegistry([]Entry{
		{Table: "users", OwnerColumn: "username", Policies: PolicyAnonymize, Anonymizer: anonOK},
	}, WithTombstone(noopTombstone()), WithAnonymizeName(func(s string) string { return s }))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	tombErr := noopTombstone()
	tombErr.err = boom
	regTombFail, err := NewRegistry([]Entry{
		{Table: "t", OwnerColumn: "owner", Policies: PolicyErase, Deleter: delOK},
	}, WithTombstone(tombErr))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	regNoErase, err := NewRegistry([]Entry{
		{Table: "t", OwnerColumn: "owner", Policies: PolicyExport, Collector: func(context.Context, string, string) ([]Record, error) {
			return nil, nil
		}},
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	cases := []struct {
		name      string
		reg       *Registry
		subject   string
		want      error
		wantTomb  bool
		wantTotal int
	}{
		{"空主体", regAnonFail, " ", ErrNoSubject, false, 0},
		{"无删除项", regNoErase, "alice", ErrNoErasers, false, 0},
		{"分块失败保留已删", regChunkFail, "alice", ErrErase, false, 400},
		{"匿名化失败", regAnonFail, "alice", ErrAnonymize, false, 0},
		{"坏替换值空", regBadReplace, "alice", ErrBadReplacement, false, 0},
		{"坏替换值同名", regSameReplace, "alice", ErrBadReplacement, false, 0},
		{"墓碑失败", regTombFail, "alice", ErrTombstone, true, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := c.reg.EraseUserData(context.Background(), c.subject)
			if !errors.Is(err, c.want) {
				t.Fatalf("错误 = %v，应 %v", err, c.want)
			}
			if got.Tombstone.Requested != c.wantTomb {
				t.Fatalf("Tombstone.Requested = %v，应 %v", got.Tombstone.Requested, c.wantTomb)
			}
			if got.Tombstone.Appended || got.Tombstone.Already {
				t.Fatalf("失败回执不得声称墓碑已写: %+v", got.Tombstone)
			}
			if c.wantTotal != 0 && got.TotalDeleted != c.wantTotal {
				t.Fatalf("已执行部分丢失: TotalDeleted=%d，应 %d", got.TotalDeleted, c.wantTotal)
			}
		})
	}

	// 分块失败时墓碑调用次数为 0。
	tomb := noopTombstone()
	reg, err := NewRegistry([]Entry{
		{Table: "t", OwnerColumn: "owner", Policies: PolicyErase, Deleter: delFailSecond},
	}, WithTombstone(tomb))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if _, err := reg.EraseUserData(context.Background(), "alice"); !errors.Is(err, ErrErase) {
		t.Fatalf("应 ErrErase，got %v", err)
	}
	if tomb.calls != 0 {
		t.Fatalf("失败路径不应追加墓碑，got %d 次", tomb.calls)
	}
}

// TestEraseInChunks 分块原语边界：整块/余数/空表/条数越界/闭包错误/ctx 取消。
func TestEraseInChunks(t *testing.T) {
	t.Run("坏分块大小", func(t *testing.T) {
		if _, err := EraseInChunks(context.Background(), 0, func(context.Context, int) (int, error) {
			return 0, nil
		}); !errors.Is(err, ErrBadChunkSize) {
			t.Fatalf("应 ErrBadChunkSize，got %v", err)
		}
	})
	t.Run("nil 删除闭包", func(t *testing.T) {
		if _, err := EraseInChunks(context.Background(), 400, nil); !errors.Is(err, ErrMissingDeleter) {
			t.Fatalf("应 ErrMissingDeleter，got %v", err)
		}
	})
	t.Run("整块与余数", func(t *testing.T) {
		remaining := 950
		var limits []int
		total, err := EraseInChunks(context.Background(), 400, func(_ context.Context, limit int) (int, error) {
			limits = append(limits, limit)
			n := limit
			if remaining < n {
				n = remaining
			}
			remaining -= n
			return n, nil
		})
		if err != nil || total != 950 {
			t.Fatalf("total=%d err=%v，应 950/nil", total, err)
		}
		if fmt.Sprint(limits) != "[400 400 400]" {
			t.Fatalf("调用序列 = %v", limits)
		}
	})
	t.Run("精确整百多一次探测", func(t *testing.T) {
		remaining := 800
		calls := 0
		total, err := EraseInChunks(context.Background(), 400, func(_ context.Context, limit int) (int, error) {
			calls++
			n := limit
			if remaining < n {
				n = remaining
			}
			remaining -= n
			return n, nil
		})
		if err != nil || total != 800 || calls != 3 {
			t.Fatalf("total=%d calls=%d err=%v，应 800/3/nil", total, calls, err)
		}
	})
	t.Run("空表", func(t *testing.T) {
		total, err := EraseInChunks(context.Background(), 400, func(context.Context, int) (int, error) {
			return 0, nil
		})
		if err != nil || total != 0 {
			t.Fatalf("空表应 0/nil，got %d/%v", total, err)
		}
	})
	t.Run("条数越界", func(t *testing.T) {
		if _, err := EraseInChunks(context.Background(), 400, func(context.Context, int) (int, error) {
			return 401, nil
		}); !errors.Is(err, ErrBadChunkCount) {
			t.Fatalf("应 ErrBadChunkCount，got %v", err)
		}
		if _, err := EraseInChunks(context.Background(), 400, func(context.Context, int) (int, error) {
			return -1, nil
		}); !errors.Is(err, ErrBadChunkCount) {
			t.Fatalf("负数应 ErrBadChunkCount，got %v", err)
		}
	})
	t.Run("闭包错误保留已删", func(t *testing.T) {
		boom := errors.New("boom")
		calls := 0
		total, err := EraseInChunks(context.Background(), 400, func(context.Context, int) (int, error) {
			calls++
			if calls == 1 {
				return 400, nil
			}
			return 0, boom
		})
		if !errors.Is(err, boom) || total != 400 {
			t.Fatalf("应 400/boom，got %d/%v", total, err)
		}
	})
	t.Run("ctx 取消", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		called := false
		_, err := EraseInChunks(ctx, 400, func(context.Context, int) (int, error) {
			called = true
			return 0, nil
		})
		if !errors.Is(err, context.Canceled) || called {
			t.Fatalf("取消后不应调用闭包: called=%v err=%v", called, err)
		}
	})
}

// TestPolicyString 策略组合的人类可读形态（日志排障用）。
func TestPolicyString(t *testing.T) {
	cases := map[Policy]string{
		0:                             "none",
		PolicyExport:                  "export",
		PolicyErase | PolicyAnonymize: "erase|anonymize",
		PolicyExempt:                  "exempt",
		Policy(1 << 7):                "unknown(0x80)",
	}
	for p, want := range cases {
		if got := p.String(); got != want {
			t.Fatalf("Policy(%d).String() = %q，应 %q", p, got, want)
		}
	}
}
