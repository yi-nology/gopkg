package approvalflow

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── 测试替身：内存 Store / Publisher / Notifier ─────────────────────

var errNoRow = errors.New("approvalflow test: 审批单不存在")

type memEvent struct {
	id         uint64
	approvalID string
	createdAt  time.Time
	notified   bool
}

type memStore struct {
	mu     sync.Mutex
	rows   map[string]*Approval
	events []memEvent
	seq    uint64
}

func newMemStore() *memStore {
	return &memStore{rows: map[string]*Approval{}}
}

func cloneApproval(a *Approval) *Approval {
	if a == nil {
		return nil
	}
	c := *a
	c.Plan = append([]byte(nil), a.Plan...)
	c.LLMRiskAssessment = append([]byte(nil), a.LLMRiskAssessment...)
	if a.L4FirstAt != nil {
		v := *a.L4FirstAt
		c.L4FirstAt = &v
	}
	if a.TokenUsedAt != nil {
		v := *a.TokenUsedAt
		c.TokenUsedAt = &v
	}
	if a.DecidedAt != nil {
		v := *a.DecidedAt
		c.DecidedAt = &v
	}
	return &c
}

func (m *memStore) Create(_ context.Context, a *Approval) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.rows[a.ApprovalID]; ok {
		return errors.New("duplicate approval id")
	}
	m.rows[a.ApprovalID] = cloneApproval(a)
	return nil
}

func (m *memStore) Get(_ context.Context, id string) (*Approval, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.rows[id]
	if !ok {
		return nil, errNoRow
	}
	return cloneApproval(a), nil
}

func (m *memStore) Decide(_ context.Context, id string, decision Status, by, note, tokenHash string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.rows[id]
	if !ok {
		return false, errNoRow
	}
	if a.Status != StatusPending {
		return false, nil
	}
	now := time.Now()
	if tokenHash != "" && !a.ExpiresAt.After(now) {
		return false, nil
	}
	a.Status = decision
	a.DecidedBy = by
	a.DecisionNote = note
	a.DecidedAt = &now
	if tokenHash != "" {
		a.DecideTokenHash = tokenHash
	}
	return true, nil
}

func (m *memStore) CancelPending(_ context.Context, id, by, note string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.rows[id]
	if !ok {
		return false, errNoRow
	}
	if a.Status != StatusPending {
		return false, nil
	}
	now := time.Now()
	a.Status = StatusCancelled
	a.DecidedBy = by
	a.DecisionNote = note
	a.DecidedAt = &now
	return true, nil
}

func (m *memStore) Expire(_ context.Context, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.rows[id]
	if !ok {
		return false, errNoRow
	}
	if a.Status != StatusPending {
		return false, nil
	}
	a.Status = StatusExpired
	return true, nil
}

func (m *memStore) Due(_ context.Context, now time.Time) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ids []string
	for id, a := range m.rows {
		if a.Status == StatusPending && !a.ExpiresAt.After(now) {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func (m *memStore) ConsumeToken(_ context.Context, id, tokenHash string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.rows[id]
	if !ok {
		return false, errNoRow
	}
	if a.Status != StatusApproved || a.DecideTokenHash != tokenHash || a.TokenUsedAt != nil {
		return false, nil
	}
	now := time.Now()
	a.TokenUsedAt = &now
	return true, nil
}

func (m *memStore) MarkL4First(_ context.Context, id string, at time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.rows[id]
	if !ok {
		return false, errNoRow
	}
	if a.Status != StatusPending || a.L4FirstAt != nil {
		return false, nil
	}
	v := at
	a.L4FirstAt = &v
	return true, nil
}

func (m *memStore) UnnotifiedRequests(_ context.Context, since time.Time, limit int) ([]RequestEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []RequestEvent
	for _, ev := range m.events {
		if ev.notified || ev.createdAt.Before(since) {
			continue
		}
		out = append(out, RequestEvent{ID: ev.id, ApprovalID: ev.approvalID})
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (m *memStore) MarkRequestNotified(_ context.Context, eventID uint64, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.events {
		if m.events[i].id == eventID {
			m.events[i].notified = true
			return nil
		}
	}
	return nil
}

// ---- 测试辅助（非接口） ----

func (m *memStore) status(id string) Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	if a, ok := m.rows[id]; ok {
		return a.Status
	}
	return ""
}

func (m *memStore) row(id string) *Approval {
	m.mu.Lock()
	defer m.mu.Unlock()
	return cloneApproval(m.rows[id])
}

func (m *memStore) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.rows)
}

func (m *memStore) mutate(id string, fn func(*Approval)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if a, ok := m.rows[id]; ok {
		fn(a)
	}
}

func (m *memStore) addEvent(approvalID string, createdAt time.Time) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	m.events = append(m.events, memEvent{id: m.seq, approvalID: approvalID, createdAt: createdAt})
	return m.seq
}

func (m *memStore) eventNotified(id uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ev := range m.events {
		if ev.id == id {
			return ev.notified
		}
	}
	return false
}

type capturePublisher struct {
	mu     sync.Mutex
	events []Event
}

func (p *capturePublisher) Publish(_ context.Context, ev Event) {
	p.mu.Lock()
	p.events = append(p.events, ev)
	p.mu.Unlock()
}

func (p *capturePublisher) snapshot() []Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Event(nil), p.events...)
}

type captureNotifier struct {
	mu  sync.Mutex
	got []*Approval
}

func (n *captureNotifier) ApprovalRequested(_ context.Context, a *Approval) {
	n.mu.Lock()
	n.got = append(n.got, cloneApproval(a))
	n.mu.Unlock()
}

func (n *captureNotifier) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.got)
}

// fixture 构造测试服务（默认 1h 审批窗 / 5m 提问窗 / 10ms 轮询）。
func fixture(t *testing.T, cfg Config) (*Service, *memStore, *capturePublisher, *captureNotifier) {
	t.Helper()
	if cfg.Secret == "" {
		cfg.Secret = "test-secret"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = time.Hour
	}
	if cfg.AskTimeout == 0 {
		cfg.AskTimeout = 5 * time.Minute
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 10 * time.Millisecond
	}
	store := newMemStore()
	pub := &capturePublisher{}
	notifier := &captureNotifier{}
	svc, err := New(store, pub, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	svc.WithNotifier(notifier)
	return svc, store, pub, notifier
}

// submit 提审一个普通方案（CreatedBy=alice、risk 可调）。
func submit(t *testing.T, svc *Service, risk int) string {
	t.Helper()
	id, err := svc.Submit(context.Background(), SubmitInput{
		CaseID:      "case-1",
		SessionID:   "sess-1",
		StepID:      "step-1",
		Plan:        []byte(`{"steps":["systemctl restart api"]}`),
		RequestType: "restart",
		RiskLevel:   risk,
		CreatedBy:   "alice",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	return id
}

// ── 构造校验 ────────────────────────────────────────────────────────

func TestNewValidation(t *testing.T) {
	store := newMemStore()
	cases := []struct {
		name    string
		store   Store
		cfg     Config
		wantErr bool
	}{
		{"nil store", nil, Config{Secret: "s"}, true},
		{"空 secret", store, Config{Timeout: time.Hour, AskTimeout: time.Minute}, true},
		{"ask 等于审批窗", store, Config{Secret: "s", Timeout: time.Minute, AskTimeout: time.Minute}, true},
		{"ask 长于审批窗", store, Config{Secret: "s", Timeout: time.Minute, AskTimeout: 2 * time.Minute}, true},
		{"合法", store, Config{Secret: "s", Timeout: time.Hour, AskTimeout: time.Minute}, false},
	}
	for _, c := range cases {
		_, err := New(c.store, nil, c.cfg)
		if c.wantErr && !errors.Is(err, ErrBadConfig) {
			t.Errorf("%s: 应 ErrBadConfig，got %v", c.name, err)
		}
		if !c.wantErr && err != nil {
			t.Errorf("%s: 不应失败，got %v", c.name, err)
		}
	}

	// 缺省档：30m 审批窗、5m 提问窗。
	store2 := newMemStore()
	svc, err := New(store2, nil, Config{Secret: "s"})
	if err != nil {
		t.Fatalf("New(缺省档): %v", err)
	}
	id, err := svc.Submit(context.Background(), SubmitInput{CaseID: "c", Plan: []byte("{}")})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	row := store2.row(id)
	left := time.Until(row.ExpiresAt)
	if left < 29*time.Minute || left > 31*time.Minute {
		t.Fatalf("缺省审批窗应约 30m，剩 %s", left)
	}
}

// ── Submit / AskUserSubmit ──────────────────────────────────────────

func TestSubmitFastTrackAndPlan(t *testing.T) {
	svc, store, _, notifier := fixture(t, Config{
		Timeout: time.Hour,
		FastTrack: &FastTrack{
			Timeout: 5 * time.Minute,
			MaxRisk: 1,
		},
	})

	plan := []byte(`{"steps":["systemctl restart api"]}`)
	id, err := svc.Submit(context.Background(), SubmitInput{
		CaseID: "case-1", SessionID: "sess-1", StepID: "step-1",
		Plan: plan, RequestType: "restart", RiskLevel: 1, CreatedBy: "alice",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	row := store.row(id)
	if !strings.HasPrefix(id, "appr-case-1-") {
		t.Fatalf("approval id 前缀不符: %s", id)
	}
	if row.Status != StatusPending || row.CreatedBy != "alice" || row.RequestType != "restart" {
		t.Fatalf("行字段不符: %+v", row)
	}
	if row.PlanHash != sha256Hex(plan) || len(row.PlanHash) != 64 {
		t.Fatalf("PlanHash 不符: %q", row.PlanHash)
	}
	if string(row.LLMRiskAssessment) != "{}" {
		t.Fatalf("LLM 评估缺省应为 {}，got %s", string(row.LLMRiskAssessment))
	}
	if left := time.Until(row.ExpiresAt); left < 4*time.Minute || left > 6*time.Minute {
		t.Fatalf("risk=1 应走快速通道 5m，剩 %s", left)
	}
	if notifier.count() != 1 {
		t.Fatalf("Submit 应推送一次，got %d", notifier.count())
	}

	// risk=2 不走快速通道（MaxRisk=1）。
	id2, err := svc.Submit(context.Background(), SubmitInput{CaseID: "case-2", Plan: plan, RiskLevel: 2})
	if err != nil {
		t.Fatalf("Submit risk2: %v", err)
	}
	if left := time.Until(store.row(id2).ExpiresAt); left < 59*time.Minute || left > 61*time.Minute {
		t.Fatalf("risk=2 应走默认 1h，剩 %s", left)
	}

	// 空 Plan 落 "{}"；非法 JSON fail-fast 且不落库。
	id3, err := svc.Submit(context.Background(), SubmitInput{CaseID: "case-3"})
	if err != nil {
		t.Fatalf("Submit 空 Plan: %v", err)
	}
	if got := string(store.row(id3).Plan); got != "{}" {
		t.Fatalf("空 Plan 应落 {}，got %q", got)
	}
	before := store.count()
	if _, err := svc.Submit(context.Background(), SubmitInput{CaseID: "case-4", Plan: []byte("{")}); !errors.Is(err, ErrBadPlan) {
		t.Fatalf("非法 Plan 应 ErrBadPlan，got %v", err)
	}
	if store.count() != before {
		t.Fatal("非法 Plan 不应落库")
	}
	if _, err := svc.Submit(context.Background(), SubmitInput{Plan: plan}); !errors.Is(err, ErrBadConfig) {
		t.Fatalf("空 case_id 应 ErrBadConfig，got %v", err)
	}
}

func TestAskUserSubmit(t *testing.T) {
	svc, store, _, notifier := fixture(t, Config{Timeout: time.Hour, AskTimeout: 10 * time.Minute})
	id, err := svc.AskUserSubmit(context.Background(), AskUserInput{
		CaseID: "case-ask", SessionID: "sess-ask", StepID: "step-ask",
		Question: "目标是 A 还是 B？", Options: []string{"A 机", "B 机"}, Assumption: "按 A 继续",
	})
	if err != nil {
		t.Fatalf("AskUserSubmit: %v", err)
	}
	row := store.row(id)
	if !strings.HasPrefix(id, "ask-case-ask-") {
		t.Fatalf("ask id 前缀不符: %s", id)
	}
	if row.RequestType != RequestTypeAskUser || row.Status != StatusPending {
		t.Fatalf("行形态不符: %+v", row)
	}
	if row.RiskLevel != 1 || row.CreatedBy != "" {
		t.Fatalf("ask_user 应 risk=1/created_by 空: %+v", row)
	}
	if left := time.Until(row.ExpiresAt); left < 9*time.Minute || left > 11*time.Minute {
		t.Fatalf("ask 窗口应约 10m，剩 %s", left)
	}
	var prompt askPrompt
	if err := json.Unmarshal(row.Plan, &prompt); err != nil {
		t.Fatalf("提问载荷非法: %v", err)
	}
	if prompt.Kind != RequestTypeAskUser || prompt.Question != "目标是 A 还是 B？" ||
		len(prompt.Options) != 2 || prompt.Assumption != "按 A 继续" {
		t.Fatalf("提问载荷字段不符: %+v", prompt)
	}
	if notifier.count() != 1 {
		t.Fatalf("AskUserSubmit 应推送一次，got %d", notifier.count())
	}
	if _, err := svc.AskUserSubmit(context.Background(), AskUserInput{}); !errors.Is(err, ErrBadConfig) {
		t.Fatalf("空 case_id 应 ErrBadConfig，got %v", err)
	}
}

// ── Decide 守卫链 ──────────────────────────────────────────────────

func TestDecideSeparation(t *testing.T) {
	ctx := context.Background()
	svc, store, _, _ := fixture(t, Config{RequireSeparateApprover: true})

	// 提审人自批 → 拒绝；reject 自拒 → 允许。
	id := submit(t, svc, 2)
	if ok, err := svc.Decide(ctx, id, StatusApproved, "alice", "", ""); ok || !errors.Is(err, ErrSeparation) {
		t.Fatalf("提审人自批应 ErrSeparation: ok=%v err=%v", ok, err)
	}
	if store.status(id) != StatusPending {
		t.Fatal("被拒绝后应保持 pending")
	}
	if ok, err := svc.Decide(ctx, id, StatusRejected, "alice", "", ""); err != nil || !ok {
		t.Fatalf("提审人 reject 应允许: ok=%v err=%v", ok, err)
	}

	// 他人批准 → 放行。
	id2 := submit(t, svc, 2)
	if ok, err := svc.Decide(ctx, id2, StatusApproved, "bob", "", ""); err != nil || !ok {
		t.Fatalf("他人批准应放行: ok=%v err=%v", ok, err)
	}
	if store.row(id2).DecideTokenHash == "" {
		t.Fatal("approved 应落执行凭据哈希")
	}

	// 提审人无身份（鉴权关闭期）→ 分离不生效。
	id3, err := svc.Submit(ctx, SubmitInput{CaseID: "c3", Plan: []byte("{}"), RequestType: "restart"})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := svc.Decide(ctx, id3, StatusApproved, "anyone", "", ""); err != nil || !ok {
		t.Fatalf("无身份提审不触发分离: ok=%v err=%v", ok, err)
	}

	// 开关关闭：自批放行。
	svc2, _, _, _ := fixture(t, Config{RequireSeparateApprover: false})
	id4 := submit(t, svc2, 2)
	if ok, err := svc2.Decide(ctx, id4, StatusApproved, "alice", "", ""); err != nil || !ok {
		t.Fatalf("开关关闭时自批应放行: ok=%v err=%v", ok, err)
	}
}

func TestDecideDenyByDefault(t *testing.T) {
	ctx := context.Background()
	svc, store, pub, _ := fixture(t, Config{})

	// approve 过期单：拒绝 + 惰性收敛 expired + 发过期事件。
	id := submit(t, svc, 2)
	store.mutate(id, func(a *Approval) { a.ExpiresAt = time.Now().Add(-time.Second) })
	if ok, err := svc.Decide(ctx, id, StatusApproved, "bob", "", ""); ok || !errors.Is(err, ErrExpired) {
		t.Fatalf("过期单 approve 应 ErrExpired: ok=%v err=%v", ok, err)
	}
	if store.status(id) != StatusExpired {
		t.Fatalf("拒绝后应收敛 expired，got %s", store.status(id))
	}
	events := pub.snapshot()
	if len(events) != 1 || events[0].Type != EventExpired || events[0].Status != StatusExpired {
		t.Fatalf("应发一次过期事件: %+v", events)
	}

	// reject 过期单：安全方向恒允许，不签 token。
	id2 := submit(t, svc, 2)
	store.mutate(id2, func(a *Approval) { a.ExpiresAt = time.Now().Add(-time.Second) })
	if ok, err := svc.Decide(ctx, id2, StatusRejected, "bob", "人工处置", ""); err != nil || !ok {
		t.Fatalf("过期单 reject 应允许: ok=%v err=%v", ok, err)
	}
	row := store.row(id2)
	if row.Status != StatusRejected || row.DecideTokenHash != "" {
		t.Fatalf("reject 后状态/凭据不符: %+v", row)
	}

	// 策略代批同样 deny-by-default。
	id3 := submit(t, svc, 2)
	store.mutate(id3, func(a *Approval) { a.ExpiresAt = time.Now().Add(-time.Second) })
	if ok, err := svc.DecideSystem(ctx, id3, StatusApproved, "auto"); ok || !errors.Is(err, ErrExpired) {
		t.Fatalf("过期单代批应 ErrExpired: ok=%v err=%v", ok, err)
	}
	if store.status(id3) != StatusExpired {
		t.Fatalf("代批拒绝后应收敛 expired，got %s", store.status(id3))
	}
}

func TestL4DoubleConfirm(t *testing.T) {
	ctx := context.Background()
	svc, store, pub, _ := fixture(t, Config{})
	id, err := svc.Submit(ctx, SubmitInput{
		CaseID: "l4-case", Plan: []byte(`{"steps":["rm -rf /data"]}`),
		RequestType: "delete", RiskLevel: 4, CreatedBy: "alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	phrase := L4Phrase("delete")

	// 无短语/错短语批准 → 拒绝且行不动；错误文本不回显正确短语。
	if ok, err := svc.Decide(ctx, id, StatusApproved, "alice", "", ""); ok || !errors.Is(err, ErrL4Phrase) {
		t.Fatalf("无短语应 ErrL4Phrase: ok=%v err=%v", ok, err)
	}
	_, err = svc.Decide(ctx, id, StatusApproved, "alice", "", "确认执行 restart")
	if !errors.Is(err, ErrL4Phrase) {
		t.Fatalf("错短语应 ErrL4Phrase，got %v", err)
	}
	if strings.Contains(err.Error(), phrase) {
		t.Fatalf("错误信息不得回显正确短语: %v", err)
	}
	if row := store.row(id); row.Status != StatusPending || row.L4FirstAt != nil {
		t.Fatalf("被拒后不应变化: %+v", row)
	}

	// 首次携带正确短语：受理但保持 pending，只记 L4FirstAt。
	if ok, err := svc.Decide(ctx, id, StatusApproved, "alice", "", phrase); err != nil || !ok {
		t.Fatalf("首次确认应受理: ok=%v err=%v", ok, err)
	}
	row := store.row(id)
	if row.Status != StatusPending || row.L4FirstAt == nil || row.DecideTokenHash != "" {
		t.Fatalf("首次确认后应保持 pending 且记 L4FirstAt: %+v", row)
	}
	if len(pub.snapshot()) != 0 {
		t.Fatal("首次确认非终态，不应发决策事件")
	}

	// 第二次错短语拒绝；正确短语（可由他人）落 approved + 凭据。
	if ok, err := svc.Decide(ctx, id, StatusApproved, "bob", "", "错误短语"); ok || !errors.Is(err, ErrL4Phrase) {
		t.Fatalf("二次错短语应拒绝: ok=%v err=%v", ok, err)
	}
	if ok, err := svc.Decide(ctx, id, StatusApproved, "bob", "复核同意", phrase); err != nil || !ok {
		t.Fatalf("二次正确短语应通过: ok=%v err=%v", ok, err)
	}
	row = store.row(id)
	if row.Status != StatusApproved || row.DecideTokenHash == "" {
		t.Fatalf("终态不符: %+v", row)
	}

	// L4 拒绝不需要短语；L4 代批恒拒绝。
	id2, err := svc.Submit(ctx, SubmitInput{CaseID: "l4-2", Plan: []byte("{}"), RequestType: "delete", RiskLevel: 4})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := svc.Decide(ctx, id2, StatusRejected, "alice", "人工拒绝", ""); err != nil || !ok {
		t.Fatalf("L4 reject 应允许: ok=%v err=%v", ok, err)
	}
	id3, err := svc.Submit(ctx, SubmitInput{CaseID: "l4-3", Plan: []byte("{}"), RequestType: "delete", RiskLevel: 4})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := svc.DecideSystem(ctx, id3, StatusApproved, "auto"); ok || !errors.Is(err, ErrL4System) {
		t.Fatalf("L4 代批应 ErrL4System: ok=%v err=%v", ok, err)
	}
	if store.status(id3) != StatusPending {
		t.Fatal("L4 代批被拒后应保持 pending")
	}
}

func TestDecideSystem(t *testing.T) {
	ctx := context.Background()
	svc, store, pub, _ := fixture(t, Config{})
	id := submit(t, svc, 2)
	if ok, err := svc.DecideSystem(ctx, id, StatusApproved, "auto 模式：风险 L2 ≤ 上限"); err != nil || !ok {
		t.Fatalf("代批应成功: ok=%v err=%v", ok, err)
	}
	row := store.row(id)
	if row.Status != StatusApproved || row.DecidedBy != SystemDecider {
		t.Fatalf("状态/决策人不符: %+v", row)
	}
	if !strings.Contains(row.DecisionNote, "策略代批") || !strings.Contains(row.DecisionNote, "auto 模式") {
		t.Fatalf("代批备注应记录依据: %q", row.DecisionNote)
	}
	events := pub.snapshot()
	if len(events) != 1 || events[0].Type != EventDecided || events[0].By != SystemDecider {
		t.Fatalf("代批事件不符: %+v", events)
	}

	// 代批凭据与人工批准同语义：一次性核销。
	status, token, _, err := svc.AwaitDecision(ctx, id)
	if err != nil || status != StatusApproved || token == "" {
		t.Fatalf("AwaitDecision: %s %q %v", status, token, err)
	}
	if ok, err := svc.ConsumeToken(ctx, id, token); err != nil || !ok {
		t.Fatalf("代批 token 应可核销: ok=%v err=%v", ok, err)
	}
	if ok, _ := svc.ConsumeToken(ctx, id, token); ok {
		t.Fatal("token 必须一次性")
	}

	// 代批 reject。
	id2 := submit(t, svc, 2)
	if ok, err := svc.DecideSystem(ctx, id2, StatusRejected, "矩阵拒绝"); err != nil || !ok {
		t.Fatalf("代批 reject 应成功: ok=%v err=%v", ok, err)
	}
	if row := store.row(id2); row.Status != StatusRejected || row.DecideTokenHash != "" {
		t.Fatalf("reject 不应签 token: %+v", row)
	}

	if _, err := svc.DecideSystem(ctx, id2, StatusExpired, "x"); !errors.Is(err, ErrInvalidDecision) {
		t.Fatalf("非法 decision 应 ErrInvalidDecision，got %v", err)
	}
}

// ── 一次性核销 ──────────────────────────────────────────────────────

func TestConsumeToken(t *testing.T) {
	ctx := context.Background()
	svc, store, _, _ := fixture(t, Config{})

	id := submit(t, svc, 2)
	if ok, err := svc.Decide(ctx, id, StatusApproved, "bob", "", ""); err != nil || !ok {
		t.Fatalf("批准失败: ok=%v err=%v", ok, err)
	}
	_, token, _, err := svc.AwaitDecision(ctx, id)
	if err != nil || token == "" {
		t.Fatalf("AwaitDecision: %q %v", token, err)
	}
	if strings.Count(token, ".") != 1 {
		t.Fatalf("tokenx 令牌应为两段式: %q", token)
	}
	if got, want := store.row(id).DecideTokenHash, sha256Hex([]byte(token)); got != want {
		t.Fatalf("库存哈希应与 sha256(token) 一致: %q vs %q", got, want)
	}

	// 错误 token / 篡改 token / 跨单挪用 → false, nil。
	if ok, err := svc.ConsumeToken(ctx, id, "wrong-token"); err != nil || ok {
		t.Fatalf("错误 token 应拒绝: ok=%v err=%v", ok, err)
	}
	flipped := "A" + token[1:]
	if token[0] == 'A' {
		flipped = "B" + token[1:]
	}
	if ok, _ := svc.ConsumeToken(ctx, id, flipped); ok {
		t.Fatal("篡改 token 应拒绝")
	}

	id2 := submit(t, svc, 2)
	if ok, err := svc.Decide(ctx, id2, StatusApproved, "bob", "", ""); err != nil || !ok {
		t.Fatalf("第二单批准失败: %v", err)
	}
	_, token2, _, err := svc.AwaitDecision(ctx, id2)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := svc.ConsumeToken(ctx, id, token2); ok {
		t.Fatal("跨单挪用 token 应拒绝（载荷绑定 approval_id）")
	}

	// 正确 token 一次性核销。
	if ok, err := svc.ConsumeToken(ctx, id, token); err != nil || !ok {
		t.Fatalf("正确 token 应核销: ok=%v err=%v", ok, err)
	}
	if ok, _ := svc.ConsumeToken(ctx, id, token); ok {
		t.Fatal("二次核销应拒绝")
	}

	// 未批准单不核销。
	id3 := submit(t, svc, 2)
	if ok, _ := svc.ConsumeToken(ctx, id3, token); ok {
		t.Fatal("pending 单不应核销")
	}
	id4 := submit(t, svc, 2)
	if ok, _ := svc.Decide(ctx, id4, StatusRejected, "bob", "", ""); err != nil || !ok {
		t.Fatalf("reject: %v", err)
	}
	if ok, _ := svc.ConsumeToken(ctx, id4, token); ok {
		t.Fatal("rejected 单不应核销")
	}
}

func TestConsumeTokenBindsPlanHash(t *testing.T) {
	ctx := context.Background()
	svc, store, _, _ := fixture(t, Config{})
	id := submit(t, svc, 2)
	if ok, err := svc.Decide(ctx, id, StatusApproved, "bob", "", ""); err != nil || !ok {
		t.Fatalf("批准失败: %v", err)
	}
	_, token, _, err := svc.AwaitDecision(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	// 批准后方案哈希被改：tokenx 载荷绑定必须拒绝。
	store.mutate(id, func(a *Approval) { a.PlanHash = strings.Repeat("0", 64) })
	if ok, _ := svc.ConsumeToken(ctx, id, token); ok {
		t.Fatal("plan_hash 变更后 token 应失效（载荷绑定）")
	}
}

// ── AwaitDecision ──────────────────────────────────────────────────

func TestAwaitDecisionWakeup(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := fixture(t, Config{})
	id := submit(t, svc, 2)

	type result struct {
		status Status
		token  string
		note   string
		err    error
	}
	ch := make(chan result, 1)
	go func() {
		status, token, note, err := svc.AwaitDecision(ctx, id)
		ch <- result{status, token, note, err}
	}()
	time.Sleep(20 * time.Millisecond)
	if ok, err := svc.Decide(ctx, id, StatusApproved, "bob", "同意", ""); err != nil || !ok {
		t.Fatalf("Decide: ok=%v err=%v", ok, err)
	}
	select {
	case got := <-ch:
		if got.err != nil || got.status != StatusApproved || got.token == "" || got.note != "同意" {
			t.Fatalf("Await 结果不符: %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AwaitDecision 未被唤醒")
	}
}

func TestAwaitDecisionCancelAndCtx(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := fixture(t, Config{})
	id := submit(t, svc, 2)
	ch := make(chan Status, 1)
	go func() {
		status, _, _, _ := svc.AwaitDecision(ctx, id)
		ch <- status
	}()
	time.Sleep(20 * time.Millisecond)
	if ok, err := svc.CancelPending(ctx, id, "alice", "用户取消"); err != nil || !ok {
		t.Fatalf("CancelPending: ok=%v err=%v", ok, err)
	}
	select {
	case status := <-ch:
		if status != StatusCancelled {
			t.Fatalf("取消后 Await 应回 cancelled，got %s", status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("取消未唤醒 AwaitDecision")
	}

	// ctx 取消。
	id2 := submit(t, svc, 2)
	cctx, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	if _, _, _, err := svc.AwaitDecision(cctx, id2); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ctx 到期应 DeadlineExceeded，got %v", err)
	}
}

func TestAwaitDecisionLazilyExpires(t *testing.T) {
	ctx := context.Background()
	svc, store, pub, _ := fixture(t, Config{})
	id := submit(t, svc, 2)
	store.mutate(id, func(a *Approval) { a.ExpiresAt = time.Now().Add(-time.Second) })
	status, token, _, err := svc.AwaitDecision(ctx, id)
	if err != nil || status != StatusExpired || token != "" {
		t.Fatalf("Await 应收敛 expired: %s %q %v", status, token, err)
	}
	if len(pub.snapshot()) != 1 {
		t.Fatal("到期收敛应发一次过期事件")
	}
}

// ── Sweep ──────────────────────────────────────────────────────────

func TestSweepExpired(t *testing.T) {
	ctx := context.Background()
	svc, store, pub, _ := fixture(t, Config{})
	id1 := submit(t, svc, 2)
	id2 := submit(t, svc, 2)
	store.mutate(id1, func(a *Approval) { a.ExpiresAt = time.Now().Add(-time.Minute) })
	store.mutate(id2, func(a *Approval) { a.ExpiresAt = time.Now().Add(-time.Minute) })
	id3 := submit(t, svc, 2) // 未到期

	if got := svc.SweepExpired(ctx); got != 2 {
		t.Fatalf("应收敛 2 单，got %d", got)
	}
	if store.status(id1) != StatusExpired || store.status(id2) != StatusExpired {
		t.Fatalf("到期单应为 expired: %s %s", store.status(id1), store.status(id2))
	}
	if store.status(id3) != StatusPending {
		t.Fatal("未到期单不应被收敛")
	}
	if events := pub.snapshot(); len(events) != 2 {
		t.Fatalf("每个到期单应发一次事件，got %d", len(events))
	}
	if got := svc.SweepExpired(ctx); got != 0 {
		t.Fatalf("重复 sweep 应 0，got %d", got)
	}
}

func TestSweepUnnotifiedRequests(t *testing.T) {
	ctx := context.Background()
	svc, store, _, notifier := fixture(t, Config{RemindAfter: 10 * time.Minute})
	id := submit(t, svc, 2)
	now := time.Now()
	if notifier.count() != 1 {
		t.Fatalf("Submit 实时卡应 1，got %d", notifier.count())
	}
	store.mutate(id, func(a *Approval) { a.CreatedAt = now.Add(-11 * time.Minute) })
	evID := store.addEvent(id, now.Add(-11*time.Minute))
	if got := svc.SweepUnnotifiedRequests(ctx, now); got != 1 {
		t.Fatalf("过阈值应补推 1，got %d", got)
	}
	if notifier.count() != 2 {
		t.Fatalf("补推后应 2 张卡，got %d", notifier.count())
	}
	if !store.eventNotified(evID) {
		t.Fatal("补推后应落 notified 标记")
	}
	if got := svc.SweepUnnotifiedRequests(ctx, now); got != 0 {
		t.Fatalf("标记后重复扫描应 0，got %d", got)
	}

	// 未过阈值：不推不标记。
	id2 := submit(t, svc, 2)
	young := store.addEvent(id2, now.Add(-time.Minute))
	if got := svc.SweepUnnotifiedRequests(ctx, now); got != 0 {
		t.Fatalf("未过阈值不应补推，got %d", got)
	}
	if store.eventNotified(young) {
		t.Fatal("未过阈值不应落标记")
	}

	// 已决策：只落标记不推送。
	id3 := submit(t, svc, 2)
	if ok, err := svc.Decide(ctx, id3, StatusRejected, "bob", "", ""); err != nil || !ok {
		t.Fatalf("Decide: %v", err)
	}
	decided := store.addEvent(id3, now.Add(-11*time.Minute))
	before := notifier.count()
	if got := svc.SweepUnnotifiedRequests(ctx, now); got != 0 {
		t.Fatalf("已决策不应补推，got %d", got)
	}
	if notifier.count() != before {
		t.Fatal("已决策不应新增卡片")
	}
	if !store.eventNotified(decided) {
		t.Fatal("已决策事件应落标记收敛扫描集")
	}

	// 无法归属的事件：落标记，不空转。
	orphan := store.addEvent("", now.Add(-11*time.Minute))
	if got := svc.SweepUnnotifiedRequests(ctx, now); got != 0 {
		t.Fatalf("孤儿事件不应补推，got %d", got)
	}
	if !store.eventNotified(orphan) {
		t.Fatal("孤儿事件应落标记")
	}

	// 读单失败的合法 approval_id：不标记，下轮重试。
	missing := store.addEvent("no-such-approval", now.Add(-11*time.Minute))
	if got := svc.SweepUnnotifiedRequests(ctx, now); got != 0 {
		t.Fatalf("读单失败不应补推，got %d", got)
	}
	if store.eventNotified(missing) {
		t.Fatal("读单失败不应落标记（需下轮重试）")
	}

	// notifier 为 nil：直接 0。
	svc2, store2, _, _ := fixture(t, Config{})
	svc2.notifier = nil
	id4 := submit(t, svc2, 2)
	store2.addEvent(id4, now.Add(-11*time.Minute))
	if got := svc2.SweepUnnotifiedRequests(ctx, now); got != 0 {
		t.Fatalf("nil notifier 应 0，got %d", got)
	}
}

// ── Cancel / 谓词 / 并发 ────────────────────────────────────────────

func TestCancelPending(t *testing.T) {
	ctx := context.Background()
	svc, store, pub, _ := fixture(t, Config{})
	id := submit(t, svc, 2)
	if ok, err := svc.CancelPending(ctx, id, "alice", "用户取消"); err != nil || !ok {
		t.Fatalf("CancelPending: ok=%v err=%v", ok, err)
	}
	row := store.row(id)
	if row.Status != StatusCancelled || row.DecidedBy != "alice" || row.DecisionNote != "用户取消" {
		t.Fatalf("取消后字段不符: %+v", row)
	}
	events := pub.snapshot()
	if len(events) != 1 || events[0].Type != EventCancelled || events[0].Status != StatusCancelled {
		t.Fatalf("取消事件不符: %+v", events)
	}
	if ok, _ := svc.CancelPending(ctx, id, "alice", "again"); ok {
		t.Fatal("重复取消应 false")
	}
}

func TestExpiredFor(t *testing.T) {
	base := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	a := &Approval{ExpiresAt: base}
	cases := []struct {
		name     string
		approval *Approval
		decision Status
		now      time.Time
		want     bool
	}{
		{"approve 到期前", a, StatusApproved, base.Add(-time.Second), false},
		{"approve 截止即过期", a, StatusApproved, base, true},
		{"approve 到期后", a, StatusApproved, base.Add(time.Second), true},
		{"reject 到期后恒否", a, StatusRejected, base.Add(time.Hour), false},
		{"reject 到期前", a, StatusRejected, base.Add(-time.Hour), false},
		{"nil 单", nil, StatusApproved, base.Add(time.Hour), false},
	}
	for _, c := range cases {
		if got := ExpiredForAt(c.approval, c.decision, c.now); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestValidateDecision(t *testing.T) {
	for _, d := range []Status{StatusApproved, StatusRejected} {
		if err := ValidateDecision(d); err != nil {
			t.Errorf("%s 应合法: %v", d, err)
		}
	}
	for _, d := range []Status{StatusPending, StatusExpired, StatusCancelled, ""} {
		if err := ValidateDecision(d); !errors.Is(err, ErrInvalidDecision) {
			t.Errorf("%q 应 ErrInvalidDecision，got %v", d, err)
		}
	}
}

func TestConcurrentDecide(t *testing.T) {
	ctx := context.Background()
	svc, store, pub, _ := fixture(t, Config{})
	id := submit(t, svc, 2)

	const n = 8
	var wg sync.WaitGroup
	results := make([]bool, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			decision := StatusApproved
			if i%2 == 1 {
				decision = StatusRejected
			}
			ok, err := svc.Decide(ctx, id, decision, "u"+string(rune('a'+i)), "", "")
			results[i], errs[i] = ok, err
		}(i)
	}
	wg.Wait()

	wins := 0
	for i := range results {
		if errs[i] != nil {
			t.Fatalf("并发决策不应报错: %v", errs[i])
		}
		if results[i] {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("并发决策应恰有一个 winner，got %d", wins)
	}
	status := store.status(id)
	if status != StatusApproved && status != StatusRejected {
		t.Fatalf("终态非法: %s", status)
	}
	events := pub.snapshot()
	if len(events) != 1 {
		t.Fatalf("终态事件应恰一次，got %d", len(events))
	}
	if status == StatusApproved && store.row(id).DecideTokenHash == "" {
		t.Fatal("approved 应落凭据哈希")
	}
}
