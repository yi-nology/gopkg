package approval

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yi-nology/gopkg/tokenx"
)

var errNotFound = errors.New("not found")

// memStore 参照 bq_approval 的 CAS 语义实现（测试用）。
type memStore struct {
	mu   sync.Mutex
	rows map[string]Request
	// getGate 测试栅栏：非 nil 时 Get 在返回快照前等待，用于把并发首确认
	// 的初始读取钉在同一时点。
	getGate      chan struct{}
	gateWaiters  int
	getErr       error
	decideErr    error
	expireErr    error
	cancelErr    error
	consumeErr   error
	existsErr    error
	createErr    error
	expireDueErr error
}

func newMemStore() *memStore { return &memStore{rows: map[string]Request{}} }

func (m *memStore) Create(_ context.Context, r *Request) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.createErr != nil {
		return m.createErr
	}
	if _, ok := m.rows[r.ApprovalID]; ok {
		return errors.New("duplicate approval id")
	}
	m.rows[r.ApprovalID] = *r
	return nil
}

func (m *memStore) Get(_ context.Context, id string) (*Request, error) {
	m.mu.Lock()
	if m.getErr != nil {
		err := m.getErr
		m.mu.Unlock()
		return nil, err
	}
	r, ok := m.rows[id]
	if !ok {
		m.mu.Unlock()
		return nil, errNotFound
	}
	cp := r
	gate := m.getGate
	if gate != nil {
		m.gateWaiters++
	}
	m.mu.Unlock()
	if gate != nil {
		<-gate
	}
	return &cp, nil
}

func (m *memStore) Decide(_ context.Context, id string, decision Status, by, note, tokenHash string, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.decideErr != nil {
		return false, m.decideErr
	}
	r, ok := m.rows[id]
	if !ok || r.Status != StatusPending {
		return false, nil
	}
	if tokenHash != "" && !r.ExpiresAt.After(now) {
		return false, nil
	}
	r.Status = decision
	r.DecidedBy = by
	r.DecisionNote = note
	at := now
	r.DecidedAt = &at
	if tokenHash != "" {
		r.DecideTokenHash = tokenHash
	}
	m.rows[id] = r
	return true, nil
}

func (m *memStore) MarkL4First(_ context.Context, id string, at time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[id]
	if !ok || r.Status != StatusPending || r.L4FirstAt != nil {
		return false, nil
	}
	first := at
	r.L4FirstAt = &first
	m.rows[id] = r
	return true, nil
}

func (m *memStore) Expire(_ context.Context, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.expireErr != nil {
		return false, m.expireErr
	}
	r, ok := m.rows[id]
	if !ok || r.Status != StatusPending {
		return false, nil
	}
	r.Status = StatusExpired
	m.rows[id] = r
	return true, nil
}

func (m *memStore) ExpireDue(_ context.Context, now time.Time) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.expireDueErr != nil {
		return nil, m.expireDueErr
	}
	var ids []string
	for id, r := range m.rows {
		if r.Status == StatusPending && !r.ExpiresAt.After(now) {
			r.Status = StatusExpired
			m.rows[id] = r
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func (m *memStore) Cancel(_ context.Context, id, by, note string, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancelErr != nil {
		return false, m.cancelErr
	}
	r, ok := m.rows[id]
	if !ok || r.Status != StatusPending {
		return false, nil
	}
	r.Status = StatusCancelled
	r.DecidedBy = by
	r.DecisionNote = note
	at := now
	r.DecidedAt = &at
	m.rows[id] = r
	return true, nil
}

func (m *memStore) ConsumeToken(_ context.Context, id, tokenHash string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.consumeErr != nil {
		return false, m.consumeErr
	}
	r, ok := m.rows[id]
	if !ok || r.Status != StatusApproved || r.DecideTokenHash != tokenHash || r.TokenUsedAt != nil {
		return false, nil
	}
	now := time.Now()
	r.TokenUsedAt = &now
	m.rows[id] = r
	return true, nil
}

func (m *memStore) ExistsPlanHash(_ context.Context, caseID, planHash string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.existsErr != nil {
		return false, m.existsErr
	}
	for _, r := range m.rows {
		if r.CaseID == caseID && r.PlanHash == planHash {
			return true, nil
		}
	}
	return false, nil
}

func (m *memStore) row(t *testing.T, id string) Request {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[id]
	if !ok {
		t.Fatalf("审批单 %s 不存在", id)
	}
	return r
}

// clock 可注入时钟。
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock {
	return &clock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type eventRecorder struct {
	mu     sync.Mutex
	events []Event
}

func (e *eventRecorder) Publish(ev Event) {
	e.mu.Lock()
	e.events = append(e.events, ev)
	e.mu.Unlock()
}

func (e *eventRecorder) list() []Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Event, len(e.events))
	copy(out, e.events)
	return out
}

func (e *eventRecorder) len() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.events)
}

type fixture struct {
	svc    *Service
	store  *memStore
	clock  *clock
	events *eventRecorder
}

func newFixture(t *testing.T, mutate func(*Config)) *fixture {
	t.Helper()
	store := newMemStore()
	clk := newClock()
	ev := &eventRecorder{}
	cfg := Config{
		Store:     store,
		Publisher: ev,
		Secret:    "test-secret",
		Timeout:   time.Hour,
		Now:       clk.Now,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	svc, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &fixture{svc: svc, store: store, clock: clk, events: ev}
}

func (f *fixture) submit(t *testing.T, in SubmitInput) string {
	t.Helper()
	id, err := f.svc.Submit(context.Background(), in)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	return id
}

func baseSubmitInput() SubmitInput {
	return SubmitInput{
		CaseID:      "cs-7",
		SessionID:   "sess-1",
		StepID:      42,
		RequestType: "restart",
		RiskLevel:   2,
		PlanReport:  []byte(`{"cmd":"systemctl restart api"}`),
		CreatedBy:   "alice",
	}
}

func TestNewRequiresStore(t *testing.T) {
	if _, err := New(Config{}); !errors.Is(err, ErrNoStore) {
		t.Fatalf("err = %v, want ErrNoStore", err)
	}
}

func TestSubmitAndFastTrack(t *testing.T) {
	f := newFixture(t, func(c *Config) {
		c.FastTrack = &FastTrack{Timeout: 10 * time.Minute, MaxRisk: 1}
	})
	now := f.clock.Now()

	lowID := f.submit(t, SubmitInput{CaseID: "cs-1", RequestType: "status", RiskLevel: 1, CreatedBy: "alice"})
	low := f.store.row(t, lowID)
	if !low.ExpiresAt.Equal(now.Add(10 * time.Minute)) {
		t.Errorf("低风险 expires_at = %v, want %v", low.ExpiresAt, now.Add(10*time.Minute))
	}
	if low.Status != StatusPending || low.CreatedBy != "alice" {
		t.Errorf("row = %+v", low)
	}
	if string(low.PlanReport) != "{}" || low.PlanHash != sha256Hex("{}") {
		t.Errorf("空方案快照 = %q hash=%q", low.PlanReport, low.PlanHash)
	}

	highID := f.submit(t, baseSubmitInput())
	high := f.store.row(t, highID)
	if !high.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Errorf("风险 2 expires_at = %v, want %v", high.ExpiresAt, now.Add(time.Hour))
	}
	if high.PlanHash != sha256Hex(string(high.PlanReport)) {
		t.Errorf("plan_hash 不符: %q", high.PlanHash)
	}
	if !strings.HasPrefix(highID, "appr-cs-7-") {
		t.Errorf("approval id = %q", highID)
	}

	if _, err := f.svc.Submit(context.Background(), SubmitInput{RequestType: "x"}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("缺 case_id err = %v", err)
	}
	if _, err := f.svc.Submit(context.Background(), SubmitInput{CaseID: "cs"}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("缺 request_type err = %v", err)
	}
}

func TestDecideApproveAndOneTimeToken(t *testing.T) {
	f := newFixture(t, nil)
	id := f.submit(t, baseSubmitInput())

	ok, err := f.svc.Decide(context.Background(), id, StatusApproved, "bob", "looks good", "")
	if err != nil || !ok {
		t.Fatalf("Decide = %v, %v", ok, err)
	}
	r := f.store.row(t, id)
	if r.Status != StatusApproved || r.DecidedBy != "bob" || r.DecisionNote != "looks good" {
		t.Errorf("row = %+v", r)
	}
	if r.DecideTokenHash == "" || len(r.DecideTokenHash) != 64 {
		t.Errorf("decide_token_hash = %q", r.DecideTokenHash)
	}

	dec, err := f.svc.AwaitDecision(context.Background(), id)
	if err != nil {
		t.Fatalf("AwaitDecision: %v", err)
	}
	if dec.Status != StatusApproved || dec.Token == "" || dec.Note != "looks good" {
		t.Errorf("decision = %+v", dec)
	}
	// 凭据是 tokenx 令牌，且绑定审批行四字段。
	if _, err := tokenx.VerifyAt("test-secret", dec.Token, tokenClaims(&r), r.ExpiresAt); err != nil {
		t.Errorf("tokenx.VerifyAt: %v", err)
	}
	if sha256Hex(dec.Token) != r.DecideTokenHash {
		t.Errorf("库存哈希不是 sha256(token)")
	}

	ok, err = f.svc.ConsumeToken(context.Background(), id, dec.Token)
	if err != nil || !ok {
		t.Fatalf("first ConsumeToken = %v, %v", ok, err)
	}
	ok, err = f.svc.ConsumeToken(context.Background(), id, dec.Token)
	if err != nil || ok {
		t.Fatalf("second ConsumeToken = %v, %v (want false)", ok, err)
	}
	ok, _ = f.svc.ConsumeToken(context.Background(), id, "garbage")
	if ok {
		t.Fatal("garbage token 被接受")
	}
	if f.store.row(t, id).TokenUsedAt == nil {
		t.Error("token_used_at 未落")
	}

	evs := f.events.list()
	if len(evs) != 1 || evs[0].Type != EventDecided || evs[0].Status != StatusApproved || evs[0].DecidedBy != "bob" {
		t.Errorf("events = %+v", evs)
	}
	if evs[0].CaseID != "cs-7" || evs[0].SessionID != "sess-1" || evs[0].StepID != 42 ||
		evs[0].RequestType != "restart" || evs[0].RiskLevel != 2 || evs[0].CreatedBy != "alice" {
		t.Errorf("event 字段 = %+v", evs[0])
	}
}

func TestConsumeTokenBoundToRequest(t *testing.T) {
	f := newFixture(t, nil)
	idA := f.submit(t, baseSubmitInput())
	inB := baseSubmitInput()
	inB.PlanReport = []byte(`{"cmd":"reboot"}`)
	idB := f.submit(t, inB)
	for _, id := range []string{idA, idB} {
		if ok, err := f.svc.Decide(context.Background(), id, StatusApproved, "bob", "", ""); err != nil || !ok {
			t.Fatalf("Decide %s = %v, %v", id, ok, err)
		}
	}
	decA, err := f.svc.AwaitDecision(context.Background(), idA)
	if err != nil {
		t.Fatal(err)
	}
	decB, err := f.svc.AwaitDecision(context.Background(), idB)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := f.svc.ConsumeToken(context.Background(), idB, decA.Token); ok {
		t.Fatal("A 的凭据在 B 上通过（载荷绑定失效）")
	}
	if ok, err := f.svc.ConsumeToken(context.Background(), idA, decA.Token); err != nil || !ok {
		t.Fatalf("A 凭据核销 = %v, %v", ok, err)
	}
	if ok, err := f.svc.ConsumeToken(context.Background(), idB, decB.Token); err != nil || !ok {
		t.Fatalf("B 凭据核销 = %v, %v", ok, err)
	}
}

func TestDenyByDefaultExpired(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.Timeout = time.Minute })

	// approve 过期单：拒绝并把行收敛为 expired。
	id := f.submit(t, baseSubmitInput())
	f.clock.Advance(2 * time.Minute)
	if ok, err := f.svc.Decide(context.Background(), id, StatusApproved, "bob", "", ""); !errors.Is(err, ErrExpired) || ok {
		t.Fatalf("过期批准 = %v, %v, want ErrExpired", ok, err)
	}
	r := f.store.row(t, id)
	if r.Status != StatusExpired || r.DecideTokenHash != "" {
		t.Errorf("row = %+v", r)
	}
	evs := f.events.list()
	if len(evs) != 1 || evs[0].Type != EventExpired || evs[0].Status != StatusExpired {
		t.Errorf("events = %+v", evs)
	}

	// reject 是 deny 方向：过期但尚未收敛的 pending 行仍可 reject。
	id2 := f.submit(t, baseSubmitInput())
	f.clock.Advance(2 * time.Minute)
	if ok, err := f.svc.Decide(context.Background(), id2, StatusRejected, "bob", "no", ""); err != nil || !ok {
		t.Fatalf("过期 reject = %v, %v", ok, err)
	}
	if got := f.store.row(t, id2).Status; got != StatusRejected {
		t.Errorf("status = %q, want rejected", got)
	}

	// 存储层双保险：approve 的 CAS 也拒绝过期行。
	id3 := f.submit(t, baseSubmitInput())
	f.clock.Advance(2 * time.Minute)
	ok, err := f.store.Decide(context.Background(), id3, StatusApproved, "bob", "", "hash", f.clock.Now())
	if err != nil || ok {
		t.Fatalf("store 过期 approve = %v, %v, want false", ok, err)
	}

	// AwaitDecision 惰性收敛：没人跑 sweep 也能拿到 expired。
	dec, err := f.svc.AwaitDecision(context.Background(), id3)
	if err != nil {
		t.Fatalf("AwaitDecision: %v", err)
	}
	if dec.Status != StatusExpired || dec.Token != "" {
		t.Errorf("decision = %+v", dec)
	}
}

func TestSeparateApprover(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.RequireSeparateApprover = true })
	id := f.submit(t, baseSubmitInput()) // CreatedBy alice

	if ok, err := f.svc.Decide(context.Background(), id, StatusApproved, "alice", "", ""); !errors.Is(err, ErrSeparateApprover) || ok {
		t.Fatalf("自批 = %v, %v, want ErrSeparateApprover", ok, err)
	}
	if got := f.store.row(t, id).Status; got != StatusPending {
		t.Errorf("自批被拒后 status = %q", got)
	}
	if ok, err := f.svc.Decide(context.Background(), id, StatusRejected, "alice", "self reject ok", ""); err != nil || !ok {
		t.Fatalf("自驳 = %v, %v, want allowed", ok, err)
	}

	// 提审人无身份（CreatedBy 空）时不生效。
	in := baseSubmitInput()
	in.CreatedBy = ""
	id2 := f.submit(t, in)
	if ok, err := f.svc.Decide(context.Background(), id2, StatusApproved, "anyone", "", ""); err != nil || !ok {
		t.Fatalf("无身份提审 = %v, %v", ok, err)
	}

	// 运行时关闭开关。
	f.svc.SetRequireSeparateApprover(false)
	id3 := f.submit(t, baseSubmitInput())
	if ok, err := f.svc.Decide(context.Background(), id3, StatusApproved, "alice", "", ""); err != nil || !ok {
		t.Fatalf("关闭分离后自批 = %v, %v", ok, err)
	}
}

func TestL4DoubleConfirm(t *testing.T) {
	f := newFixture(t, nil)
	in := baseSubmitInput()
	in.RequestType = "delete"
	in.RiskLevel = RiskL4
	id := f.submit(t, in)
	phrase := L4Phrase("delete")

	if ok, err := f.svc.Decide(context.Background(), id, StatusApproved, "bob", "", ""); !errors.Is(err, ErrL4Phrase) || ok {
		t.Fatalf("无短语首确认 = %v, %v", ok, err)
	}
	if ok, err := f.svc.Decide(context.Background(), id, StatusApproved, "bob", "", "确认执行 wrong"); !errors.Is(err, ErrL4Phrase) || ok {
		t.Fatalf("错短语首确认 = %v, %v", ok, err)
	}
	if ok, err := f.svc.Decide(context.Background(), id, StatusApproved, "bob", "", phrase); err != nil || !ok {
		t.Fatalf("首确认 = %v, %v", ok, err)
	}
	r := f.store.row(t, id)
	if r.Status != StatusPending || r.L4FirstAt == nil || r.DecideTokenHash != "" {
		t.Fatalf("首确认后 row = %+v, want pending + l4_first_at", r)
	}
	if f.events.len() != 0 {
		t.Errorf("首确认不应发终态事件: %+v", f.events.list())
	}

	if ok, err := f.svc.Decide(context.Background(), id, StatusApproved, "bob", "", ""); !errors.Is(err, ErrL4Phrase) || ok {
		t.Fatalf("二次无短语 = %v, %v", ok, err)
	}
	if ok, err := f.svc.Decide(context.Background(), id, StatusApproved, "bob", "confirmed", phrase); err != nil || !ok {
		t.Fatalf("二次确认 = %v, %v", ok, err)
	}
	r = f.store.row(t, id)
	if r.Status != StatusApproved || r.DecideTokenHash == "" {
		t.Fatalf("二次确认后 row = %+v", r)
	}
	dec, err := f.svc.AwaitDecision(context.Background(), id)
	if err != nil || dec.Status != StatusApproved || dec.Token == "" {
		t.Fatalf("decision = %+v, %v", dec, err)
	}
	if ok, err := f.svc.ConsumeToken(context.Background(), id, dec.Token); err != nil || !ok {
		t.Fatalf("L4 token 核销 = %v, %v", ok, err)
	}

	// L4 永不代批。
	id2 := f.submit(t, in)
	if ok, err := f.svc.DecideSystem(context.Background(), id2, StatusApproved, "auto"); !errors.Is(err, ErrL4System) || ok {
		t.Fatalf("L4 代批 = %v, %v", ok, err)
	}
}

func TestL4ConcurrentFirstConfirmation(t *testing.T) {
	f := newFixture(t, nil)
	in := baseSubmitInput()
	in.RiskLevel = RiskL4
	id := f.submit(t, in)
	phrase := L4Phrase(in.RequestType)

	// 栅栏把 N 个并发 Decide 的初始 Get 钉在同一时点（都看到 L4FirstAt
	// 为空），于是它们都走「首确认」分支：一个 CAS 成功，其余经重读
	// 收敛为「首确认已存在」——任何一个都不应被当成第二次批准。
	gate := make(chan struct{})
	f.store.mu.Lock()
	f.store.getGate = gate
	f.store.mu.Unlock()

	const n = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	for k := 0; k < n; k++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := f.svc.Decide(context.Background(), id, StatusApproved, "bob", "", phrase)
			if err != nil {
				return
			}
			if ok {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		f.store.mu.Lock()
		waiters := f.store.gateWaiters
		f.store.mu.Unlock()
		if waiters >= n || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(gate)
	wg.Wait()
	f.store.mu.Lock()
	f.store.getGate = nil
	f.store.mu.Unlock()

	if accepted != n {
		t.Errorf("并发首确认受理数 = %d, want %d（首确认是非终态，重复首确认视同受理）", accepted, n)
	}
	r := f.store.row(t, id)
	if r.Status != StatusPending || r.L4FirstAt == nil {
		t.Fatalf("row = %+v, want pending + l4_first_at", r)
	}

	// 串行的第二次确认才落 approved。
	if ok, err := f.svc.Decide(context.Background(), id, StatusApproved, "bob", "", phrase); err != nil || !ok {
		t.Fatalf("第二次确认 = %v, %v", ok, err)
	}
	if got := f.store.row(t, id).Status; got != StatusApproved {
		t.Errorf("二次确认后 status = %q", got)
	}
}

func TestDecideSystem(t *testing.T) {
	f := newFixture(t, nil)
	id := f.submit(t, baseSubmitInput()) // risk 2
	if ok, err := f.svc.DecideSystem(context.Background(), id, StatusApproved, "matrix auto/full"); err != nil || !ok {
		t.Fatalf("DecideSystem = %v, %v", ok, err)
	}
	r := f.store.row(t, id)
	if r.Status != StatusApproved || r.DecidedBy != SystemDecider || !strings.HasPrefix(r.DecisionNote, "策略代批: ") {
		t.Errorf("row = %+v", r)
	}
	evs := f.events.list()
	if len(evs) != 1 || evs[0].DecidedBy != SystemDecider {
		t.Errorf("events = %+v", evs)
	}
	dec, err := f.svc.AwaitDecision(context.Background(), id)
	if err != nil || dec.Token == "" {
		t.Fatalf("decision = %+v, %v", dec, err)
	}
	if ok, err := f.svc.ConsumeToken(context.Background(), id, dec.Token); err != nil || !ok {
		t.Fatalf("代批 token 核销 = %v, %v", ok, err)
	}

	// 过期单不得代批。
	id2 := f.submit(t, baseSubmitInput())
	f.clock.Advance(2 * time.Hour)
	if ok, err := f.svc.DecideSystem(context.Background(), id2, StatusApproved, "auto"); !errors.Is(err, ErrExpired) || ok {
		t.Fatalf("过期代批 = %v, %v", ok, err)
	}
	// reject 方向允许。
	id3 := f.submit(t, baseSubmitInput())
	f.clock.Advance(2 * time.Hour)
	if ok, err := f.svc.DecideSystem(context.Background(), id3, StatusRejected, "deny"); err != nil || !ok {
		t.Fatalf("过期代驳 = %v, %v", ok, err)
	}
	if ok, err := f.svc.DecideSystem(context.Background(), id3, "maybe", "x"); !errors.Is(err, ErrBadDecision) || ok {
		t.Fatalf("非法决策 = %v, %v", ok, err)
	}
}

func TestDecideInvalidDecision(t *testing.T) {
	f := newFixture(t, nil)
	id := f.submit(t, baseSubmitInput())
	if ok, err := f.svc.Decide(context.Background(), id, StatusExpired, "bob", "", ""); !errors.Is(err, ErrBadDecision) || ok {
		t.Fatalf("err = %v, ok=%v", err, ok)
	}
}

func TestAwaitDecisionWakesOnDecision(t *testing.T) {
	f := newFixture(t, nil)
	id := f.submit(t, baseSubmitInput())

	type result struct {
		d   Decision
		err error
	}
	done := make(chan result, 1)
	go func() {
		d, err := f.svc.AwaitDecision(context.Background(), id)
		done <- result{d, err}
	}()
	waitSubscribed(t, f.svc, id)
	if ok, err := f.svc.Decide(context.Background(), id, StatusApproved, "bob", "", ""); err != nil || !ok {
		t.Fatalf("Decide = %v, %v", ok, err)
	}
	select {
	case got := <-done:
		if got.err != nil || got.d.Status != StatusApproved || got.d.Token == "" {
			t.Fatalf("await = %+v, %v", got.d, got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AwaitDecision 未被唤醒")
	}
}

func waitSubscribed(t *testing.T, s *Service, id string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		n := len(s.waiters[id])
		s.mu.Unlock()
		if n > 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("AwaitDecision 未完成订阅")
}

func TestAwaitDecisionContextCancel(t *testing.T) {
	f := newFixture(t, nil)
	id := f.submit(t, baseSubmitInput())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := f.svc.AwaitDecision(ctx, id); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
}

func TestSweepExpired(t *testing.T) {
	f := newFixture(t, nil)
	f.svc.SetTimeout(time.Minute)
	idDue := f.submit(t, baseSubmitInput())
	f.svc.SetTimeout(time.Hour)
	idFuture := f.submit(t, baseSubmitInput())
	f.clock.Advance(2 * time.Minute)

	n, err := f.svc.SweepExpired(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("SweepExpired = %d, %v, want 1", n, err)
	}
	if got := f.store.row(t, idDue).Status; got != StatusExpired {
		t.Errorf("due status = %q", got)
	}
	if got := f.store.row(t, idFuture).Status; got != StatusPending {
		t.Errorf("future status = %q", got)
	}
	evs := f.events.list()
	if len(evs) != 1 || evs[0].Type != EventExpired || evs[0].ApprovalID != idDue {
		t.Errorf("events = %+v", evs)
	}
	if n, err := f.svc.SweepExpired(context.Background()); err != nil || n != 0 {
		t.Fatalf("second sweep = %d, %v", n, err)
	}

	f.store.mu.Lock()
	f.store.expireDueErr = errors.New("db down")
	f.store.mu.Unlock()
	if _, err := f.svc.SweepExpired(context.Background()); err == nil {
		t.Fatal("扫描错误未返回")
	}
}

func TestCancel(t *testing.T) {
	f := newFixture(t, nil)
	id := f.submit(t, baseSubmitInput())
	ok, err := f.svc.Cancel(context.Background(), id, "alice", "不再需要")
	if err != nil || !ok {
		t.Fatalf("Cancel = %v, %v", ok, err)
	}
	r := f.store.row(t, id)
	if r.Status != StatusCancelled || r.DecidedBy != "alice" || r.DecisionNote != "不再需要" {
		t.Errorf("row = %+v", r)
	}
	if ok, err := f.svc.Cancel(context.Background(), id, "alice", "again"); err != nil || ok {
		t.Fatalf("second Cancel = %v, %v", ok, err)
	}
	evs := f.events.list()
	if len(evs) != 1 || evs[0].Status != StatusCancelled || evs[0].Type != EventDecided {
		t.Errorf("events = %+v", evs)
	}
}

func TestAskUserSubmit(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.AskTimeout = 2 * time.Minute })
	id, err := f.svc.AskUserSubmit(context.Background(), AskUserInput{
		CaseID: "cs-7", SessionID: "sess-1", StepID: 9,
		Question: "继续吗？", Options: []string{"继续", "停止"}, Assumption: "默认继续",
	})
	if err != nil {
		t.Fatalf("AskUserSubmit: %v", err)
	}
	r := f.store.row(t, id)
	if r.RequestType != AskUserRequestType || r.RiskLevel != 1 || r.CreatedBy != "" {
		t.Errorf("row = %+v", r)
	}
	if !r.ExpiresAt.Equal(f.clock.Now().Add(2 * time.Minute)) {
		t.Errorf("expires_at = %v", r.ExpiresAt)
	}
	var payload struct {
		Kind       string   `json:"kind"`
		Question   string   `json:"question"`
		Options    []string `json:"options"`
		Assumption string   `json:"assumption"`
		TextRender string   `json:"text_render"`
	}
	if err := json.Unmarshal(r.PlanReport, &payload); err != nil {
		t.Fatalf("payload: %v (%s)", err, r.PlanReport)
	}
	if payload.Kind != AskUserRequestType || payload.Question != "继续吗？" ||
		len(payload.Options) != 2 || payload.Assumption != "默认继续" {
		t.Errorf("payload = %+v", payload)
	}
	if payload.TextRender != "继续吗？\n1. 继续\n2. 停止" {
		t.Errorf("text_render = %q", payload.TextRender)
	}
	if _, err := f.svc.AskUserSubmit(context.Background(), AskUserInput{CaseID: "cs"}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("缺 question err = %v", err)
	}
}

func TestHasSamePlanHash(t *testing.T) {
	f := newFixture(t, nil)
	id := f.submit(t, baseSubmitInput())
	r := f.store.row(t, id)
	same, err := f.svc.HasSamePlanHash(context.Background(), "cs-7", r.PlanHash)
	if err != nil || !same {
		t.Fatalf("HasSamePlanHash = %v, %v", same, err)
	}
	same, err = f.svc.HasSamePlanHash(context.Background(), "cs-7", "other")
	if err != nil || same {
		t.Fatalf("other hash = %v, %v", same, err)
	}
}

func TestExecutionTokenSurvivesWallClockExpiry(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.Timeout = time.Minute })
	id := f.submit(t, baseSubmitInput())
	if ok, err := f.svc.Decide(context.Background(), id, StatusApproved, "bob", "", ""); err != nil || !ok {
		t.Fatalf("Decide = %v, %v", ok, err)
	}
	dec, err := f.svc.AwaitDecision(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	f.clock.Advance(24 * time.Hour) // 越过审批 deadline 很久
	if ok, err := f.svc.ConsumeToken(context.Background(), id, dec.Token); err != nil || !ok {
		t.Fatalf("批准后晚到的核销 = %v, %v（凭据生命周期应由行状态+一次性核销决定）", ok, err)
	}
}

func TestConcurrentDecideExactlyOneWins(t *testing.T) {
	f := newFixture(t, nil)
	id := f.submit(t, baseSubmitInput())

	const n = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for k := 0; k < n; k++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := f.svc.Decide(context.Background(), id, StatusApproved, "bob", "", "")
			if err == nil && ok {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Errorf("并发批准成功数 = %d, want 1", wins)
	}
	if f.events.len() != 1 {
		t.Errorf("事件数 = %d, want 1", f.events.len())
	}
	if got := f.store.row(t, id).Status; got != StatusApproved {
		t.Errorf("status = %q", got)
	}
}

func TestSecretEmptyGenerated(t *testing.T) {
	store := newMemStore()
	svc, err := New(Config{Store: store, Timeout: time.Hour})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	id, err := svc.Submit(context.Background(), baseSubmitInput())
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := svc.Decide(context.Background(), id, StatusApproved, "bob", "", ""); err != nil || !ok {
		t.Fatalf("Decide = %v, %v", ok, err)
	}
	dec, err := svc.AwaitDecision(context.Background(), id)
	if err != nil || dec.Token == "" {
		t.Fatalf("decision = %+v, %v", dec, err)
	}
	if ok, err := svc.ConsumeToken(context.Background(), id, dec.Token); err != nil || !ok {
		t.Fatalf("ConsumeToken = %v, %v", ok, err)
	}
}

func TestStoreErrorsPropagate(t *testing.T) {
	f := newFixture(t, nil)
	id := f.submit(t, baseSubmitInput())

	f.store.mu.Lock()
	f.store.decideErr = errors.New("write failed")
	f.store.mu.Unlock()
	if _, err := f.svc.Decide(context.Background(), id, StatusApproved, "bob", "", ""); err == nil {
		t.Fatal("Decide 的存储错误未透出")
	}

	f.store.mu.Lock()
	f.store.decideErr = nil
	f.store.getErr = errors.New("read failed")
	f.store.mu.Unlock()
	if _, err := f.svc.AwaitDecision(context.Background(), id); err == nil {
		t.Fatal("AwaitDecision 的读取错误未透出")
	}
}
