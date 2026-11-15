package approval

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yi-nology/gopkg/tokenx"
)

// 执行凭据载荷绑定键（tokenx.Claims）。
const (
	ClaimApprovalID = "approval_id"
	ClaimCaseID     = "case_id"
	ClaimPlanHash   = "plan_hash"
	ClaimExpiresAt  = "expires_at"
)

// FastTrack 快速通道：风险 ≤ MaxRisk 的审批单改走短超时档。只改超时档，
// 不改决策语义——超时仍 deny by default（红线不回退）。
type FastTrack struct {
	Timeout time.Duration
	MaxRisk int
}

// Config 服务装配。
type Config struct {
	Store     Store
	Publisher Publisher // 可 nil（不发布事件）

	// Secret 执行凭据 HMAC 密钥。空 = 启动期生成随机密钥：重启后未消费的
	// 旧凭据全部校验失败（fail-closed，与 bianque 同口径）。
	Secret string

	Timeout                 time.Duration
	AskTimeout              time.Duration
	FastTrack               *FastTrack
	RequireSeparateApprover bool
	PollInterval            time.Duration
	Now                     func() time.Time
}

// Service 审批流状态机。并发安全；配置项可运行时热更新（Set* 方法）。
type Service struct {
	store  Store
	pub    Publisher
	secret []byte
	now    func() time.Time
	poll   time.Duration

	settingsMu      sync.RWMutex
	timeout         time.Duration
	askTimeout      time.Duration
	fast            *FastTrack
	requireSeparate bool

	mu      sync.Mutex
	waiters map[string][]chan struct{}
}

// New 构造服务。Store 必填；Secret 为空时生成随机密钥（进程重启即失效）。
func New(cfg Config) (*Service, error) {
	if cfg.Store == nil {
		return nil, ErrNoStore
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.AskTimeout <= 0 {
		cfg.AskTimeout = DefaultAskTimeout
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = DefaultPollInterval
	}
	secret := cfg.Secret
	if secret == "" {
		generated, err := randomHex(32)
		if err != nil {
			return nil, err
		}
		secret = generated
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	s := &Service{
		store:           cfg.Store,
		pub:             cfg.Publisher,
		secret:          []byte(secret),
		now:             nowFn,
		poll:            cfg.PollInterval,
		timeout:         cfg.Timeout,
		askTimeout:      cfg.AskTimeout,
		requireSeparate: cfg.RequireSeparateApprover,
		waiters:         map[string][]chan struct{}{},
	}
	if cfg.FastTrack != nil {
		ft := normalizeFastTrack(*cfg.FastTrack)
		s.fast = &ft
	}
	return s, nil
}

// normalizeFastTrack 缺省值归一（短档 5m、仅 LOW）。
func normalizeFastTrack(ft FastTrack) FastTrack {
	if ft.Timeout <= 0 {
		ft.Timeout = DefaultFastTrackTimeout
	}
	if ft.MaxRisk <= 0 {
		ft.MaxRisk = DefaultFastTrackMaxRisk
	}
	return ft
}

// SetTimeout 运行时改审批默认超时（进行中单据不受影响，逐单创建时读）。
func (s *Service) SetTimeout(d time.Duration) {
	if d <= 0 {
		return
	}
	s.settingsMu.Lock()
	s.timeout = d
	s.settingsMu.Unlock()
}

// SetAskTimeout 运行时改 ask_user 窗口（≤0 忽略）。
func (s *Service) SetAskTimeout(d time.Duration) {
	if d <= 0 {
		return
	}
	s.settingsMu.Lock()
	s.askTimeout = d
	s.settingsMu.Unlock()
}

// SetFastTrack 运行时改快速通道；enabled=false 摘除。缺省归一与构造同。
func (s *Service) SetFastTrack(enabled bool, timeout time.Duration, maxRisk int) {
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	if !enabled {
		s.fast = nil
		return
	}
	ft := normalizeFastTrack(FastTrack{Timeout: timeout, MaxRisk: maxRisk})
	s.fast = &ft
}

// SetRequireSeparateApprover 运行时改审批人≠提审人开关。
func (s *Service) SetRequireSeparateApprover(v bool) {
	s.settingsMu.Lock()
	s.requireSeparate = v
	s.settingsMu.Unlock()
}

type settings struct {
	timeout         time.Duration
	askTimeout      time.Duration
	fast            *FastTrack
	requireSeparate bool
}

func (s *Service) snapshot() settings {
	s.settingsMu.RLock()
	defer s.settingsMu.RUnlock()
	snap := settings{
		timeout:         s.timeout,
		askTimeout:      s.askTimeout,
		requireSeparate: s.requireSeparate,
	}
	if s.fast != nil {
		ft := *s.fast
		snap.fast = &ft
	}
	return snap
}

// SubmitInput 提审输入。PlanReport 为空按 "{}" 快照（仍参与 plan_hash）。
type SubmitInput struct {
	CaseID            string
	SessionID         string
	StepID            uint64
	RequestType       string
	RiskLevel         int
	PlanReport        []byte
	LLMRiskAssessment []byte
	CreatedBy         string // 提审人（审批分离基准；空=无身份）
}

// Submit 创建审批单（pending + expires_at）。risk ≤ 快速通道阈值时走短
// 超时档；其余用默认档。返回新审批单 ID。
func (s *Service) Submit(ctx context.Context, in SubmitInput) (string, error) {
	if strings.TrimSpace(in.CaseID) == "" || strings.TrimSpace(in.RequestType) == "" {
		return "", fmt.Errorf("%w: case_id/request_type 不能为空", ErrInvalidInput)
	}
	snap := s.snapshot()
	now := s.now()
	timeout := snap.timeout
	if snap.fast != nil && in.RiskLevel <= snap.fast.MaxRisk {
		timeout = snap.fast.Timeout
	}
	plan := normalizeJSON(in.PlanReport)
	assessment := normalizeJSON(in.LLMRiskAssessment)
	id, err := newApprovalID("appr", in.CaseID)
	if err != nil {
		return "", err
	}
	r := &Request{
		ApprovalID:        id,
		CaseID:            in.CaseID,
		SessionID:         in.SessionID,
		StepID:            in.StepID,
		PlanReport:        plan,
		PlanHash:          sha256Hex(string(plan)),
		RequestType:       in.RequestType,
		RiskLevel:         in.RiskLevel,
		LLMRiskAssessment: assessment,
		Status:            StatusPending,
		CreatedBy:         in.CreatedBy,
		ExpiresAt:         now.Add(timeout),
		CreatedAt:         now,
	}
	if err := s.store.Create(ctx, r); err != nil {
		return "", err
	}
	return r.ApprovalID, nil
}

// AskUserInput ask_user 提问卡输入。
type AskUserInput struct {
	CaseID     string
	SessionID  string
	StepID     uint64
	Question   string
	Options    []string
	Assumption string
}

// AskUserSubmit 创建 ask_user 提问卡行：与变更审批同管道（sweep/等待/
// deny-by-default/决策事件全复用），差异只有三点——RequestType 分族、
// 窗口用 AskTimeout、CreatedBy 恒空（引擎自提，无自提自批面）。风险恒 1，
// 不触 L4 双确认/代批红线。
func (s *Service) AskUserSubmit(ctx context.Context, in AskUserInput) (string, error) {
	if strings.TrimSpace(in.CaseID) == "" || strings.TrimSpace(in.Question) == "" {
		return "", fmt.Errorf("%w: case_id/question 不能为空", ErrInvalidInput)
	}
	snap := s.snapshot()
	now := s.now()
	options := in.Options
	if options == nil {
		options = []string{}
	}
	payload := struct {
		Kind       string   `json:"kind"`
		Question   string   `json:"question"`
		Options    []string `json:"options"`
		Assumption string   `json:"assumption"`
		TextRender string   `json:"text_render"`
	}{
		Kind:       AskUserRequestType,
		Question:   in.Question,
		Options:    options,
		Assumption: in.Assumption,
		TextRender: RenderAskUserText(in.Question, options),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("approval: 提问载荷编码失败: %w", err)
	}
	id, err := newApprovalID("ask", in.CaseID)
	if err != nil {
		return "", err
	}
	r := &Request{
		ApprovalID:        id,
		CaseID:            in.CaseID,
		SessionID:         in.SessionID,
		StepID:            in.StepID,
		PlanReport:        raw,
		PlanHash:          sha256Hex(string(raw)),
		RequestType:       AskUserRequestType,
		RiskLevel:         1,
		LLMRiskAssessment: []byte("{}"),
		Status:            StatusPending,
		ExpiresAt:         now.Add(snap.askTimeout),
		CreatedAt:         now,
	}
	if err := s.store.Create(ctx, r); err != nil {
		return "", err
	}
	return r.ApprovalID, nil
}

// RenderAskUserText text_render 的 IM 预留纯文本形态：问题 + 编号选项。
func RenderAskUserText(question string, options []string) string {
	var b strings.Builder
	b.WriteString(question)
	for i, o := range options {
		b.WriteString("\n")
		b.WriteString(strconv.Itoa(i + 1))
		b.WriteString(". ")
		b.WriteString(o)
	}
	return b.String()
}

// Decide 审批决策（人工入口）：仅 pending 可迁移；approve 时签发一次性
// 执行凭据（明文只经 AwaitDecision 交给引擎，行上只存哈希）。
//
// 返回 false 且 err == nil = CAS 竞态失败（他方已决策/已过期），调用方按
// 409/回退处理。L4 首次确认是一条「非终态」的成功路径：返回 true 但单据
// 仍 pending。
func (s *Service) Decide(ctx context.Context, approvalID string, decision Status, by, note, confirmPhrase string) (bool, error) {
	if !ValidDecision(decision) {
		return false, fmt.Errorf("%w: %q（approved|rejected）", ErrBadDecision, decision)
	}
	snap := s.snapshot()
	r, err := s.store.Get(ctx, approvalID)
	if err != nil {
		return false, err
	}
	// 审批人≠提审人：只约束 approve 方向（自批高危变更正是要堵的洞）；
	// reject 是 deny 方向恒允许。匿名期 CreatedBy 空时分离不生效。
	if decision == StatusApproved && snap.requireSeparate && r.CreatedBy != "" && by == r.CreatedBy {
		return false, fmt.Errorf("%w: 提审人 %q 不得批准自己的方案，请由其他操作者决策", ErrSeparateApprover, r.CreatedBy)
	}
	now := s.now()
	if ExpiredFor(r, decision, now) {
		s.expireOne(ctx, approvalID)
		return false, fmt.Errorf("%w: 不可批准；可重新发起方案", ErrExpired)
	}
	tokenHash := ""
	if decision == StatusApproved {
		if r.RiskLevel >= RiskL4 {
			if r.L4FirstAt == nil {
				if confirmPhrase != L4Phrase(r.RequestType) {
					// 错误提示不得回显正确短语（自动重试读到答案会架空双确认）。
					return false, fmt.Errorf("%w: L4 高危变更需携带确认短语再次提交", ErrL4Phrase)
				}
				ok, err := s.store.MarkL4First(ctx, approvalID, now)
				if err != nil {
					return false, err
				}
				if !ok {
					// 竞态：他方可能刚完成首确认（视同受理），也可能已决策。
					cur, gerr := s.store.Get(ctx, approvalID)
					if gerr != nil {
						return false, gerr
					}
					if cur.Status == StatusPending && cur.L4FirstAt != nil {
						return true, nil
					}
					return false, nil
				}
				s.notify(approvalID)
				return true, nil // 首次确认受理（非终态）
			}
			// 已有首确认：第二次批准必须精确携带确认短语。
			if confirmPhrase != L4Phrase(r.RequestType) {
				return false, fmt.Errorf("%w: L4 高危变更二次确认短语不匹配", ErrL4Phrase)
			}
		}
		tokenHash, err = s.mintTokenHash(r)
		if err != nil {
			return false, err
		}
	}
	return s.commitDecision(ctx, approvalID, decision, by, note, tokenHash, now)
}

// DecideSystem 策略代批（审计门放行的自动决策）：审批单/事件/凭据与人工
// 决策同一语义，仅 decided_by=system_policy。L4 永不代批；过期单不得批准
// （与 Decide 同一 deny-by-default 红线）。
func (s *Service) DecideSystem(ctx context.Context, approvalID string, decision Status, reason string) (bool, error) {
	if !ValidDecision(decision) {
		return false, fmt.Errorf("%w: %q（approved|rejected）", ErrBadDecision, decision)
	}
	r, err := s.store.Get(ctx, approvalID)
	if err != nil {
		return false, err
	}
	if r.RiskLevel >= RiskL4 {
		return false, fmt.Errorf("%w（须人工双确认）", ErrL4System)
	}
	now := s.now()
	if ExpiredFor(r, decision, now) {
		s.expireOne(ctx, approvalID)
		return false, fmt.Errorf("%w: 不可代批", ErrExpired)
	}
	tokenHash := ""
	if decision == StatusApproved {
		tokenHash, err = s.mintTokenHash(r)
		if err != nil {
			return false, err
		}
	}
	return s.commitDecision(ctx, approvalID, decision, SystemDecider, "策略代批: "+reason, tokenHash, now)
}

// Cancel 取消待批审批单（用户取消会话的 waiting_approval 分支）：仅
// pending 可取消；false = 已被决策/过期（他方先行）。
func (s *Service) Cancel(ctx context.Context, approvalID, by, note string) (bool, error) {
	ok, err := s.store.Cancel(ctx, approvalID, by, note, s.now())
	if err != nil || !ok {
		return ok, err
	}
	s.settle(ctx, approvalID, EventDecided, by)
	return true, nil
}

// Decision AwaitDecision 的终态结果。approved 时 Token 是执行凭据明文。
type Decision struct {
	Status Status
	Token  string
	Note   string
}

// AwaitDecision 阻塞等待决策（通知 + 轮询双通道）；pending 且已到期的行
// 先惰性收敛为 expired（sweep 未跑到时的兜底）。ctx 取消返回 ctx.Err()。
func (s *Service) AwaitDecision(ctx context.Context, approvalID string) (Decision, error) {
	ch := s.subscribe(approvalID)
	defer s.unsubscribe(approvalID, ch)
	ticker := time.NewTicker(s.poll)
	defer ticker.Stop()

	for {
		r, err := s.store.Get(ctx, approvalID)
		if err != nil {
			return Decision{}, err
		}
		if r.Status == StatusPending && !r.ExpiresAt.After(s.now()) {
			s.expireOne(ctx, approvalID)
			continue
		}
		if r.Status != StatusPending {
			d := Decision{Status: r.Status, Note: r.DecisionNote}
			if r.Status == StatusApproved {
				tok, err := s.signToken(r)
				if err != nil {
					return Decision{}, err
				}
				d.Token = tok
			}
			return d, nil
		}
		select {
		case <-ctx.Done():
			return Decision{}, ctx.Err()
		case <-ticker.C:
		case <-ch:
		}
	}
}

// ConsumeToken 一次性核销执行凭据：先 tokenx 验签+载荷绑定复验，再 DB/CAS
// 一次性核销。invalid token/非 approved/已核销一律返回 (false, nil)——凭据
// 面不区分失败原因（不泄露行状态给持有猜测令牌的一方）。
func (s *Service) ConsumeToken(ctx context.Context, approvalID, token string) (bool, error) {
	r, err := s.store.Get(ctx, approvalID)
	if err != nil {
		return false, err
	}
	if r.Status != StatusApproved {
		return false, nil
	}
	// exp 绑定审批窗口；VerifyAt 用 expires_at 自身作「当前时刻」，把 exp
	// 变成窗口绑定而不是执行墙钟——凭据生命周期由行状态+一次性核销决定。
	if _, err := tokenx.VerifyAt(string(s.secret), token, tokenClaims(r), r.ExpiresAt); err != nil {
		return false, nil
	}
	return s.store.ConsumeToken(ctx, approvalID, sha256Hex(token))
}

// HasSamePlanHash 防驳回后原样重提。
func (s *Service) HasSamePlanHash(ctx context.Context, caseID, planHash string) (bool, error) {
	return s.store.ExistsPlanHash(ctx, caseID, planHash)
}

// Get 读取审批单（详情/适配器用）。
func (s *Service) Get(ctx context.Context, approvalID string) (*Request, error) {
	return s.store.Get(ctx, approvalID)
}

// SweepExpired 周期收敛到期待批单（宿主后台轮调用，建议 leader 选主）。
// 返回本轮实际迁移的单数；批次扫描错误原样返回，单行 settle 失败不阻塞
// 其余行（事件是观测面，不改变已落定的 denied 状态）。
func (s *Service) SweepExpired(ctx context.Context) (int, error) {
	ids, err := s.store.ExpireDue(ctx, s.now())
	if err != nil {
		return 0, err
	}
	for _, id := range ids {
		s.settle(ctx, id, EventExpired, "system")
	}
	return len(ids), nil
}

// commitDecision 落库后收尾（CAS → settle）；两决策入口共用。
func (s *Service) commitDecision(ctx context.Context, approvalID string, decision Status, by, note, tokenHash string, now time.Time) (bool, error) {
	ok, err := s.store.Decide(ctx, approvalID, decision, by, note, tokenHash, now)
	if err != nil || !ok {
		return ok, err
	}
	s.settle(ctx, approvalID, EventDecided, by)
	return true, nil
}

// settle 决策落定收尾：停表由宿主负责（无 timer），本包做「重读 → 事件 →
// 唤醒 waiter」。重读用 detached 上下文：决策已落库，事件不得因请求 ctx
// 取消而丢。
func (s *Service) settle(ctx context.Context, approvalID, eventType, by string) {
	sctx := context.WithoutCancel(ctx)
	if r, err := s.store.Get(sctx, approvalID); err == nil {
		s.publish(Event{
			Type:        eventType,
			ApprovalID:  r.ApprovalID,
			CaseID:      r.CaseID,
			SessionID:   r.SessionID,
			StepID:      r.StepID,
			RequestType: r.RequestType,
			RiskLevel:   r.RiskLevel,
			Status:      r.Status,
			DecidedBy:   by,
			Note:        r.DecisionNote,
			CreatedBy:   r.CreatedBy,
			At:          s.now(),
		})
	}
	s.notify(approvalID)
}

func (s *Service) publish(ev Event) {
	if s.pub == nil {
		return
	}
	s.pub.Publish(ev)
}

// expireOne 单行惰性收敛 + 事件；CAS 失败（他方已决策）静默跳过。
func (s *Service) expireOne(ctx context.Context, approvalID string) {
	ok, err := s.store.Expire(ctx, approvalID)
	if err != nil || !ok {
		return
	}
	s.settle(ctx, approvalID, EventExpired, "system")
}

// signToken 确定性执行凭据：同审批行字段签出逐字节相同的 tokenx 令牌（多
// 副本可复算）。
func (s *Service) signToken(r *Request) (string, error) {
	tok, err := tokenx.Sign(string(s.secret), tokenClaims(r), r.ExpiresAt)
	if err != nil {
		return "", fmt.Errorf("approval: 执行凭据签发失败: %w", err)
	}
	return tok, nil
}

func (s *Service) mintTokenHash(r *Request) (string, error) {
	tok, err := s.signToken(r)
	if err != nil {
		return "", err
	}
	return sha256Hex(tok), nil
}

// tokenClaims 执行凭据的载荷绑定：审批行四字段任一改动即验签失败。
func tokenClaims(r *Request) tokenx.Claims {
	return tokenx.Claims{
		ClaimApprovalID: r.ApprovalID,
		ClaimCaseID:     r.CaseID,
		ClaimPlanHash:   r.PlanHash,
		ClaimExpiresAt:  strconv.FormatInt(r.ExpiresAt.Unix(), 10),
	}
}

func (s *Service) subscribe(approvalID string) chan struct{} {
	ch := make(chan struct{})
	s.mu.Lock()
	s.waiters[approvalID] = append(s.waiters[approvalID], ch)
	s.mu.Unlock()
	return ch
}

func (s *Service) unsubscribe(approvalID string, ch chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.waiters[approvalID]
	for i, c := range list {
		if c == ch {
			s.waiters[approvalID] = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(s.waiters[approvalID]) == 0 {
		delete(s.waiters, approvalID)
	}
}

func (s *Service) notify(approvalID string) {
	s.mu.Lock()
	list := s.waiters[approvalID]
	delete(s.waiters, approvalID)
	s.mu.Unlock()
	for _, ch := range list {
		close(ch)
	}
}

// normalizeJSON 空载荷按 "{}" 快照（plan_hash 仍确定）；拷贝一份避免调用
// 方在落库后改内存。
func normalizeJSON(raw []byte) []byte {
	if len(bytes.TrimSpace(raw)) == 0 {
		return []byte("{}")
	}
	out := make([]byte, len(raw))
	copy(out, raw)
	return out
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func newApprovalID(prefix, caseID string) (string, error) {
	suffix, err := randomHex(4)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-%s-%s", prefix, caseID, suffix), nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("approval: 系统熵源故障: %w", err)
	}
	return hex.EncodeToString(b), nil
}
