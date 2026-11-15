package approvalflow

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/yi-nology/gopkg/tokenx"
)

// Status 审批单状态（也是决策值 approved/rejected）。
type Status string

const (
	// StatusPending 待决策。
	StatusPending Status = "pending"
	// StatusApproved 已批准（可签发/核销一次性执行凭据）。
	StatusApproved Status = "approved"
	// StatusRejected 已驳回。
	StatusRejected Status = "rejected"
	// StatusExpired 超时过期（deny by default）。
	StatusExpired Status = "expired"
	// StatusCancelled 提审方取消。
	StatusCancelled Status = "cancelled"
)

// RequestTypeAskUser ask_user 提问卡的行类型（引擎自提，非高危变更批准）。
const RequestTypeAskUser = "ask_user"

// SystemDecider 策略代批的决策人标识（审计口径）。
const SystemDecider = "system_policy"

const (
	defaultTimeout      = 30 * time.Minute
	defaultAskTimeout   = 5 * time.Minute
	defaultFastTimeout  = 5 * time.Minute
	defaultRemindAfter  = 10 * time.Minute
	defaultPollInterval = 200 * time.Millisecond
	remindLookback      = 24 * time.Hour
	remindLimit         = 20
	l4RiskLevel         = 4
)

// 哨兵错误（errors.Is 判定，消费方不要匹配错误文本）。
var (
	// ErrBadConfig 构造配置非法（store 为空/secret 为空/ask 窗口不短于审批窗）。
	ErrBadConfig = errors.New("approvalflow: 配置非法")
	// ErrInvalidDecision decision 不是 approved|rejected。
	ErrInvalidDecision = errors.New("approvalflow: decision 非法（approved|rejected）")
	// ErrSeparation 审批人等于提审人（审批分离红线）。
	ErrSeparation = errors.New("approvalflow: 审批分离：提审人不得批准自己的方案")
	// ErrExpired 审批单已过期，approve 被 deny-by-default 拒绝。
	ErrExpired = errors.New("approvalflow: 审批单已超时过期（deny by default）")
	// ErrL4Phrase L4 双确认短语缺失/不匹配。错误文本不含正确短语。
	ErrL4Phrase = errors.New("approvalflow: L4 高危变更需二次确认短语")
	// ErrL4System L4 高危变更不允许策略代批。
	ErrL4System = errors.New("approvalflow: L4 高危变更不允许策略代批")
	// ErrBadPlan 方案载荷不是合法 JSON。
	ErrBadPlan = errors.New("approvalflow: 方案载荷不是合法 JSON")
)

// Approval 审批单（宿主持久化形态）。所有时间字段由宿主存储原样保存；StepID
// 是不透明步骤标识（字符串化，避免绑定宿主的数值 ID 类型）。
type Approval struct {
	// ApprovalID 审批单号（主键；由 Submit/AskUserSubmit 生成，前缀 appr-/ask-）。
	ApprovalID string
	// CaseID 案例 id。
	CaseID string
	// SessionID 会话 id。
	SessionID string
	// StepID 触发审批的步骤标识（不透明）。
	StepID string
	// Plan 方案快照（任意合法 JSON；ask_user 为提问载荷）。
	Plan []byte
	// PlanHash sha256(Plan) 十六进制（防驳回后原样重提的锚点，也进执行凭据绑定）。
	PlanHash string
	// RequestType 方案类型（kill/restart/delete/...；ask_user 为 RequestTypeAskUser）。
	RequestType string
	// RiskLevel 风险档 1-4（终值；L4=4 触发双确认与代批禁令）。
	RiskLevel int
	// LLMRiskAssessment LLM 风险评估快照（空则落 "{}"）。
	LLMRiskAssessment []byte
	// Status 当前状态。
	Status Status
	// DecideTokenHash sha256(执行凭据)；明文只在审批响应与引擎内存中。
	DecideTokenHash string
	// L4FirstAt L4 双确认的首次批准时间；nil=尚未首次确认。
	L4FirstAt *time.Time
	// TokenUsedAt 执行凭据一次性核销时间；nil=未核销。
	TokenUsedAt *time.Time
	// DecidedBy 决策人（策略代批为 SystemDecider；过期收敛为 system）。
	DecidedBy string
	// CreatedBy 提审人（审批分离比对基准；空=创建期无身份，分离不生效）。
	CreatedBy string
	// DecisionNote 决策备注（ask_user 的答案文本也走这里）。
	DecisionNote string
	// ExpiresAt 审批窗口截止时刻（deny-by-default 判据）。
	ExpiresAt time.Time
	// DecidedAt 决策/过期/取消落定时刻。
	DecidedAt *time.Time
	// CreatedAt 创建时刻。
	CreatedAt time.Time
}

// RequestEvent 未通知的审批请求事件（宿主事件表的一行投影）。ID 是宿主事件
// 行主键，用于推送后落 notified 标记；ApprovalID 为空的历史/无法归属事件由
// 服务层直接落标记收敛扫描集。
type RequestEvent struct {
	ID         uint64
	ApprovalID string
}

// Store 审批单存储与一次性核销 CAS。**每个迁移方法都必须是原子条件更新**，
// 返回 true 表示本次调用赢得了迁移（RowsAffected>0）；false 表示他方先行
// （已决策/已过期/已核销），服务层按竞态失败返回。方法注释里的条件就是
// 宿主 SQL 的 WHERE 子句。
type Store interface {
	// Create 插入审批单（ApprovalID 冲突应返回错误）。
	Create(ctx context.Context, a *Approval) error
	// Get 按 approval_id 读取；不存在返回错误（宿主可包装自己的 404 语义）。
	Get(ctx context.Context, approvalID string) (*Approval, error)
	// Decide CAS：WHERE approval_id=? AND status='pending'，更新
	// status/decided_by/decision_note/decided_at；tokenHash 非空（approve）时
	// 必须额外 AND expires_at > now（并发窗口的 deny-by-default 双保险），并写
	// decide_token_hash。
	Decide(ctx context.Context, approvalID string, decision Status, by, note, tokenHash string) (bool, error)
	// CancelPending CAS：WHERE approval_id=? AND status='pending'，更新
	// status='cancelled'/decided_by/decision_note/decided_at。
	CancelPending(ctx context.Context, approvalID, by, note string) (bool, error)
	// Expire CAS：WHERE approval_id=? AND status='pending'，更新 status='expired'。
	Expire(ctx context.Context, approvalID string) (bool, error)
	// Due 返回 status='pending' AND expires_at <= now 的 approval_id 列表（只读，
	// 不改状态；服务层逐条 Expire 以确保每个到期单都发事件/唤醒 waiter）。
	Due(ctx context.Context, now time.Time) ([]string, error)
	// ConsumeToken 一次性 CAS：WHERE approval_id=? AND status='approved'
	// AND decide_token_hash=? AND token_used_at IS NULL，更新 token_used_at=now。
	ConsumeToken(ctx context.Context, approvalID, tokenHash string) (bool, error)
	// MarkL4First CAS：WHERE approval_id=? AND status='pending'
	// AND l4_first_at IS NULL，更新 l4_first_at=at。
	MarkL4First(ctx context.Context, approvalID string, at time.Time) (bool, error)
	// UnnotifiedRequests 返回 approval_requested 事件中 created_at >= since、
	// notified_at IS NULL 的前 limit 条（宿主可加索引）。
	UnnotifiedRequests(ctx context.Context, since time.Time, limit int) ([]RequestEvent, error)
	// MarkRequestNotified 落事件已推送标记（推送调用之后调用；宁可崩溃窗口重推
	// 一次，不可标记先行漏推）。
	MarkRequestNotified(ctx context.Context, eventID uint64, at time.Time) error
}

// EventType 终态事件类型。
type EventType string

const (
	// EventDecided 人工/策略决策落定。
	EventDecided EventType = "approval_decided"
	// EventExpired 超时过期落定。
	EventExpired EventType = "approval_expired"
	// EventCancelled 提审方取消落定。
	EventCancelled EventType = "approval_cancelled"
)

// Event 终态事件（Publisher 的载荷）。Note 取落定后的 DecisionNote（ask_user
// 的答案文本在此）。
type Event struct {
	Type        EventType
	ApprovalID  string
	CaseID      string
	SessionID   string
	StepID      string
	RequestType string
	RiskLevel   int
	Status      Status
	By          string
	Note        string
	At          time.Time
}

// Publisher 终态事件出口（宿主实现：事件总线/审计/SSE）。可为 nil=不发布。
// 服务层在迁移成功后以脱离请求取消的上下文调用。
type Publisher interface {
	Publish(ctx context.Context, ev Event)
}

// Notifier 审批请求推送出口（宿主实现：IM 卡片文案与通道、Webhook 等）。可为
// nil=不推送；Submit/AskUserSubmit 创建后调用一次，SweepUnnotifiedRequests 对
// 过阈值未决单补推。
type Notifier interface {
	ApprovalRequested(ctx context.Context, a *Approval)
}

// FastTrack 快速通道：risk <= MaxRisk 的审批单走 Timeout 档，只改超时档，
// 不改任何决策语义。Timeout<=0 落 5 分钟，MaxRisk<=0 落 1。
type FastTrack struct {
	Timeout time.Duration
	MaxRisk int
}

// Config 服务配置。Timeout<=0 落 30 分钟；AskTimeout<=0 落 5 分钟且必须严格
// 短于 Timeout（硬约束，否则构造失败）；RemindAfter<=0 落 10 分钟；
// PollInterval<=0 落 200ms。Secret 必填（fail-closed）。TokenGrace 追加在执行
// 凭据 exp 上（0=凭据与审批窗口同刻到期），宿主可给批准后执行留余量。
type Config struct {
	Timeout                 time.Duration
	Secret                  string
	RequireSeparateApprover bool
	AskTimeout              time.Duration
	FastTrack               *FastTrack
	RemindAfter             time.Duration
	PollInterval            time.Duration
	TokenGrace              time.Duration
}

// Service 审批流状态机（并发安全）。字段在构造后只读；定时器/唤醒表由 mu 保护。
type Service struct {
	store     Store
	publisher Publisher
	notifier  Notifier

	secret          string
	timeout         time.Duration
	askTimeout      time.Duration
	requireSeparate bool
	fast            *FastTrack
	remindAfter     time.Duration
	pollInterval    time.Duration
	tokenGrace      time.Duration

	mu      sync.Mutex
	timers  map[string]*time.Timer
	waiters map[string][]chan struct{}
}

// New 构造审批流服务。store 为空、Secret 为空、AskTimeout >= Timeout 均返回
// 包装 [ErrBadConfig] 的错误（不静默降级）。publisher/notifier 可为 nil。
func New(store Store, publisher Publisher, cfg Config) (*Service, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: store 不能为空", ErrBadConfig)
	}
	if cfg.Secret == "" {
		return nil, fmt.Errorf("%w: secret 不能为空（fail-closed）", ErrBadConfig)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	askTimeout := cfg.AskTimeout
	if askTimeout <= 0 {
		askTimeout = defaultAskTimeout
	}
	if askTimeout >= timeout {
		return nil, fmt.Errorf("%w: ask_user 窗口（%s）必须严格短于审批窗口（%s）", ErrBadConfig, askTimeout, timeout)
	}
	remindAfter := cfg.RemindAfter
	if remindAfter <= 0 {
		remindAfter = defaultRemindAfter
	}
	pollInterval := cfg.PollInterval
	if pollInterval <= 0 {
		pollInterval = defaultPollInterval
	}
	var fast *FastTrack
	if cfg.FastTrack != nil {
		ft := *cfg.FastTrack
		if ft.Timeout <= 0 {
			ft.Timeout = defaultFastTimeout
		}
		if ft.MaxRisk <= 0 {
			ft.MaxRisk = 1
		}
		fast = &ft
	}
	grace := cfg.TokenGrace
	if grace < 0 {
		grace = 0
	}
	return &Service{
		store:           store,
		publisher:       publisher,
		secret:          cfg.Secret,
		timeout:         timeout,
		askTimeout:      askTimeout,
		requireSeparate: cfg.RequireSeparateApprover,
		fast:            fast,
		remindAfter:     remindAfter,
		pollInterval:    pollInterval,
		tokenGrace:      grace,
		timers:          map[string]*time.Timer{},
		waiters:         map[string][]chan struct{}{},
	}, nil
}

// WithNotifier 挂审批请求推送出口（返回自身便于链式装配）。
func (s *Service) WithNotifier(n Notifier) *Service {
	s.notifier = n
	return s
}

// timeoutFor 按风险档选审批窗口：快速通道只改超时档，不改任何决策语义。
func (s *Service) timeoutFor(riskLevel int) time.Duration {
	if s.fast != nil && riskLevel <= s.fast.MaxRisk {
		return s.fast.Timeout
	}
	return s.timeout
}

// SubmitInput 提审入参。Plan 是任意合法 JSON 快照，PlanHash 由本包计算。
type SubmitInput struct {
	CaseID            string
	SessionID         string
	StepID            string
	Plan              []byte
	RequestType       string
	RiskLevel         int
	CreatedBy         string
	LLMRiskAssessment []byte
}

// Submit 创建 pending 审批单（ExpiresAt=now+窗口，快速通道按 risk 选档）、
// 注册进程内超时任务并触发一次请求推送。返回 approval_id。
func (s *Service) Submit(ctx context.Context, in SubmitInput) (string, error) {
	if in.CaseID == "" {
		return "", fmt.Errorf("%w: case_id 不能为空", ErrBadConfig)
	}
	plan, err := normalizePlan(in.Plan)
	if err != nil {
		return "", err
	}
	id, err := newID("appr-", in.CaseID)
	if err != nil {
		return "", err
	}
	now := time.Now()
	timeout := s.timeoutFor(in.RiskLevel)
	riskAssessment := in.LLMRiskAssessment
	if len(riskAssessment) == 0 {
		riskAssessment = []byte("{}")
	}
	a := &Approval{
		ApprovalID:        id,
		CaseID:            in.CaseID,
		SessionID:         in.SessionID,
		StepID:            in.StepID,
		Plan:              plan,
		PlanHash:          sha256Hex(plan),
		RequestType:       in.RequestType,
		RiskLevel:         in.RiskLevel,
		LLMRiskAssessment: riskAssessment,
		Status:            StatusPending,
		CreatedBy:         in.CreatedBy,
		ExpiresAt:         now.Add(timeout),
		CreatedAt:         now,
	}
	if err := s.store.Create(ctx, a); err != nil {
		return "", err
	}
	s.scheduleExpiry(a.ApprovalID, timeout)
	s.notifyRequested(ctx, a)
	return a.ApprovalID, nil
}

// AskUserInput ask_user 提问卡入参。
type AskUserInput struct {
	CaseID     string
	SessionID  string
	StepID     string
	Question   string
	Options    []string
	Assumption string
}

// askPrompt ask_user 行 Plan 的 JSON 形态（卡片文案由宿主渲染，不在此拼）。
type askPrompt struct {
	Kind       string   `json:"kind"`
	Question   string   `json:"question"`
	Options    []string `json:"options,omitempty"`
	Assumption string   `json:"assumption,omitempty"`
}

// AskUserSubmit 创建 ask_user 挂起卡行：与 Submit 同管道（sweep/AwaitDecision/
// deny-by-default/决策事件全复用），差异是窗口用 AskTimeout（严格短于审批窗）、
// RiskLevel=1、CreatedBy 恒空（引擎自提，无自批面）。返回 approval_id。
func (s *Service) AskUserSubmit(ctx context.Context, in AskUserInput) (string, error) {
	if in.CaseID == "" {
		return "", fmt.Errorf("%w: case_id 不能为空", ErrBadConfig)
	}
	payload, err := json.Marshal(askPrompt{
		Kind:       RequestTypeAskUser,
		Question:   in.Question,
		Options:    in.Options,
		Assumption: in.Assumption,
	})
	if err != nil {
		return "", fmt.Errorf("approvalflow: 提问载荷编码失败: %w", err)
	}
	id, err := newID("ask-", in.CaseID)
	if err != nil {
		return "", err
	}
	now := time.Now()
	a := &Approval{
		ApprovalID:        id,
		CaseID:            in.CaseID,
		SessionID:         in.SessionID,
		StepID:            in.StepID,
		Plan:              payload,
		PlanHash:          sha256Hex(payload),
		RequestType:       RequestTypeAskUser,
		RiskLevel:         1,
		LLMRiskAssessment: []byte("{}"),
		Status:            StatusPending,
		ExpiresAt:         now.Add(s.askTimeout),
		CreatedAt:         now,
	}
	if err := s.store.Create(ctx, a); err != nil {
		return "", err
	}
	s.scheduleExpiry(a.ApprovalID, s.askTimeout)
	s.notifyRequested(ctx, a)
	return a.ApprovalID, nil
}

// L4Phrase L4 双确认短语格式（签名校验语义）：`确认执行 <request_type>`。
// 错误提示不得回显本函数返回值。
func L4Phrase(requestType string) string { return "确认执行 " + requestType }

// ValidateDecision 决策合法性：仅 approved|rejected。
func ValidateDecision(decision Status) error {
	if decision != StatusApproved && decision != StatusRejected {
		return fmt.Errorf("%w: %q", ErrInvalidDecision, decision)
	}
	return nil
}

// ExpiredFor deny-by-default 判据：仅约束 approve 方向——reject 是 deny 方向
// 恒允许。now 取 time.Now；需要注入时钟时用 [ExpiredForAt]。
func ExpiredFor(a *Approval, decision Status) bool {
	return ExpiredForAt(a, decision, time.Now())
}

// ExpiredForAt = [ExpiredFor] 且显式指定当前时刻（谓词单源，测试/跨副本时钟
// 演练可注入）。a 为 nil 返回 false（无单可判，由调用方另行处理）。
func ExpiredForAt(a *Approval, decision Status, now time.Time) bool {
	return a != nil && decision == StatusApproved && !a.ExpiresAt.After(now)
}

// Decide 人工决策（API 入口）。守卫链：decision 合法 → 审批分离（仅 approve）
// → deny-by-default（仅 approve，过期单惰性收敛 expired）→ L4 双确认（risk>=4
// 的 approve：首次携带正确短语只记 L4FirstAt 并保持 pending；第二次携带正确
// 短语才落 approved/签发凭据）→ 一次性凭据哈希落库 → 终态事件/唤醒 waiter。
//
// 返回 false, nil 表示存储 CAS 竞态失败（他方已决策/已过期），调用方可映射
// 409；错误均为哨兵包装，调用方按 errors.Is 映射 HTTP 语义。
func (s *Service) Decide(ctx context.Context, approvalID string, decision Status, by, note, confirmPhrase string) (bool, error) {
	if err := ValidateDecision(decision); err != nil {
		return false, err
	}
	a, err := s.store.Get(ctx, approvalID)
	if err != nil {
		return false, err
	}
	// 审批人≠提审人分离：只约束 approve 方向（自批自己的高危变更是要堵的洞；
	// reject 是 deny 方向恒允许）。提审人/决策人匿名时不生效。
	if decision == StatusApproved && s.requireSeparate && a.CreatedBy != "" && by == a.CreatedBy {
		return false, fmt.Errorf("%w: 提审人 %q 不得批准自己的方案", ErrSeparation, a.CreatedBy)
	}
	if ExpiredForAt(a, decision, time.Now()) {
		_, _ = s.expireOne(ctx, approvalID)
		return false, ErrExpired
	}
	tokenHash := ""
	if decision == StatusApproved {
		// L4 双确认：首次与第二次都必须携带精确短语；错误提示不回显短语。
		if a.RiskLevel >= l4RiskLevel {
			if confirmPhrase != L4Phrase(a.RequestType) {
				return false, ErrL4Phrase
			}
			if a.L4FirstAt == nil {
				ok, err := s.store.MarkL4First(ctx, approvalID, time.Now())
				if err != nil {
					return false, err
				}
				if !ok {
					return false, nil // 竞态：他方已首次确认/已决策，调用方重试
				}
				s.wake(approvalID) // 首次确认非终态，但让等待方重新读状态
				return true, nil
			}
		}
		token, err := s.mintToken(a)
		if err != nil {
			return false, err
		}
		tokenHash = sha256Hex([]byte(token))
	}
	return s.commitDecision(ctx, approvalID, decision, by, note, tokenHash)
}

// DecideSystem 策略代批（操作审计门的 auto/full 模式矩阵放行）。与人工决策
// 同一状态机/凭据/事件语义，仅 decided_by=SystemDecider、备注记录策略依据。
// L4 高危变更永不代批（在过期判定之前直接拒绝）；过期单 approve 同样 deny。
func (s *Service) DecideSystem(ctx context.Context, approvalID string, decision Status, reason string) (bool, error) {
	if err := ValidateDecision(decision); err != nil {
		return false, err
	}
	a, err := s.store.Get(ctx, approvalID)
	if err != nil {
		return false, err
	}
	if a.RiskLevel >= l4RiskLevel {
		return false, ErrL4System
	}
	if ExpiredForAt(a, decision, time.Now()) {
		_, _ = s.expireOne(ctx, approvalID)
		return false, ErrExpired
	}
	tokenHash := ""
	if decision == StatusApproved {
		token, err := s.mintToken(a)
		if err != nil {
			return false, err
		}
		tokenHash = sha256Hex([]byte(token))
	}
	return s.commitDecision(ctx, approvalID, decision, SystemDecider, "策略代批: "+reason, tokenHash)
}

// CancelPending 提审方取消待批审批单（仅 pending 可取消）。返回 false=他方
// 已决策/过期。成功走与决策相同的终态收尾（事件/唤醒）。
func (s *Service) CancelPending(ctx context.Context, approvalID, by, note string) (bool, error) {
	ok, err := s.store.CancelPending(ctx, approvalID, by, note)
	if err != nil || !ok {
		return ok, err
	}
	s.settle(ctx, approvalID, EventCancelled, StatusCancelled, by)
	return true, nil
}

// commitDecision 决策落定尾（Decide/DecideSystem 共用）：CAS 成功才发事件/
// 唤醒；false=竞态失败，调用方按 409/回退人工处理。
func (s *Service) commitDecision(ctx context.Context, approvalID string, decision Status, by, note, tokenHash string) (bool, error) {
	ok, err := s.store.Decide(ctx, approvalID, decision, by, note, tokenHash)
	if err != nil || !ok {
		return ok, err
	}
	s.settle(ctx, approvalID, EventDecided, decision, by)
	return true, nil
}

// AwaitDecision 阻塞等待终态（订阅唤醒 + 周期轮询双通道；pending 且已到期时
// 惰性收敛 expired 再继续等）。approved 返回由审批行字段确定性签出的执行凭据
// （明文不落库；跨副本可用）。ctx 取消返回 ctx.Err。
func (s *Service) AwaitDecision(ctx context.Context, approvalID string) (status Status, token, note string, err error) {
	ch := s.subscribe(approvalID)
	defer s.unsubscribe(approvalID, ch)
	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()

	for {
		a, err := s.store.Get(ctx, approvalID)
		if err != nil {
			return "", "", "", err
		}
		if a.Status == StatusPending && !a.ExpiresAt.After(time.Now()) {
			// 到期收敛后不立即 continue：走一次 select 等 ticker，避免存储写失败
			// 时忙旋。
			_, _ = s.expireOne(ctx, approvalID)
		} else if a.Status != StatusPending {
			token := ""
			if a.Status == StatusApproved {
				tok, err := s.mintToken(a)
				if err != nil {
					return "", "", "", err
				}
				token = tok
			}
			return a.Status, token, a.DecisionNote, nil
		}
		select {
		case <-ctx.Done():
			return "", "", "", ctx.Err()
		case <-ticker.C:
		case <-ch:
		}
	}
}

// ConsumeToken 一次性核销执行凭据：先 tokenx 无状态验签（MAC/绑定/时效），
// 再做存储 CAS（approved + 哈希匹配 + 未使用）。错误 token/过期/跨单挪用一律
// 返回 false, nil（不给攻击者区分oracle）；只有存储读/写失败返回 error。
func (s *Service) ConsumeToken(ctx context.Context, approvalID, token string) (bool, error) {
	a, err := s.store.Get(ctx, approvalID)
	if err != nil {
		return false, err
	}
	if a.Status != StatusApproved {
		return false, nil
	}
	if _, err := tokenx.Verify(s.secret, token, s.tokenBinding(a)); err != nil {
		return false, nil
	}
	return s.store.ConsumeToken(ctx, approvalID, sha256Hex([]byte(token)))
}

// SweepExpired 周期扫描到期 pending 单：逐条 CAS 置 expired，成功的逐条发事件/
// 唤醒 waiter（与进程内定时器双保险；重启/多副本的兜底）。返回本次收敛数。
func (s *Service) SweepExpired(ctx context.Context) int {
	ids, err := s.store.Due(ctx, time.Now())
	if err != nil {
		return 0
	}
	n := 0
	for _, id := range ids {
		ok, err := s.expireOne(ctx, id)
		if err == nil && ok {
			n++
		}
	}
	return n
}

// SweepUnnotifiedRequests 审批创建卡片的扫描兜底与未决催办：对
// approval_requested 未落推送标记的事件，pending 且已过 RemindAfter 的补推
// 一次并落标记；未过阈值的保留待下轮；已决策/过期/取消的只落标记收敛扫描集。
// 返回本次补推数。notifier 为 nil 时直接 0。
func (s *Service) SweepUnnotifiedRequests(ctx context.Context, now time.Time) int {
	if s.notifier == nil {
		return 0
	}
	evs, err := s.store.UnnotifiedRequests(ctx, now.Add(-remindLookback), remindLimit)
	if err != nil {
		return 0
	}
	n := 0
	for _, ev := range evs {
		if ev.ApprovalID == "" {
			// 无法归属的历史/异常帧：落标记防反复空转。
			_ = s.store.MarkRequestNotified(ctx, ev.ID, now)
			continue
		}
		a, err := s.store.Get(ctx, ev.ApprovalID)
		if err != nil {
			continue // 读单瞬时失败：不标记，下轮重试
		}
		if a.Status == StatusPending {
			if now.Sub(a.CreatedAt) < s.remindAfter {
				continue // 未过阈值：不推不标记（留待下轮催办）
			}
			s.notifyRequested(ctx, a)
			n++
		}
		_ = s.store.MarkRequestNotified(ctx, ev.ID, now)
	}
	return n
}

// Get 读取审批单（宿主 API 详情可直接转调存储）。
func (s *Service) Get(ctx context.Context, approvalID string) (*Approval, error) {
	return s.store.Get(ctx, approvalID)
}

// mintToken 由审批行字段确定性签出执行凭据（tokenx：HMAC + 载荷绑定 + 时效）。
// 同一行任何副本签出同一凭据；明文只返回给调用方，不落库。
func (s *Service) mintToken(a *Approval) (string, error) {
	return tokenx.Sign(s.secret, s.tokenBinding(a), a.ExpiresAt.Add(s.tokenGrace))
}

// tokenBinding 执行凭据的载荷绑定：审批单/案例/方案哈希三元组。跨单挪用或
// 批准后改写方案都会在验签/绑定处失败。
func (s *Service) tokenBinding(a *Approval) tokenx.Claims {
	return tokenx.Claims{
		"approval_id": a.ApprovalID,
		"case_id":     a.CaseID,
		"plan_hash":   a.PlanHash,
	}
}

// expireOne CAS 置 expired 成功才发事件/唤醒。false=他方已决策/已过期。
func (s *Service) expireOne(ctx context.Context, approvalID string) (bool, error) {
	ok, err := s.store.Expire(ctx, approvalID)
	if err != nil || !ok {
		// 他方已决策/已过期：本地定时器条目也要收敛，避免 map 泄漏。
		s.stopTimer(approvalID)
		return false, err
	}
	s.settle(ctx, approvalID, EventExpired, StatusExpired, "system")
	return true, nil
}

// settle 终态收尾：停超时定时器 → 重读审批行 → 发事件 → 唤醒 waiter。重读
// 用脱离请求取消的上下文：决策已落库，事件不得因请求 ctx 取消而丢。
func (s *Service) settle(ctx context.Context, approvalID string, typ EventType, status Status, by string) {
	s.stopTimer(approvalID)
	pctx := context.WithoutCancel(ctx)
	if s.publisher != nil {
		if a, err := s.store.Get(pctx, approvalID); err == nil {
			s.publisher.Publish(pctx, Event{
				Type:        typ,
				ApprovalID:  a.ApprovalID,
				CaseID:      a.CaseID,
				SessionID:   a.SessionID,
				StepID:      a.StepID,
				RequestType: a.RequestType,
				RiskLevel:   a.RiskLevel,
				Status:      status,
				By:          by,
				Note:        a.DecisionNote,
				At:          time.Now(),
			})
		}
	}
	s.wake(approvalID)
}

// scheduleExpiry 注册进程内超时任务；决策/取消/过期后 stopTimer 撤销。
func (s *Service) scheduleExpiry(approvalID string, d time.Duration) {
	t := time.AfterFunc(d, func() {
		_, _ = s.expireOne(context.Background(), approvalID)
	})
	s.mu.Lock()
	s.timers[approvalID] = t
	s.mu.Unlock()
}

// stopTimer 撤销超时任务（不存在/已触发也安全）。
func (s *Service) stopTimer(approvalID string) {
	s.mu.Lock()
	if t, ok := s.timers[approvalID]; ok {
		t.Stop()
		delete(s.timers, approvalID)
	}
	s.mu.Unlock()
}

// subscribe 注册等待唤醒通道（AwaitDecision 专用）。
func (s *Service) subscribe(approvalID string) chan struct{} {
	ch := make(chan struct{})
	s.mu.Lock()
	s.waiters[approvalID] = append(s.waiters[approvalID], ch)
	s.mu.Unlock()
	return ch
}

// unsubscribe 撤销等待通道（已唤醒/已删除也安全）。
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

// wake 唤醒某审批单的全部等待者（一次性：关闭并删除通道）。
func (s *Service) wake(approvalID string) {
	s.mu.Lock()
	list := s.waiters[approvalID]
	delete(s.waiters, approvalID)
	s.mu.Unlock()
	for _, ch := range list {
		close(ch)
	}
}

// notifyRequested 请求创建/催办推送（宿主实现卡片；nil=no-op）。
func (s *Service) notifyRequested(ctx context.Context, a *Approval) {
	if s.notifier != nil {
		s.notifier.ApprovalRequested(ctx, a)
	}
}

// normalizePlan 方案载荷规范化：空载荷落 "{}"；非空必须是合法 JSON（fail-fast，
// 不把未定义字节哈希进凭据绑定）。
func normalizePlan(plan []byte) ([]byte, error) {
	if len(plan) == 0 {
		return []byte("{}"), nil
	}
	if !json.Valid(plan) {
		return nil, ErrBadPlan
	}
	return plan, nil
}

// sha256Hex sha256 十六进制（方案哈希/凭据哈希同一形态，64 字符）。
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// newID 生成审批单号：<prefix><caseID>-<8 字节随机 hex>。随机后缀让驳回重提
// 成为新单（同 id 会让状态更新串单）。
func newID(prefix, caseID string) (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("approvalflow: 系统熵源故障: %w", err)
	}
	return prefix + caseID + "-" + hex.EncodeToString(b), nil
}
