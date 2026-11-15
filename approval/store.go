package approval

import (
	"context"
	"errors"
	"time"
)

// Status 审批单状态（终态：approved/rejected/expired/cancelled）。
type Status string

// 状态常量与 bq_approval.status 取值一致。
const (
	StatusPending   Status = "pending"
	StatusApproved  Status = "approved"
	StatusRejected  Status = "rejected"
	StatusExpired   Status = "expired"
	StatusCancelled Status = "cancelled"
)

// ValidDecision 决策只接受 approved|rejected。
func ValidDecision(d Status) bool {
	return d == StatusApproved || d == StatusRejected
}

// Request 审批单行（宿主存储的领域形态；字段与 bianque bq_approval 对齐，
// 不绑定任何 ORM）。
type Request struct {
	ApprovalID        string
	CaseID            string
	SessionID         string
	StepID            uint64
	PlanReport        []byte // 方案/提问载荷快照
	PlanHash          string // sha256(PlanReport)，防原样重提
	RequestType       string
	RiskLevel         int
	LLMRiskAssessment []byte
	Status            Status
	DecideTokenHash   string // sha256(执行凭据)；明文只在批准返回与引擎内存
	L4FirstAt         *time.Time
	TokenUsedAt       *time.Time
	DecidedBy         string
	CreatedBy         string // 提审人（审批分离比对基准；空=无身份）
	DecisionNote      string
	ExpiresAt         time.Time
	DecidedAt         *time.Time
	CreatedAt         time.Time
}

// Store 审批单持久化契约。所有迁移都是 CAS：返回 false 表示守卫未命中
// （他方已决策/已过期/已核销），调用方按并发失败处理，不得当成错误重试
// 同一次迁移。
type Store interface {
	// Create 插入审批单（ApprovalID 由服务层生成，必须唯一）。
	Create(ctx context.Context, r *Request) error
	// Get 按 ApprovalID 读取；不存在返回宿主自己的 not-found 错误。
	Get(ctx context.Context, approvalID string) (*Request, error)
	// Decide 条件决策：仅 pending 可迁移。
	//
	// approve（tokenHash 非空）还必须满足 expires_at > now——服务层检查与
	// 存储层并发窗口双保险，过期单放行是 deny-by-default 红线的洞。
	// reject（tokenHash 空）对过期行恒允许。
	// 同时写入 decided_by/decision_note/decided_at/decide_token_hash。
	Decide(ctx context.Context, approvalID string, decision Status, by, note, tokenHash string, now time.Time) (bool, error)
	// MarkL4First L4 首次确认 CAS：仅 pending 且 l4_first_at IS NULL 时置 at。
	MarkL4First(ctx context.Context, approvalID string, at time.Time) (bool, error)
	// Expire 条件置过期：仅 pending → expired。
	Expire(ctx context.Context, approvalID string) (bool, error)
	// ExpireDue 批量收敛到期 pending 行 → expired，返回本次实际迁移的
	// ApprovalID 列表（竞态落败者不在列表中）。
	ExpireDue(ctx context.Context, now time.Time) ([]string, error)
	// Cancel 条件取消：仅 pending → cancelled，写入 by/note/decided_at。
	Cancel(ctx context.Context, approvalID, by, note string, now time.Time) (bool, error)
	// ConsumeToken 一次性核销：仅 approved、decide_token_hash 等于
	// tokenHash 且 token_used_at IS NULL 时置当前时刻，原子完成。
	ConsumeToken(ctx context.Context, approvalID, tokenHash string) (bool, error)
	// ExistsPlanHash 同案例是否已有同方案哈希（防驳回后原样重提）。
	ExistsPlanHash(ctx context.Context, caseID, planHash string) (bool, error)
}

// Event 决策/过期/取消事件（Publisher 的输入）。字段够宿主接审计与指标；
// Request 本体不回传（避免宿主误改已落定行）。
type Event struct {
	Type        string // EventDecided | EventExpired
	ApprovalID  string
	CaseID      string
	SessionID   string
	StepID      uint64
	RequestType string
	RiskLevel   int
	Status      Status
	DecidedBy   string
	Note        string
	CreatedBy   string
	At          time.Time
}

// 事件类型（稳定字符串，宿主按此路由）。
const (
	EventDecided = "approval.decided"
	EventExpired = "approval.expired"
)

// Publisher 决策事件出口（宿主接审计/指标/通知编排）。Publish 在状态迁移
// 落定后同步调用；实现不得阻塞状态机——需要慢操作时由宿主自行投递。
type Publisher interface {
	Publish(Event)
}

// PublisherFunc 把普通函数适配成 Publisher。
type PublisherFunc func(Event)

// Publish 实现 Publisher。
func (f PublisherFunc) Publish(ev Event) { f(ev) }

// 包级哨兵：调用方一律 errors.Is 判定，不匹配错误文本。
var (
	// ErrNoStore Store 未注入。
	ErrNoStore = errors.New("approval: Store 未注入")
	// ErrInvalidInput 输入非法（缺 case_id/request_type/question 等）。
	ErrInvalidInput = errors.New("approval: 输入非法")
	// ErrBadDecision 决策值非法（仅 approved|rejected）。
	ErrBadDecision = errors.New("approval: decision 非法")
	// ErrSeparateApprover 审批分离：提审人不得批准自己的方案。
	ErrSeparateApprover = errors.New("approval: 审批人不得与提审人相同")
	// ErrExpired 过期单不可批准（deny by default）。
	ErrExpired = errors.New("approval: 审批单已过期（deny by default）")
	// ErrL4Phrase L4 双确认短语缺失或不匹配。
	ErrL4Phrase = errors.New("approval: L4 二次确认短语不匹配")
	// ErrL4System L4 高危变更不允许策略代批。
	ErrL4System = errors.New("approval: L4 高危变更不允许策略代批")
)

// 审批域常量。
const (
	// RiskL4 高危档：双确认 + 永不代批。
	RiskL4 = 4
	// SystemDecider 策略代批的决策人标识。
	SystemDecider = "system_policy"
	// AskUserRequestType ask_user 提问卡分族。
	AskUserRequestType = "ask_user"

	// DefaultTimeout 审批窗缺省 30min。
	DefaultTimeout = 30 * time.Minute
	// DefaultAskTimeout ask_user 窗口缺省 5m（必须短于审批窗）。
	DefaultAskTimeout = 5 * time.Minute
	// DefaultPollInterval AwaitDecision 轮询兜底间隔。
	DefaultPollInterval = 200 * time.Millisecond
	// DefaultFastTrackTimeout 快速通道缺省短档。
	DefaultFastTrackTimeout = 5 * time.Minute
	// DefaultFastTrackMaxRisk 快速通道缺省只覆盖 LOW（risk<=1）。
	DefaultFastTrackMaxRisk = 1
)

// ExpiredFor deny-by-default 红线判定（Decide/DecideSystem 同一谓词）：
// 仅约束 approve 方向——reject 是 deny 方向恒允许。
func ExpiredFor(r *Request, decision Status, now time.Time) bool {
	return decision == StatusApproved && !r.ExpiresAt.After(now)
}

// L4Phrase L4 双确认短语格式（签名校验语义）：确认执行 <request_type>。
func L4Phrase(requestType string) string { return "确认执行 " + requestType }
