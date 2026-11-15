package gdpr

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DefaultChunkSize 分块删除默认块大小：与宿主事件表清理同款纪律——单块
// 删除控制在短事务内，避免大表长事务锁表（400 是既有生产口径）。
const DefaultChunkSize = 400

// ErasedPrefix 匿名化替换值前缀：erased-<subject>。
const ErasedPrefix = "erased-"

// Policy 表级策略位（可组合；PolicyExempt 必须单独使用）。
type Policy uint8

const (
	// PolicyExport 采集该表归属键等于主体的记录。
	PolicyExport Policy = 1 << iota
	// PolicyErase 按归属键分块硬删。
	PolicyErase
	// PolicyAnonymize 按归属键把主体标识改写为匿名值（行保留）。
	PolicyAnonymize
	// PolicyExempt 显式豁免：不采集、不删除，回执中显式列出。
	PolicyExempt
)

const policyAll = PolicyExport | PolicyErase | PolicyAnonymize | PolicyExempt

// String 人类可读策略组合（日志/回执排障用，不参与判定）。
func (p Policy) String() string {
	if p == 0 {
		return "none"
	}
	names := make([]string, 0, 4)
	if p&PolicyExport != 0 {
		names = append(names, "export")
	}
	if p&PolicyErase != 0 {
		names = append(names, "erase")
	}
	if p&PolicyAnonymize != 0 {
		names = append(names, "anonymize")
	}
	if p&PolicyExempt != 0 {
		names = append(names, "exempt")
	}
	if p&^policyAll != 0 {
		names = append(names, fmt.Sprintf("unknown(0x%x)", uint8(p&^policyAll)))
	}
	return strings.Join(names, "|")
}

// Record 单条个人数据记录：必须是 JSON 可编码的普通值（string/数字/布尔/
// nil/map[string]any/[]any 及其嵌套）。struct、json.RawMessage 等无法按
// 字段名判定敏感性的类型被脱敏器拒绝（fail-closed）。
type Record map[string]any

// Collector 采集闭包：按归属列与主体采集该表记录。SQL 方言与字段裁剪由
// 宿主决定；返回原始记录，脱敏由骨架统一执行。
type Collector func(ctx context.Context, ownerColumn, subject string) ([]Record, error)

// Deleter 单块删除原语：删除至多 limit 条归属键等于 subject 的行，返回
// 实际删除数。宿主实现应使用 `DELETE ... WHERE owner = ? LIMIT ?` 形态。
type Deleter func(ctx context.Context, ownerColumn, subject string, limit int) (int, error)

// Anonymizer 匿名化闭包：把归属键等于 subject 的行改写为 replacement，
// 返回受影响行数。
type Anonymizer func(ctx context.Context, ownerColumn, subject, replacement string) (int, error)

// TombstoneStore 墓碑存储：EraseUserData 全部表处理成功后调用一次。
// 实现必须是幂等追加（唯一索引 + ON CONFLICT DO NOTHING 或等价形态）：
// already=true 表示该主体墓碑已存在，不是错误。
type TombstoneStore interface {
	AppendErasedUser(ctx context.Context, subject string) (already bool, err error)
}

// Redactor 导出脱敏器：返回脱敏后的记录副本，不得修改入参。
// 实现必须 fail-closed——无法安全判定的值应报错而不是原样透出。
type Redactor interface {
	Redact(record Record) (Record, error)
}

// Entry 一行注册表：一张表一个归属列，策略位声明纳入哪些权利面。
type Entry struct {
	// Table 表名（回执/日志用语）。
	Table string
	// OwnerColumn 归属键列名（如 creator/username/id）。Exempt 项可留空。
	OwnerColumn string
	// Policies 策略位组合（PolicyExempt 必须单独使用）。
	Policies Policy
	// Description 可选说明（为什么这样登记，审计可读）。
	Description string
	// Collector PolicyExport 必填。
	Collector Collector
	// Deleter PolicyErase 必填。
	Deleter Deleter
	// Anonymizer PolicyAnonymize 必填。
	Anonymizer Anonymizer
}

// SubjectExporter 数据主体导出面（[Registry] 实现）。
type SubjectExporter interface {
	ExportUserData(ctx context.Context, subject string) (ExportResult, error)
}

// SubjectEraser 数据主体删除面（[Registry] 实现）。
type SubjectEraser interface {
	EraseUserData(ctx context.Context, subject string) (EraseReport, error)
}

var (
	_ SubjectExporter = (*Registry)(nil)
	_ SubjectEraser   = (*Registry)(nil)
)

// ExportResult 导出回执：按注册序排列的表数据 + 显式豁免表。
type ExportResult struct {
	Subject     string        `json:"subject"`
	GeneratedAt time.Time     `json:"generated_at"`
	Tables      []ExportTable `json:"tables"`
	Exempt      []string      `json:"exempt,omitempty"`
}

// ExportTable 单表导出数据（Records 已过 Redactor）。
type ExportTable struct {
	Table       string   `json:"table"`
	OwnerColumn string   `json:"owner_column"`
	Count       int      `json:"count"`
	Records     []Record `json:"records"`
}

// EraseTableReport 单表删除/匿名化回执。Deleted 与 Anonymized 二者只会
// 有一个非零（同一表禁止同时登记 erase 与 anonymize）。
type EraseTableReport struct {
	Table       string `json:"table"`
	OwnerColumn string `json:"owner_column"`
	Deleted     int    `json:"deleted"`
	Anonymized  int    `json:"anonymized"`
}

// TombstoneResult 墓碑追加结果：Appended 与 Already 互斥。
type TombstoneResult struct {
	Requested bool `json:"requested"`
	Appended  bool `json:"appended"`
	Already   bool `json:"already"`
}

// EraseReport 删除回执：即使中途失败也返回已执行部分（错误另行返回）。
type EraseReport struct {
	Subject         string             `json:"subject"`
	StartedAt       time.Time          `json:"started_at"`
	FinishedAt      time.Time          `json:"finished_at"`
	Tables          []EraseTableReport `json:"tables"`
	Exempt          []string           `json:"exempt,omitempty"`
	TotalDeleted    int                `json:"total_deleted"`
	TotalAnonymized int                `json:"total_anonymized"`
	Tombstone       TombstoneResult    `json:"tombstone"`
}

// 哨兵错误（errors.Is 判定，不匹配文案）。
var (
	// ErrNoSubject 数据主体为空/纯空白（fail-fast：空主体会命中全表）。
	ErrNoSubject = errors.New("gdpr: 数据主体为空")
	// ErrEmptyRegistry 注册表为空（fail-closed：空表遍历会静默漏导/漏删）。
	ErrEmptyRegistry = errors.New("gdpr: 注册表为空（fail-closed）")
	// ErrBadEntry 登记项形态非法（表名/归属列缺失）。
	ErrBadEntry = errors.New("gdpr: 登记项非法")
	// ErrDuplicateTable 同一张表重复登记（归属列/策略单源）。
	ErrDuplicateTable = errors.New("gdpr: 表重复登记")
	// ErrBadPolicy 策略位为零、含未知位，或 Exempt 与其它策略混用。
	ErrBadPolicy = errors.New("gdpr: 策略位非法")
	// ErrMissingCollector PolicyExport 缺采集闭包。
	ErrMissingCollector = errors.New("gdpr: PolicyExport 缺少 Collector")
	// ErrMissingDeleter PolicyErase 缺分块删除闭包。
	ErrMissingDeleter = errors.New("gdpr: PolicyErase 缺少 Deleter")
	// ErrMissingAnonymizer PolicyAnonymize 缺匿名化闭包。
	ErrMissingAnonymizer = errors.New("gdpr: PolicyAnonymize 缺少 Anonymizer")
	// ErrNoRedactor 导出脱敏器缺失（不存在不脱敏导出）。
	ErrNoRedactor = errors.New("gdpr: 导出缺少 Redactor（fail-closed）")
	// ErrNoTombstone 有删除/匿名化策略但未注入墓碑存储。
	ErrNoTombstone = errors.New("gdpr: 缺少墓碑存储（fail-closed）")
	// ErrBadChunkSize 分块大小 <= 0。
	ErrBadChunkSize = errors.New("gdpr: 分块大小必须为正")
	// ErrBadReplacement 匿名化替换值为空或与主体同名（匿名化未生效）。
	ErrBadReplacement = errors.New("gdpr: 匿名化替换值非法")
	// ErrNoExporters 注册表没有任何 PolicyExport 项（导出会静默为空）。
	ErrNoExporters = errors.New("gdpr: 无导出登记项（fail-closed）")
	// ErrNoErasers 注册表没有任何 erase/anonymize 项（删除会静默空转）。
	ErrNoErasers = errors.New("gdpr: 无删除/匿名化登记项（fail-closed）")
	// ErrCollect 采集闭包失败。
	ErrCollect = errors.New("gdpr: 采集失败")
	// ErrRedact 脱敏失败（值类型无法安全判定或脱敏器报错）。
	ErrRedact = errors.New("gdpr: 脱敏失败")
	// ErrErase 分块删除失败。
	ErrErase = errors.New("gdpr: 删除失败")
	// ErrAnonymize 匿名化失败。
	ErrAnonymize = errors.New("gdpr: 匿名化失败")
	// ErrTombstone 墓碑追加失败。
	ErrTombstone = errors.New("gdpr: 墓碑追加失败")
	// ErrBadChunkCount 删除闭包返回的条数越界（<0 或 >limit）。
	ErrBadChunkCount = errors.New("gdpr: 删除闭包返回条数越界")
	// ErrUnsupportedValue 记录含无法按字段名判定敏感性的值类型
	// （struct/json.RawMessage/通道等），拒绝原样透出。
	ErrUnsupportedValue = errors.New("gdpr: 值类型无法安全脱敏")
)

// Registry 归属键注册表：ExportUserData/EraseUserData 的唯一执行入口。
type Registry struct {
	entries       []Entry
	redactor      Redactor
	chunkSize     int
	tombstones    TombstoneStore
	anonymizeName func(subject string) string
	now           func() time.Time
}

// Option 注册表选项。
type Option func(*Registry) error

// WithRedactor 注入导出脱敏器（覆盖默认 [DenyListRedactor]；必须更严格，
// nil 拒绝）。
func WithRedactor(r Redactor) Option {
	return func(reg *Registry) error {
		if r == nil {
			return ErrNoRedactor
		}
		reg.redactor = r
		return nil
	}
}

// WithChunkSize 调整分块删除大小（必须为正；默认 [DefaultChunkSize]）。
func WithChunkSize(n int) Option {
	return func(reg *Registry) error {
		if n <= 0 {
			return ErrBadChunkSize
		}
		reg.chunkSize = n
		return nil
	}
}

// WithTombstone 注入墓碑存储（存在删除/匿名化策略时必填）。
func WithTombstone(t TombstoneStore) Option {
	return func(reg *Registry) error {
		if t == nil {
			return ErrNoTombstone
		}
		reg.tombstones = t
		return nil
	}
}

// WithAnonymizeName 注入匿名化替换值生成器（默认 erased-<subject>；
// 返回空或原值会在删除时被拒绝）。
func WithAnonymizeName(fn func(subject string) string) Option {
	return func(reg *Registry) error {
		if fn == nil {
			return ErrBadReplacement
		}
		reg.anonymizeName = fn
		return nil
	}
}

// WithClock 注入时钟（测试/演练用；默认 time.Now）。
func WithClock(now func() time.Time) Option {
	return func(reg *Registry) error {
		if now == nil {
			return errors.New("gdpr: 时钟为 nil")
		}
		reg.now = now
		return nil
	}
}

// NewRegistry 构建注册表并做全量校验（fail-closed），应把错误当启动期
// 配置错误处理，不要吞掉。
func NewRegistry(entries []Entry, opts ...Option) (*Registry, error) {
	defaultRedactor, err := NewRedactor()
	if err != nil {
		return nil, err
	}
	reg := &Registry{
		redactor:      defaultRedactor,
		chunkSize:     DefaultChunkSize,
		anonymizeName: func(subject string) string { return ErasedPrefix + subject },
		now:           time.Now,
	}
	for i, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("gdpr: 第 %d 个 Option 为 nil", i)
		}
		if err := opt(reg); err != nil {
			return nil, err
		}
	}
	if len(entries) == 0 {
		return nil, ErrEmptyRegistry
	}

	seen := make(map[string]struct{}, len(entries))
	needTombstone := false
	for i, e := range entries {
		if strings.TrimSpace(e.Table) == "" {
			return nil, fmt.Errorf("%w: 第 %d 项缺少表名", ErrBadEntry, i)
		}
		if _, dup := seen[e.Table]; dup {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateTable, e.Table)
		}
		seen[e.Table] = struct{}{}

		switch {
		case e.Policies == 0:
			return nil, fmt.Errorf("%w: %q 策略为零", ErrBadPolicy, e.Table)
		case e.Policies&^policyAll != 0:
			return nil, fmt.Errorf("%w: %q 含未知位 %s", ErrBadPolicy, e.Table, e.Policies)
		case e.Policies&PolicyExempt != 0 && e.Policies != PolicyExempt:
			return nil, fmt.Errorf("%w: %q Exempt 不能与其它策略组合", ErrBadPolicy, e.Table)
		}
		if e.Policies != PolicyExempt && strings.TrimSpace(e.OwnerColumn) == "" {
			return nil, fmt.Errorf("%w: %q 缺少归属列", ErrBadEntry, e.Table)
		}
		if e.Policies&PolicyExport != 0 && e.Collector == nil {
			return nil, fmt.Errorf("%w: %q", ErrMissingCollector, e.Table)
		}
		if e.Policies&PolicyErase != 0 && e.Deleter == nil {
			return nil, fmt.Errorf("%w: %q", ErrMissingDeleter, e.Table)
		}
		if e.Policies&PolicyAnonymize != 0 && e.Anonymizer == nil {
			return nil, fmt.Errorf("%w: %q", ErrMissingAnonymizer, e.Table)
		}
		if e.Policies&(PolicyErase|PolicyAnonymize) != 0 {
			needTombstone = true
		}
	}
	if needTombstone && reg.tombstones == nil {
		return nil, ErrNoTombstone
	}
	reg.entries = append([]Entry(nil), entries...)
	return reg, nil
}

// Entries 返回注册表快照（审计/测试用；可安全修改返回值）。
func (r *Registry) Entries() []Entry {
	if r == nil {
		return nil
	}
	return append([]Entry(nil), r.entries...)
}

// ExportUserData 按注册表采集主体全部可导出表，逐条过 Redactor。
// 任一表采集/脱敏失败即中止并返回已采集部分 + 错误（失败不是成功）。
// 显式 Exempt 表列在结果里，缺席与漏登记可区分。
func (r *Registry) ExportUserData(ctx context.Context, subject string) (ExportResult, error) {
	result := ExportResult{Subject: subject}
	if r == nil {
		return result, ErrEmptyRegistry
	}
	if strings.TrimSpace(subject) == "" {
		return result, ErrNoSubject
	}
	result.GeneratedAt = r.now()

	exporters := 0
	for _, e := range r.entries {
		if e.Policies&PolicyExempt != 0 {
			result.Exempt = append(result.Exempt, e.Table)
			continue
		}
		if e.Policies&PolicyExport == 0 {
			continue
		}
		exporters++
		records, err := e.Collector(ctx, e.OwnerColumn, subject)
		if err != nil {
			return result, fmt.Errorf("%w: %s: %w", ErrCollect, e.Table, err)
		}
		redacted := make([]Record, 0, len(records))
		for _, rec := range records {
			out, err := r.redactor.Redact(rec)
			if err != nil {
				return result, fmt.Errorf("%w: %s: %w", ErrRedact, e.Table, err)
			}
			redacted = append(redacted, out)
		}
		result.Tables = append(result.Tables, ExportTable{
			Table:       e.Table,
			OwnerColumn: e.OwnerColumn,
			Count:       len(redacted),
			Records:     redacted,
		})
	}
	if exporters == 0 {
		return result, ErrNoExporters
	}
	return result, nil
}

// EraseUserData 按注册表分块硬删 + 匿名化 + 墓碑追加。任一步失败立即
// 中止：返回已执行部分回执 + 错误，墓碑不追加。全部成功后才追加墓碑
// （幂等）。
func (r *Registry) EraseUserData(ctx context.Context, subject string) (EraseReport, error) {
	report := EraseReport{Subject: subject}
	if r == nil {
		return report, ErrEmptyRegistry
	}
	if strings.TrimSpace(subject) == "" {
		return report, ErrNoSubject
	}
	report.StartedAt = r.now()
	finish := func() { report.FinishedAt = r.now() }

	erasers := 0
	for _, e := range r.entries {
		if e.Policies&PolicyExempt != 0 {
			report.Exempt = append(report.Exempt, e.Table)
			continue
		}
		switch {
		case e.Policies&PolicyErase != 0:
			erasers++
			deleted, err := EraseInChunks(ctx, r.chunkSize, func(ctx context.Context, limit int) (int, error) {
				return e.Deleter(ctx, e.OwnerColumn, subject, limit)
			})
			report.Tables = append(report.Tables, EraseTableReport{
				Table:       e.Table,
				OwnerColumn: e.OwnerColumn,
				Deleted:     deleted,
			})
			report.TotalDeleted += deleted
			if err != nil {
				finish()
				return report, fmt.Errorf("%w: %s: %w", ErrErase, e.Table, err)
			}
		case e.Policies&PolicyAnonymize != 0:
			erasers++
			replacement := r.anonymizeName(subject)
			if strings.TrimSpace(replacement) == "" || replacement == subject {
				finish()
				return report, fmt.Errorf("%w: %q -> %q", ErrBadReplacement, subject, replacement)
			}
			anonymized, err := e.Anonymizer(ctx, e.OwnerColumn, subject, replacement)
			report.Tables = append(report.Tables, EraseTableReport{
				Table:       e.Table,
				OwnerColumn: e.OwnerColumn,
				Anonymized:  anonymized,
			})
			report.TotalAnonymized += anonymized
			if err != nil {
				finish()
				return report, fmt.Errorf("%w: %s: %w", ErrAnonymize, e.Table, err)
			}
		}
	}
	if erasers == 0 {
		finish()
		return report, ErrNoErasers
	}

	report.Tombstone.Requested = true
	already, err := r.tombstones.AppendErasedUser(ctx, subject)
	if err != nil {
		finish()
		return report, fmt.Errorf("%w: %w", ErrTombstone, err)
	}
	report.Tombstone.Already = already
	report.Tombstone.Appended = !already
	finish()
	return report, nil
}

// EraseInChunks 分块删除原语：反复调用 del(ctx, chunkSize) 直到单次删除
// 数小于 chunkSize（含 0）。del 返回条数越界（<0 或 >chunkSize）按实现
// 违约处理，直接报错（fail-closed）。ctx 取消即返回已删除总数 + ctx 错误。
func EraseInChunks(ctx context.Context, chunkSize int, del func(ctx context.Context, limit int) (int, error)) (int, error) {
	if chunkSize <= 0 {
		return 0, ErrBadChunkSize
	}
	if del == nil {
		return 0, ErrMissingDeleter
	}
	total := 0
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, err := del(ctx, chunkSize)
		if err != nil {
			return total, err
		}
		if n < 0 || n > chunkSize {
			return total, fmt.Errorf("%w: got %d, limit %d", ErrBadChunkCount, n, chunkSize)
		}
		total += n
		if n < chunkSize {
			return total, nil
		}
	}
}
