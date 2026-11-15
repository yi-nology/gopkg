package privacy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

// DefaultChunkSize 分块删除缺省批大小（防长事务锁表）。
const DefaultChunkSize = 400

// Bundle 导出包的稳定元键（表名不得与之冲突）。
const (
	KeyExportedAt = "exported_at"
	KeySubject    = "subject"
)

// 包级哨兵：调用方一律 errors.Is 判定。
var (
	// ErrNoRegistry Registry 未注入。
	ErrNoRegistry = errors.New("privacy: Registry 未注入")
	// ErrSubject 数据主体标识为空。
	ErrSubject = errors.New("privacy: subject 不能为空")
	// ErrInvalidTable 注册项非法（缺名/缺归属列/策略非法/缺闭包/豁免缺理由）。
	ErrInvalidTable = errors.New("privacy: 注册项非法")
	// ErrDuplicateTable 表重复注册。
	ErrDuplicateTable = errors.New("privacy: 表重复注册")
	// ErrNoDelete 分块删除闭包为空。
	ErrNoDelete = errors.New("privacy: 删除闭包为空")
	// ErrNoTombstoneStore 墓碑存储为空。
	ErrNoTombstoneStore = errors.New("privacy: 墓碑存储为空")
)

// Policy 表级策略位集合。
type Policy uint8

const (
	// Export 导出时采集该表。
	Export Policy = 1 << iota
	// Erase 删除时清除该表。
	Erase
	// Anonymize 清除后匿名化保留行（闭包返回新名）。
	Anonymize
	// Exempt 导出与删除都跳过（必须写明 Reason，不得与其他策略组合）。
	Exempt
)

// Has 是否包含某策略位。
func (p Policy) Has(q Policy) bool { return p&q != 0 }

// String 稳定文本形态（"export|erase" 等，审计/测试用）。
func (p Policy) String() string {
	if p == 0 {
		return "none"
	}
	if p == Exempt {
		return "exempt"
	}
	names := make([]string, 0, 3)
	if p.Has(Export) {
		names = append(names, "export")
	}
	if p.Has(Erase) {
		names = append(names, "erase")
	}
	if p.Has(Anonymize) {
		names = append(names, "anonymize")
	}
	if p.Has(Exempt) {
		names = append(names, "exempt")
	}
	return strings.Join(names, "|")
}

func (p Policy) valid() bool {
	if p == 0 || p&^(Export|Erase|Anonymize|Exempt) != 0 {
		return false
	}
	return !p.Has(Exempt) || p == Exempt
}

// CollectFunc 采集某主体在该表的全部行（返回值按 JSON 序列化进导出包）。
type CollectFunc func(ctx context.Context, subject string) (any, error)

// EraseFunc 清除某主体在该表的全部行，返回删除行数。batch 是建议批大小
// （[DefaultChunkSize]），闭包内部可用 [ChunkDelete] 执行分批删除。
type EraseFunc func(ctx context.Context, subject string, batch int) (int64, error)

// AnonymizeFunc 匿名化保留行并返回匿名后的主体名（如 erased-<id>）。
type AnonymizeFunc func(ctx context.Context, subject string) (alias string, err error)

// Table 一条归属键登记。
type Table struct {
	// Name 逻辑表名（导出包键/删除回执键）；不得与元键冲突。
	Name string
	// OwnerColumn 归属列（creator/username/identity/session_id…），随注册
	// 表成为「归属键与豁免面单源」的一部分，供审计与评审核对。
	OwnerColumn string
	// Policy 表级策略（见包文档）。
	Policy Policy
	// Omit 导出时剔除的顶层 JSON 字段（口令哈希/密文载荷等凭证类字段）。
	// 仅对 Export 策略有效。
	Omit []string
	// Reason 豁免依据（Exempt 必填；其他策略可空）。
	Reason string
	// Collect 导出采集闭包（Policy 含 Export 时必填）。
	Collect CollectFunc
	// Erase 删除闭包（Policy 含 Erase 时必填）。
	Erase EraseFunc
	// Anonymize 匿名化闭包（Policy 含 Anonymize 时必填）。
	Anonymize AnonymizeFunc
}

// Registry 归属键注册表。Register 应发生在装配期；Tables 可并发读。
type Registry struct {
	mu     sync.RWMutex
	tables []Table
	names  map[string]struct{}
}

// NewRegistry 空注册表。
func NewRegistry() *Registry {
	return &Registry{names: map[string]struct{}{}}
}

// Register 登记一张表（幂等性不做：重复名直接拒绝）。
func (r *Registry) Register(t Table) error {
	name := strings.TrimSpace(t.Name)
	if name == "" {
		return fmt.Errorf("%w: Name 不能为空", ErrInvalidTable)
	}
	if name == KeyExportedAt || name == KeySubject {
		return fmt.Errorf("%w: 表名 %q 与导出包元键冲突", ErrInvalidTable, name)
	}
	if strings.TrimSpace(t.OwnerColumn) == "" {
		return fmt.Errorf("%w: %s 缺 OwnerColumn", ErrInvalidTable, name)
	}
	if !t.Policy.valid() {
		return fmt.Errorf("%w: %s 策略 %q 非法", ErrInvalidTable, name, t.Policy)
	}
	if t.Policy == Exempt {
		if strings.TrimSpace(t.Reason) == "" {
			return fmt.Errorf("%w: %s 豁免必须写明 Reason", ErrInvalidTable, name)
		}
		if t.Collect != nil || t.Erase != nil || t.Anonymize != nil {
			return fmt.Errorf("%w: %s 豁免表不应带闭包", ErrInvalidTable, name)
		}
	}
	if t.Policy.Has(Export) && t.Collect == nil {
		return fmt.Errorf("%w: %s Export 策略缺 Collect", ErrInvalidTable, name)
	}
	if t.Policy.Has(Erase) && t.Erase == nil {
		return fmt.Errorf("%w: %s Erase 策略缺 Erase 闭包", ErrInvalidTable, name)
	}
	if t.Policy.Has(Anonymize) && t.Anonymize == nil {
		return fmt.Errorf("%w: %s Anonymize 策略缺 Anonymize 闭包", ErrInvalidTable, name)
	}
	if len(t.Omit) > 0 && !t.Policy.Has(Export) {
		return fmt.Errorf("%w: %s 的 Omit 仅对 Export 策略有效", ErrInvalidTable, name)
	}
	t.Name = name
	if len(t.Omit) > 0 {
		t.Omit = append([]string(nil), t.Omit...)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.names[name]; ok {
		return fmt.Errorf("%w: %s", ErrDuplicateTable, name)
	}
	r.names[name] = struct{}{}
	r.tables = append(r.tables, t)
	return nil
}

// MustRegister 装配期便利：登记失败即 panic（程序错误，不是运行期错误）。
func (r *Registry) MustRegister(t Table) {
	if err := r.Register(t); err != nil {
		panic(err)
	}
}

// Tables 按登记顺序返回快照（执行顺序 = 登记顺序）。
func (r *Registry) Tables() []Table {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Table, len(r.tables))
	for i, t := range r.tables {
		out[i] = t
		if len(t.Omit) > 0 {
			out[i].Omit = append([]string(nil), t.Omit...)
		}
	}
	return out
}

// Names 已登记表名（按登记顺序；评审「新表是否登记」的单一清单）。
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, len(r.tables))
	for i, t := range r.tables {
		out[i] = t.Name
	}
	return out
}

// Bundle 导出包：元键 + 表名 → 采集结果。
type Bundle map[string]any

// ExporterConfig 导出装配。
type ExporterConfig struct {
	Registry *Registry
	Now      func() time.Time // 可注入时钟；缺省 time.Now
}

// SubjectExporter 按注册表遍历的数据主体导出器。
type SubjectExporter struct {
	reg *Registry
	now func() time.Time
}

// NewSubjectExporter 构造导出器。
func NewSubjectExporter(cfg ExporterConfig) (*SubjectExporter, error) {
	if cfg.Registry == nil {
		return nil, ErrNoRegistry
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	return &SubjectExporter{reg: cfg.Registry, now: nowFn}, nil
}

// Export 采集主体的全部 Export 策略表。Exempt/仅 Erase/仅 Anonymize 的表
// 不进导出包；任一采集失败即整体失败（不返回半包）。
func (e *SubjectExporter) Export(ctx context.Context, subject string) (Bundle, error) {
	if strings.TrimSpace(subject) == "" {
		return nil, ErrSubject
	}
	bundle := Bundle{
		KeyExportedAt: e.now().UTC().Format(time.RFC3339),
		KeySubject:    subject,
	}
	for _, t := range e.reg.Tables() {
		if !t.Policy.Has(Export) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		v, err := t.Collect(ctx, subject)
		if err != nil {
			return nil, fmt.Errorf("privacy: export %s: %w", t.Name, err)
		}
		if len(t.Omit) > 0 {
			v, err = omitFields(v, t.Omit)
			if err != nil {
				return nil, fmt.Errorf("privacy: export %s: %w", t.Name, err)
			}
		}
		bundle[t.Name] = v
	}
	return bundle, nil
}

// omitFields 按 JSON 字段名剔除顶层字段：对象直接删；对象数组对每个元素
// 删；其他形态原样返回（不强行改造宿主载荷）。
func omitFields(v any, fields []string) (any, error) {
	if v == nil {
		return nil, nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("字段剔除序列化失败: %w", err)
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("字段剔除反序列化失败: %w", err)
	}
	switch x := decoded.(type) {
	case map[string]any:
		for _, f := range fields {
			delete(x, f)
		}
		return x, nil
	case []any:
		for _, item := range x {
			if m, ok := item.(map[string]any); ok {
				for _, f := range fields {
					delete(m, f)
				}
			}
		}
		return x, nil
	default:
		return v, nil
	}
}

// TombstoneStore 墓碑名册的宿主持久化（setting 单键 JSON / 名册表等）。
// Load/Save 的读改写需由宿主串行化（同一主体的删除本应串行执行）。
type TombstoneStore interface {
	Load(ctx context.Context) ([]string, error)
	Save(ctx context.Context, names []string) error
}

// AppendTombstone 幂等追加墓碑名：已存在不重复写。
func AppendTombstone(ctx context.Context, store TombstoneStore, subject string) error {
	if strings.TrimSpace(subject) == "" {
		return ErrSubject
	}
	if store == nil {
		return ErrNoTombstoneStore
	}
	names, err := store.Load(ctx)
	if err != nil {
		return fmt.Errorf("privacy: 墓碑读取失败: %w", err)
	}
	if slices.Contains(names, subject) {
		return nil
	}
	names = append(names, subject)
	if err := store.Save(ctx, names); err != nil {
		return fmt.Errorf("privacy: 墓碑写入失败: %w", err)
	}
	return nil
}

// EraseReport 删除回执（表名 → 行数；匿名化表记 1）。
type EraseReport map[string]int64

// Total 回执行数总和（审计/响应展示用）。
func (r EraseReport) Total() int64 {
	var n int64
	for _, v := range r {
		n += v
	}
	return n
}

// EraserConfig 删除装配。Tombstones 可 nil（不落墓碑）。
type EraserConfig struct {
	Registry   *Registry
	Tombstones TombstoneStore
}

// SubjectEraser 按注册表遍历的数据主体删除器。
type SubjectEraser struct {
	reg     *Registry
	records TombstoneStore
}

// NewSubjectEraser 构造删除器。
func NewSubjectEraser(cfg EraserConfig) (*SubjectEraser, error) {
	if cfg.Registry == nil {
		return nil, ErrNoRegistry
	}
	return &SubjectEraser{reg: cfg.Registry, records: cfg.Tombstones}, nil
}

// Erase 删除主体数据：按登记顺序执行全部 Erase 表 → 追加墓碑 → 执行
// Anonymize 表。返回删除回执与匿名化后的主体名（匿名化闭包返回的第一个
// 非空别名；无 Anonymize 表时为空串）。任一环节失败即整体失败（不返回
// 半截回执；已执行的删除不可回滚是宿主事务边界责任）。
func (e *SubjectEraser) Erase(ctx context.Context, subject string) (EraseReport, string, error) {
	if strings.TrimSpace(subject) == "" {
		return nil, "", ErrSubject
	}
	report := EraseReport{}
	for _, t := range e.reg.Tables() {
		if !t.Policy.Has(Erase) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		n, err := t.Erase(ctx, subject, DefaultChunkSize)
		if err != nil {
			return nil, "", fmt.Errorf("privacy: erase %s: %w", t.Name, err)
		}
		report[t.Name] = n
	}
	if e.records != nil {
		if err := AppendTombstone(ctx, e.records, subject); err != nil {
			return nil, "", fmt.Errorf("privacy: 墓碑追加: %w", err)
		}
	}
	alias := ""
	for _, t := range e.reg.Tables() {
		if !t.Policy.Has(Anonymize) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		a, err := t.Anonymize(ctx, subject)
		if err != nil {
			return nil, "", fmt.Errorf("privacy: anonymize %s: %w", t.Name, err)
		}
		report[t.Name] = 1
		if alias == "" && a != "" {
			alias = a
		}
	}
	return report, alias, nil
}

// ChunkDelete 分块删除原语：按 batch 切 keys 调 del，返回跨批累加的行数。
// batch <= 0 落 [DefaultChunkSize]；keys 为空直接返回；中途失败返回已累计
// 行数与错误。keys 的类型由宿主决定（会话 ID/用户名/主键等）。
func ChunkDelete[T any](ctx context.Context, keys []T, batch int, del func(context.Context, []T) (int64, error)) (int64, error) {
	if del == nil {
		return 0, ErrNoDelete
	}
	if batch <= 0 {
		batch = DefaultChunkSize
	}
	var total int64
	for start := 0; start < len(keys); start += batch {
		end := min(start+batch, len(keys))
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, err := del(ctx, keys[start:end])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
