package credstage

import (
	"context"
	"errors"
	"sync"
)

// ScopeGlobal 全局档（平台面）；空串与 "global" 同义（存量行没有 scope 列值）。
const ScopeGlobal = "global"

// IsGlobalScope 是否全局档（type:* 通配展开的唯一放行档）。
func IsGlobalScope(scope string) bool { return scope == "" || scope == ScopeGlobal }

// ErrNotFound Decryptor.Get 未命中哨兵（宿主用 %w 包装）。
var ErrNotFound = errors.New("credstage: 凭证实例不存在")

// FieldDef 类型字段声明（本包只关心 credential_ref：via 递归的识别依据）。
type FieldDef struct {
	Name    string
	Kind    string // credential_ref 表示该字段指向另一实例名
	RefType string // kind=credential_ref 时的目标类型（宿主校验用；本包不强制）
}

// FileSpec staging 文件条目：ContentFrom 空=由 Renderer 生成（每类型至多一个）。
type FileSpec struct {
	Path        string // 相对 server 目录，支持 ${name}/${<field>}/${staging_dir} 插值
	Mode        string // "0600"|"0644"；空=0600
	ContentFrom string // 直接取字段值
	When        string // v1 仅支持 "<field> != ''"：字段为空则跳过该文件
}

// EnvSpec 注入环境变量：值支持 ${name}/${<field>}/${staging_dir}。
type EnvSpec struct {
	Name  string
	Value string
}

// InjectSpec 类型注入声明。
type InjectSpec struct {
	Renderer string
	Files    []FileSpec
	Env      []EnvSpec
}

// Type 凭证类型（宿主从 YAML/pack 加载后注入）。
type Type struct {
	Name   string
	Fields []FieldDef
	Inject InjectSpec
}

// Registry 凭证类型词表（宿主实现；内建/pack 类型加载与热替换留宿主）。
type Registry interface {
	Get(name string) (*Type, bool)
}

// Credential 物化所需的实例元数据（不含明文）。
type Credential struct {
	Name    string
	Type    string
	Enabled bool
	Scope   string // ""/"global"=平台面；其余档不参与 type:* 通配展开
}

// Decryptor 实例元数据 + 按实例解密的明文面（宿主实现加密/存储）。
// Get 未命中返回 ErrNotFound（可用 %w 包装）；List 返回全部实例元数据。
type Decryptor interface {
	Get(ctx context.Context, name string) (*Credential, error)
	List(ctx context.Context) ([]Credential, error)
	DecryptFields(ctx context.Context, cred *Credential) (map[string]string, error)
}

// RenderFunc 内建渲染器：为类型中 ContentFrom 为空的文件条目生成内容。
type RenderFunc func(instanceName string, fields map[string]string, stagingDir string) (string, error)

// 内建渲染器名（类型注入声明以名引用）。
const (
	RendererSSHHost         = "ssh-host"
	RendererDatasourcesYAML = "datasources-yaml"
)

// Renderers 渲染器注册表（并发安全；NewRenderers 已含内建两项）。
type Renderers struct {
	mu sync.RWMutex
	m  map[string]RenderFunc
}

// NewRenderers 构造含内建渲染器的注册表（宿主可再注册自定义渲染器）。
func NewRenderers() *Renderers {
	return &Renderers{m: map[string]RenderFunc{
		RendererSSHHost:         RenderSSHHost,
		RendererDatasourcesYAML: RenderDatasourcesYAML,
	}}
}

// Register 注册自定义渲染器（空名/nil/重名 fail-loud）。
func (r *Renderers) Register(name string, fn RenderFunc) error {
	if name == "" {
		return errors.New("credstage: renderer 名为空")
	}
	if fn == nil {
		return errors.New("credstage: renderer 为 nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.m[name]; ok {
		return errors.New("credstage: renderer 已注册: " + name)
	}
	r.m[name] = fn
	return nil
}

// Get 按名取渲染器。
func (r *Renderers) Get(name string) (RenderFunc, bool) {
	if r == nil {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	fn, ok := r.m[name]
	return fn, ok
}

// SkipNote 跳过实例与原因（降级不阻塞其他实例）。
type SkipNote struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// Staged 一次 Stage 的产物。
type Staged struct {
	Staged  []string   `json:"staged"`  // 成功物化的实例名（含 via 递归展开）
	Skipped []SkipNote `json:"skipped"` // 跳过实例与原因
	Files   []string   `json:"files"`   // 相对 server 目录的落盘路径
	Env     []string   `json:"env"`     // KEY=VALUE（同名多实例按 ":" 拼接去重）
}
