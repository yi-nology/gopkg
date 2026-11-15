package stager

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// 包级哨兵错误（errors.Is 判定）。
var (
	ErrInstanceNotFound = errors.New("stager: 实例不存在")
	ErrInstanceDisabled = errors.New("stager: 实例已禁用")
	ErrDecrypt          = errors.New("stager: 解密失败")
	ErrUnknownType      = errors.New("stager: 类型未声明")
	ErrTypeMismatch     = errors.New("stager: 引用类型不符")
	ErrCycle            = errors.New("stager: 引用环")
	ErrTooDeep          = errors.New("stager: 引用深度超限")
	ErrPathEscape       = errors.New("stager: 路径逃逸")
	ErrBadMode          = errors.New("stager: 文件权限非法")
	ErrNoRenderer       = errors.New("stager: renderer 未注册")
)

// 作用域：type:* 通配展开只取全局档（安全契约：平台级 MCP server 以平台
// 身份出网，把个人/团队凭证展开进来等于让任意用户凭证变成平台出网目标）。
const (
	ScopeGlobal = "global"
)

// SkipNote 跳过实例与原因（禁用/缺失/解密失败/引用环）——不阻塞其他实例。
type SkipNote struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// Staged 一次 Stage 的产物。
type Staged struct {
	Staged  []string   `json:"staged"`  // 成功物化的实例名（含 via 递归展开）
	Skipped []SkipNote `json:"skipped"` // 跳过实例与原因
	Files   []string   `json:"files"`   // 相对 serverDir 的落盘路径
	Env     []string   `json:"env"`     // KEY=VALUE（同名多实例按 ":" 拼接去重）
}

// EnvMap 把 Env 列表解析为 map（KEY→VALUE；首 "=" 之前为键）。
func (s *Staged) EnvMap() map[string]string {
	out := make(map[string]string, len(s.Env))
	for _, kv := range s.Env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		out[k] = v
	}
	return out
}

// FieldSpec 类型字段声明。Kind=credential_ref 的字段携带「另一个实例名」，
// 物化时递归展开（via 链）。其余 kind 只供宿主表单/校验使用，本包忽略。
type FieldSpec struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// FileSpec staging 文件条目。ContentFrom 为空时由 TypeSpec.Renderer 生成。
type FileSpec struct {
	Path        string `json:"path"`         // 相对 staging 根；${name}/${staging_dir}/${field} 插值
	Mode        string `json:"mode"`         // 0600（缺省）|0644
	ContentFrom string `json:"content_from"` // 明文字段名
	When        string `json:"when"`         // "<field> != ''"：字段为空则跳过该文件
}

// EnvSpec 注入环境变量：值支持 ${name}/${field}/${staging_dir}。
type EnvSpec struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Renderer 文件内容渲染器：只产出内容，落点由 FileSpec 声明。
type Renderer func(instance string, fields map[string]string, stagingDir string) (string, error)

// TypeSpec 凭证类型声明（宿主 Registry 返回的投影）。
type TypeSpec struct {
	Fields   []FieldSpec `json:"fields"`
	Files    []FileSpec  `json:"files"`
	Env      []EnvSpec   `json:"env"`
	Renderer string      `json:"renderer"` // ""=只用 ContentFrom；"ssh-host"/"datasources-yaml" 为内建
}

// InstanceInfo 实例元数据（宿主 Registry 返回的投影）。
type InstanceInfo struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Enabled bool   `json:"enabled"`
	// Scope 作用域："global"（或空串，兼容无 scope 列的存量）参与 type:*
	// 通配展开；个人/团队档不参与。
	Scope string `json:"scope,omitempty"`
}

// Registry 凭证类型与实例声明面（宿主实现；实例名全局唯一）。
type Registry interface {
	// Type 按名取类型声明；ok=false 表示未声明（配置错误，Stage 报错）。
	Type(name string) (*TypeSpec, bool)
	// Instances 返回某类型的全部实例（type:* 展开用；含禁用/非全局档，
	// 由 Stager 过滤）。错误是存储故障，Stage 直接上抛。
	Instances(typeName string) ([]InstanceInfo, error)
	// Instance 按名取实例元数据。缺失应返回 [ErrInstanceNotFound]（或其
	// 包装）；其他错误按运行数据问题跳过留痕。
	Instance(name string) (InstanceInfo, error)
}

// Decryptor 明文字段读取面（宿主实现；加密/密钥不出宿主）。
type Decryptor interface {
	Fields(ctx context.Context, instance string) (map[string]string, error)
}

// Ref 解析后的凭证引用。
type Ref struct {
	Type     string
	Name     string
	Wildcard bool
}

// ParseRef 解析 "type:name" / "type:*"（也接受裸 "type" 视为通配，兼容
// 参考实现的无 name 形态）。类型名与实例名都做 TrimSpace。
func ParseRef(raw string) (Ref, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Ref{}, errors.New("stager: 凭证引用为空")
	}
	typ, name, hasName := strings.Cut(s, ":")
	typ, name = strings.TrimSpace(typ), strings.TrimSpace(name)
	if typ == "" {
		return Ref{}, fmt.Errorf("stager: 凭证引用 %q 缺类型", raw)
	}
	if !hasName || name == "" || name == "*" {
		return Ref{Type: typ, Wildcard: true}, nil
	}
	return Ref{Type: typ, Name: name}, nil
}

// globalScope 空串与 global 同义（存量行没有 scope 列值）。
func globalScope(scope string) bool {
	return scope == "" || scope == ScopeGlobal
}

// Config Stager 装配参数。
type Config struct {
	Registry  Registry
	Decryptor Decryptor
	// Root staging 根目录（必填；构造时转绝对路径）。
	Root string
	// InstanceID 实例/副本 id（空="default"）；物化目录为 Root/InstanceID/。
	InstanceID string
	// MaxViaDepth via 递归深度上限；<=0 用 3。
	MaxViaDepth int
	// Renderers 宿主自定义渲染器（按 TypeSpec.Renderer 名字引用）；同名
	// 时覆盖内建。
	Renderers map[string]Renderer
}
