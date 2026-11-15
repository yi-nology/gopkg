package stager

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Stager 引用解析 + staging 物化 + env 组装。并发安全：同一 Stager 的
// Stage/RestageBindings/Cleanup 串行执行（staging 目录是共享资产）。
type Stager struct {
	registry    Registry
	decryptor   Decryptor
	root        string
	inst        string
	maxViaDepth int
	renderers   map[string]Renderer

	mu          sync.Mutex
	loadedRefs  map[string][]string // server→原始 refs（RestageBindings 重放）
	loadedNames map[string][]string // server→显式请求面实例名（反查提示）
}

// NewStager 构造。Root 必填并转绝对路径；构造时清扫本实例 staging 根
// （boot 时子进程未起，安全）。InstanceID 为空用 "default"。
func NewStager(cfg Config) (*Stager, error) {
	if cfg.Registry == nil {
		return nil, errors.New("stager: Registry 未装配")
	}
	if cfg.Decryptor == nil {
		return nil, errors.New("stager: Decryptor 未装配")
	}
	if strings.TrimSpace(cfg.Root) == "" {
		return nil, errors.New("stager: Root 未配置")
	}
	inst := strings.TrimSpace(cfg.InstanceID)
	if inst == "" {
		inst = "default"
	}
	if err := validateSegment(inst, "instance_id"); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(cfg.Root)
	if err != nil {
		return nil, fmt.Errorf("stager: Root 转绝对路径失败: %w", err)
	}
	depth := cfg.MaxViaDepth
	if depth <= 0 {
		depth = 3
	}
	st := &Stager{
		registry: cfg.Registry, decryptor: cfg.Decryptor,
		root: abs, inst: inst, maxViaDepth: depth,
		renderers:   make(map[string]Renderer, len(builtinRenderers)+len(cfg.Renderers)),
		loadedRefs:  map[string][]string{},
		loadedNames: map[string][]string{},
	}
	for name, r := range builtinRenderers {
		st.renderers[name] = r
	}
	for name, r := range cfg.Renderers {
		if r == nil {
			return nil, fmt.Errorf("stager: renderer %q 为空", name)
		}
		st.renderers[name] = r
	}
	if err := os.RemoveAll(st.instanceDir()); err != nil {
		return nil, fmt.Errorf("stager: 清扫实例 staging 根失败: %w", err)
	}
	if err := os.MkdirAll(st.instanceDir(), 0o700); err != nil {
		return nil, fmt.Errorf("stager: 创建实例 staging 根失败: %w", err)
	}
	return st, nil
}

// Root staging 根目录（绝对路径）。
func (st *Stager) Root() string { return st.root }

// InstanceID 当前实例/副本 id。
func (st *Stager) InstanceID() string { return st.inst }

// InstanceDir 当前实例 staging 根（Root/InstanceID）。
func (st *Stager) InstanceDir() string { return st.instanceDir() }

func (st *Stager) instanceDir() string { return filepath.Join(st.root, st.inst) }

func (st *Stager) serverDir(server string) string { return filepath.Join(st.instanceDir(), server) }

// Stage 为一个 server 物化凭证：解析 refs（"type:*"/"type:name"）→ via
// 递归展开 → 落盘文件 + 组装 env。缺失/禁用/解密失败/引用链断裂跳过留痕
// 不报错；类型未声明/类型不符/renderer 未注册/路径逃逸属配置错误，返回
// error。
func (st *Stager) Stage(ctx context.Context, server string, refs []string) (*Staged, error) {
	if err := validateSegment(server, "server"); err != nil {
		return nil, err
	}
	st.mu.Lock()
	defer st.mu.Unlock()

	out := &Staged{Staged: []string{}, Skipped: []SkipNote{}, Files: []string{}, Env: []string{}}
	if len(refs) == 0 {
		return out, nil
	}
	dir := st.serverDir(server)
	// 写-后-剪：不清空目录——resync 期间运行中子进程可能正在读 staging，
	// 先删后写会读到空目录。先建目录，最后只剪陈旧文件。
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("stager: 创建 server staging 目录失败: %w", err)
	}
	res := &resolver{st: st, ctx: ctx, entries: map[string]*instEntry{}, lists: map[string][]InstanceInfo{}}
	roots, err := st.resolveRoots(res, refs, out)
	if err != nil {
		return nil, err
	}
	order := st.expandVias(res, roots, out)
	keep := map[string]bool{}
	if err := st.materialize(res, order, dir, out, keep); err != nil {
		return nil, err
	}
	st.assembleEnv(res, refs, order, dir, out)
	pruneStale(dir, keep)

	st.loadedRefs[server] = append([]string(nil), refs...)
	st.loadedNames[server] = append([]string(nil), roots...)
	return out, nil
}

// resolver 单次 Stage 内的实例解析缓存：同一实例的元数据查询与解密在
// resolve/via/物化/env 四阶段只做一次（RestageBindings 串行重放全部
// server 时不放大解密成本）。失败结论同样缓存。
type resolver struct {
	st      *Stager
	ctx     context.Context
	entries map[string]*instEntry
	lists   map[string][]InstanceInfo
}

type instEntry struct {
	info    InstanceInfo
	infoErr error
	fields  map[string]string
	decErr  error
	decDone bool
}

func (r *resolver) info(name string) (InstanceInfo, error) {
	if e, ok := r.entries[name]; ok {
		return e.info, e.infoErr
	}
	info, err := r.st.registry.Instance(name)
	if err != nil {
		if errors.Is(err, ErrInstanceNotFound) {
			err = fmt.Errorf("%w: %s", ErrInstanceNotFound, name)
		} else {
			err = fmt.Errorf("实例查询失败: %s: %w", name, err)
		}
	}
	e := &instEntry{info: info, infoErr: err}
	r.entries[name] = e
	return info, err
}

func (r *resolver) fields(name string) (InstanceInfo, map[string]string, error) {
	info, err := r.info(name)
	if err != nil {
		return info, nil, err
	}
	e := r.entries[name]
	if !e.decDone {
		fields, derr := r.st.decryptor.Fields(r.ctx, name)
		e.fields, e.decErr, e.decDone = fields, derr, true
	}
	if e.decErr != nil {
		return info, nil, fmt.Errorf("%w: %s: %v", ErrDecrypt, name, e.decErr)
	}
	if e.fields == nil {
		e.fields = map[string]string{}
	}
	return info, e.fields, nil
}

func (r *resolver) list(typeName string) ([]InstanceInfo, error) {
	if infos, ok := r.lists[typeName]; ok {
		return infos, nil
	}
	infos, err := r.st.registry.Instances(typeName)
	if err != nil {
		return nil, err
	}
	r.lists[typeName] = infos
	return infos, nil
}

// resolveRoots 阶段①：refs → 显式请求面（root 实例名）。类型未声明属配置
// 错误；type:* 只展开启用且全局档的实例；实例缺失/禁用属运行数据问题，
// 跳过留痕。
func (st *Stager) resolveRoots(res *resolver, refs []string, out *Staged) ([]string, error) {
	roots := []string{}
	seen := map[string]bool{}
	for _, raw := range refs {
		ref, err := ParseRef(raw)
		if err != nil {
			return nil, err
		}
		if _, ok := st.registry.Type(ref.Type); !ok {
			return nil, fmt.Errorf("%w: %q", ErrUnknownType, raw)
		}
		if ref.Wildcard {
			infos, err := res.list(ref.Type)
			if err != nil {
				return nil, fmt.Errorf("stager: 展开 %q 失败: %w", raw, err)
			}
			for _, info := range infos {
				if info.Type != ref.Type || !info.Enabled || !globalScope(info.Scope) {
					continue
				}
				if !seen[info.Name] {
					seen[info.Name] = true
					roots = append(roots, info.Name)
				}
			}
			continue
		}
		info, err := res.info(ref.Name)
		if err != nil {
			addSkip(out, ref.Name, skipReason(err))
			continue
		}
		if info.Type != ref.Type {
			return nil, fmt.Errorf("%w: %q 实际为 %q", ErrTypeMismatch, raw, info.Type)
		}
		if !info.Enabled {
			addSkip(out, ref.Name, skipReason(ErrInstanceDisabled))
			continue
		}
		if !seen[ref.Name] {
			seen[ref.Name] = true
			roots = append(roots, ref.Name)
		}
	}
	return roots, nil
}

// expandVias 阶段②：credential_ref 字段递归展开，产出依赖序（被引用者
// 在前）的物化清单。链上任一环不可用 → 根整体跳过；引用环/深度超限同样
// 按跳过处理（运行数据/配置链问题，不拖垮其他根）。
func (st *Stager) expandVias(res *resolver, roots []string, out *Staged) []string {
	done := map[string]bool{}
	visiting := map[string]bool{}
	order := []string{}
	var expand func(name string, depth int, chain string) error
	expand = func(name string, depth int, chain string) error {
		if done[name] {
			return nil
		}
		if visiting[name] {
			return fmt.Errorf("%w: %s%s", ErrCycle, chain, name)
		}
		if depth > st.maxViaDepth {
			return fmt.Errorf("%w（>%d）: %s", ErrTooDeep, st.maxViaDepth, name)
		}
		info, fields, err := res.fields(name)
		if err != nil {
			return err
		}
		if !info.Enabled {
			return ErrInstanceDisabled
		}
		spec, ok := st.registry.Type(info.Type)
		if !ok {
			return fmt.Errorf("%w: %s", ErrUnknownType, info.Type)
		}
		visiting[name] = true
		defer delete(visiting, name)
		for _, f := range spec.Fields {
			if f.Kind != "credential_ref" {
				continue
			}
			target := strings.TrimSpace(fields[f.Name])
			if target == "" {
				continue
			}
			if err := expand(target, depth+1, chain+name+"→"); err != nil {
				return fmt.Errorf("引用链 %s→%s: %w", name, target, err)
			}
		}
		done[name] = true
		order = append(order, name)
		return nil
	}
	for _, root := range roots {
		if err := expand(root, 0, ""); err != nil {
			addSkip(out, root, skipReason(err))
		}
	}
	return order
}

// materialize 阶段③：按依赖序落盘文件（ContentFrom 直取 / renderer 渲染，
// 限界 + 原子写）。缺失/解密失败跳过留痕；renderer 未注册/落盘失败/
// 路径逃逸属配置或环境故障，fail-fast。
func (st *Stager) materialize(res *resolver, order []string, dir string, out *Staged, keep map[string]bool) error {
	for _, name := range order {
		info, fields, err := res.fields(name)
		if err != nil {
			addSkip(out, name, skipReason(err))
			continue
		}
		if !info.Enabled {
			addSkip(out, name, skipReason(ErrInstanceDisabled))
			continue
		}
		spec, ok := st.registry.Type(info.Type)
		if !ok {
			return fmt.Errorf("%w: %s", ErrUnknownType, info.Type)
		}
		for _, fs := range spec.Files {
			if SkipByWhen(fs.When, fields) {
				continue
			}
			var content string
			if fs.ContentFrom != "" {
				content = fields[fs.ContentFrom]
			} else {
				rn := st.renderers[spec.Renderer]
				if rn == nil {
					return fmt.Errorf("%w: 类型 %s renderer %q", ErrNoRenderer, info.Type, spec.Renderer)
				}
				content, err = rn(name, fields, dir)
				if err != nil {
					return fmt.Errorf("stager: 实例 %s 渲染失败: %w", name, err)
				}
			}
			rel := Interpolate(fs.Path, name, fields, dir)
			final, err := st.writeConfined(dir, rel, content, fs.Mode)
			if err != nil {
				return fmt.Errorf("stager: 实例 %s 落盘失败: %w", name, err)
			}
			out.Files = append(out.Files, rel)
			keep[final] = true
		}
		out.Staged = append(out.Staged, name)
	}
	return nil
}

// assembleEnv 阶段④：base 条目（仅 ${staging_dir}）按绑定类型恒注入；
// per-instance 条目随实例追加；同名值去重后按 ":" 拼接（KUBECONFIG 多文件
// 语义）。
func (st *Stager) assembleEnv(res *resolver, refs []string, order []string, dir string, out *Staged) {
	bound := map[string]bool{}
	for _, raw := range refs {
		if ref, err := ParseRef(raw); err == nil {
			bound[ref.Type] = true
		}
	}
	types := make([]string, 0, len(bound))
	for typ := range bound {
		types = append(types, typ)
	}
	sort.Strings(types)

	byName := map[string][]string{}
	envOrder := []string{}
	addEnv := func(name, val string) {
		if containsString(byName[name], val) {
			return
		}
		byName[name] = append(byName[name], val)
		envOrder = append(envOrder, name)
	}

	for _, typ := range types {
		spec, ok := st.registry.Type(typ)
		if !ok {
			continue
		}
		for _, e := range spec.Env {
			if !perInstanceTemplate(e.Value) {
				addEnv(e.Name, Interpolate(e.Value, "", map[string]string{}, dir))
			}
		}
	}
	for _, name := range order {
		info, fields, err := res.fields(name)
		if err != nil {
			continue
		}
		spec, ok := st.registry.Type(info.Type)
		if !ok {
			continue
		}
		for _, e := range spec.Env {
			if perInstanceTemplate(e.Value) {
				addEnv(e.Name, Interpolate(e.Value, name, fields, dir))
			}
		}
	}
	for _, n := range envOrder {
		out.Env = append(out.Env, n+"="+strings.Join(byName[n], ":"))
	}
}

// RestageBindings 重物化全部已绑定 server 的 staging（凭证变更即时生效
// 通道）：ssh 类消费端每次建连重读 staging 目录，重写文件即对运行中进程
// 生效；env 绑定具体实例路径的新增实例仍需进程重启（由调用方如实呈现）。
// 返回快照的绑定表、各 server 重物化结果、以及失败 server 的错误（失败
// server 不出现在结果 map 中，避免静默丢生命周期）。
func (st *Stager) RestageBindings(ctx context.Context) (map[string][]string, map[string]*Staged, map[string]error) {
	st.mu.Lock()
	bindings := make(map[string][]string, len(st.loadedRefs))
	for server, refs := range st.loadedRefs {
		bindings[server] = append([]string(nil), refs...)
	}
	st.mu.Unlock()

	out := make(map[string]*Staged, len(bindings))
	failed := map[string]error{}
	for server, refs := range bindings {
		staged, err := st.Stage(ctx, server, refs)
		if err != nil {
			failed[server] = err
			continue
		}
		out[server] = staged
	}
	return bindings, out, failed
}

// StagedServers 反查：哪些已 Stage 的 server 显式请求了该实例（删除/停用
// 提示用；空集非 nil）。
func (st *Stager) StagedServers(instance string) []string {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := []string{}
	for server, names := range st.loadedNames {
		if containsString(names, instance) {
			out = append(out, server)
		}
	}
	sort.Strings(out)
	return out
}

// Cleanup 停机清理实例 staging 根。
func (st *Stager) Cleanup() error {
	st.mu.Lock()
	defer st.mu.Unlock()
	return os.RemoveAll(st.instanceDir())
}

// writeConfined 相对路径插值后限界检查 + 原子落盘（同目录临时文件 + rename）。
// 返回最终绝对路径（写-后-剪 keep 清单用）。
func (st *Stager) writeConfined(baseDir, rel, content, mode string) (string, error) {
	rel = strings.TrimSpace(rel)
	if rel == "" || filepath.IsAbs(rel) || strings.ContainsRune(rel, 0) {
		return "", fmt.Errorf("%w: %q", ErrPathEscape, rel)
	}
	clean := filepath.Clean(rel)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %q", ErrPathEscape, rel)
	}
	final := filepath.Join(baseDir, clean)
	if !strings.HasPrefix(final, baseDir+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %q", ErrPathEscape, rel)
	}
	perm, err := parseFileMode(mode)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(final), 0o700); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(filepath.Dir(final), ".stager-*")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	fail := func(err error) (string, error) {
		_ = f.Close()
		_ = os.Remove(tmp)
		return "", err
	}
	if err := f.Chmod(perm); err != nil {
		return fail(err)
	}
	if _, err := f.WriteString(content); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return final, nil
}

// pruneStale 剪除保留清单之外的陈旧文件与残留临时文件（先文件后空目录；
// 目录根保留；仅空目录会 Remove 成功）。
func pruneStale(dir string, keep map[string]bool) {
	var dirs []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil || p == dir {
			return nil
		}
		if d.IsDir() {
			dirs = append(dirs, p)
			return nil
		}
		if !keep[p] {
			_ = os.Remove(p)
		}
		return nil
	})
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	for _, d := range dirs {
		_ = os.Remove(d) // 仅空目录会成功
	}
}

// parseFileMode 只接受 0600（缺省）/0644，其余视为配置错误。
func parseFileMode(mode string) (os.FileMode, error) {
	switch strings.TrimSpace(mode) {
	case "", "0600":
		return 0o600, nil
	case "0644":
		return 0o644, nil
	default:
		return 0, fmt.Errorf("%w: %q（只允许 0600/0644）", ErrBadMode, mode)
	}
}

// validateSegment 校验 instance/server 路径段（不允许分隔符与 . / ..）。
func validateSegment(seg, field string) error {
	seg = strings.TrimSpace(seg)
	if seg == "" || seg == "." || seg == ".." {
		return fmt.Errorf("stager: %s 非法: %q", field, seg)
	}
	if strings.ContainsAny(seg, `/\`) || strings.ContainsRune(seg, 0) {
		return fmt.Errorf("stager: %s 含路径分隔符: %q", field, seg)
	}
	return nil
}

// addSkip 追加跳过留痕（同 name+reason 去重，避免 via 多路径重复噪声）。
func addSkip(out *Staged, name, reason string) {
	for _, s := range out.Skipped {
		if s.Name == name && s.Reason == reason {
			return
		}
	}
	out.Skipped = append(out.Skipped, SkipNote{Name: name, Reason: reason})
}

// skipReason 把内部错误变成人读的跳过原因（去掉包前缀，保留链上下文）。
func skipReason(err error) string {
	if err == nil {
		return ""
	}
	s := strings.TrimPrefix(err.Error(), "stager: ")
	return strings.ReplaceAll(s, "stager: ", "")
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// perInstanceTemplate 注入模板是否引用实例级占位符（${name}/${field}）——
// 仅含 ${staging_dir} 的条目与实例无关，零实例也必须注入。
func perInstanceTemplate(tpl string) bool {
	return strings.Contains(strings.ReplaceAll(tpl, "${staging_dir}", ""), "${")
}
