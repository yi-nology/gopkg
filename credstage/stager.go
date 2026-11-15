package credstage

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

// MaxViaDepth via 链最大递归深度（同 bianque 口径：超过 3 层视为配置错误）。
const MaxViaDepth = 3

// Options Stager 装配选项。
type Options struct {
	Registry   Registry
	Decryptor  Decryptor
	Root       string // staging 根（绝对/相对均可，内部转绝对）
	InstanceID string // 空="default"；per-instance 目录防双副本互踩
	Renderers  *Renderers
}

// Stager 引用解析 + staging 物化 + env 组装。并发安全（Stage 全局串行，
// 避免同 server 写-后-剪与 resync 交叉）。
type Stager struct {
	reg       Registry
	dec       Decryptor
	renderers *Renderers
	root      string
	inst      string
	mu        sync.Mutex
	// loadedRefs server→原始引用（RestageBindings 重放用，保留通配符）
	loadedRefs map[string][]string
	// loadedNames server→显式请求面实例名（StagedServers 反查；递归被引用者不登记）
	loadedNames map[string][]string
}

// New 装配 Stager：校验依赖、建立 per-instance 根并收紧到 0700。
func New(opts Options) (*Stager, error) {
	if opts.Registry == nil {
		return nil, errors.New("credstage: Registry 未装配")
	}
	if opts.Decryptor == nil {
		return nil, errors.New("credstage: Decryptor 未装配")
	}
	if strings.TrimSpace(opts.Root) == "" {
		return nil, errors.New("credstage: Root 未配置")
	}
	abs, err := filepath.Abs(opts.Root)
	if err != nil {
		return nil, fmt.Errorf("credstage: Root 解析失败: %w", err)
	}
	inst := opts.InstanceID
	if inst == "" {
		inst = "default"
	}
	if !safeSegment(inst) {
		return nil, fmt.Errorf("credstage: InstanceID %q 非法（不得含路径分隔符/点段）", inst)
	}
	rend := opts.Renderers
	if rend == nil {
		rend = NewRenderers()
	}
	st := &Stager{
		reg:         opts.Registry,
		dec:         opts.Decryptor,
		renderers:   rend,
		root:        abs,
		inst:        inst,
		loadedRefs:  map[string][]string{},
		loadedNames: map[string][]string{},
	}
	if err := os.MkdirAll(st.instanceRoot(), 0o700); err != nil {
		return nil, fmt.Errorf("credstage: 创建 staging 根: %w", err)
	}
	if err := os.Chmod(st.instanceRoot(), 0o700); err != nil {
		return nil, fmt.Errorf("credstage: 收紧 staging 根权限: %w", err)
	}
	return st, nil
}

func (st *Stager) instanceRoot() string { return filepath.Join(st.root, st.inst) }

func (st *Stager) serverDir(server string) string { return filepath.Join(st.instanceRoot(), server) }

// Stage 为一个 MCP server 物化凭证：解析 refs（"type:*"/"type:name"）→ via 递归
// 展开 → 原子落盘 + 组装 env → 剪除陈旧文件。
//
// 缺失/禁用/解密失败属运行数据问题：SkipNote 留痕不报错；ref 类型未声明属
// 配置错误：报错；renderer 未注册/落盘/剪除失败：fail-loud。
func (st *Stager) Stage(ctx context.Context, server string, refs []string) (*Staged, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if !safeSegment(server) {
		return nil, fmt.Errorf("credstage: server 名 %q 非法（不得含路径分隔符/点段）", server)
	}
	dir := st.serverDir(server)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("credstage: 创建 server staging 目录: %w", err)
	}
	out := &Staged{}
	keep := map[string]bool{}
	// refs 为空 = 解绑：剪除全部文件（旧明文不留在磁盘）。
	if len(refs) == 0 {
		if err := pruneStale(dir, keep); err != nil {
			return nil, fmt.Errorf("credstage: 剪除 staging 文件: %w", err)
		}
		st.loadedRefs[server] = nil
		st.loadedNames[server] = nil
		return out, nil
	}

	res := &stageResolver{st: st, ctx: ctx, rows: map[string]stageEntry{}}
	roots, err := st.resolveRoots(res, refs, out)
	if err != nil {
		return nil, err
	}
	order := st.expandVias(res, roots, out)
	if err := st.materialize(res, order, dir, out, keep); err != nil {
		return nil, err
	}
	if err := st.assembleEnv(res, refs, order, dir, out); err != nil {
		return nil, err
	}
	// 写-后-剪：新文件已原子落位，再剪除本次清单之外的陈旧文件与 .tmp 残留。
	if err := pruneStale(dir, keep); err != nil {
		return nil, fmt.Errorf("credstage: 剪除 staging 文件: %w", err)
	}
	st.loadedRefs[server] = append([]string(nil), refs...)
	st.loadedNames[server] = append([]string(nil), roots...)
	return out, nil
}

// stageResolver 单次 Stage 内的实例解析缓存：同一实例的 Get 与解密在
// resolve/via/物化/env 四阶段只做一次（RestageBindings 串行重放时避免线性
// 放大 AES-GCM）；失败结论同样缓存。
type stageResolver struct {
	st    *Stager
	ctx   context.Context
	rows  map[string]stageEntry
	list  []Credential
	listd bool
}

type stageEntry struct {
	cred    *Credential
	getErr  error
	fields  map[string]string
	decErr  error
	decDone bool
}

func (r *stageResolver) get(name string) (*Credential, error) {
	e, ok := r.rows[name]
	if !ok {
		cred, err := r.st.dec.Get(r.ctx, name)
		if err == nil && cred == nil {
			err = ErrNotFound
		}
		e = stageEntry{cred: cred, getErr: err}
		r.rows[name] = e
	}
	return e.cred, e.getErr
}

func (r *stageResolver) resolveFields(name string) (*Credential, map[string]string, error) {
	cred, err := r.get(name)
	if err != nil {
		return nil, nil, err
	}
	e := r.rows[name]
	if !e.decDone {
		fields, derr := r.st.dec.DecryptFields(r.ctx, cred)
		e.fields, e.decErr, e.decDone = fields, derr, true
		r.rows[name] = e
	}
	if e.decErr != nil {
		return cred, nil, e.decErr
	}
	return cred, e.fields, nil
}

func (r *stageResolver) listAll() ([]Credential, error) {
	if !r.listd {
		rows, err := r.st.dec.List(r.ctx)
		if err != nil {
			return nil, err
		}
		r.list, r.listd = rows, true
	}
	return r.list, nil
}

// resolveRoots 阶段①：refs → 显式请求面（root 实例名）。ref 类型未声明属配置
// 错误报错；"type:*"/无 name → 该类型全部启用且全局档实例；实例不存在/已禁用
// 跳过留痕；类型不符属引用书写错误报错。
func (st *Stager) resolveRoots(res *stageResolver, refs []string, out *Staged) ([]string, error) {
	var roots []string
	for _, ref := range refs {
		typ, name, hasName := strings.Cut(ref, ":")
		if _, ok := st.reg.Get(typ); !ok {
			return nil, fmt.Errorf("凭证引用 %q 类型未声明", ref)
		}
		if !hasName || name == "" || name == "*" {
			rows, err := res.listAll()
			if err != nil {
				return nil, fmt.Errorf("列出凭证实例: %w", err)
			}
			var names []string
			for _, row := range rows {
				// type:* 只展开全局档：平台级子进程的凭证面不得混入个人/团队档。
				if row.Type == typ && row.Enabled && IsGlobalScope(row.Scope) {
					names = append(names, row.Name)
				}
			}
			slices.Sort(names)
			roots = append(roots, names...)
			continue
		}
		cred, err := res.get(name)
		if errors.Is(err, ErrNotFound) {
			out.Skipped = append(out.Skipped, SkipNote{Name: name, Reason: "实例不存在"})
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("读取凭证 %s: %w", name, err)
		}
		if cred.Type != typ {
			return nil, fmt.Errorf("凭证引用 %q 类型不符（实例实际为 %s）", ref, cred.Type)
		}
		if !cred.Enabled {
			out.Skipped = append(out.Skipped, SkipNote{Name: name, Reason: "已禁用"})
			continue
		}
		roots = append(roots, name)
	}
	return roots, nil
}

// expandVias 阶段②：via（credential_ref 字段）递归展开，产出依赖序（被引用者
// 在前）物化清单；链上任一环不可用 → 根整体跳过（SkipNote）；引用环/深度超限
// 直接报错（配置错误，根跳过并留痕）。
func (st *Stager) expandVias(res *stageResolver, roots []string, out *Staged) []string {
	expanded := map[string]bool{}
	inStack := map[string]bool{}
	var stack []string
	var order []string
	var expand func(name string, depth int) error
	expand = func(name string, depth int) error {
		if expanded[name] {
			return nil
		}
		if inStack[name] {
			path := append(append([]string{}, stack...), name)
			return fmt.Errorf("引用环: %s", strings.Join(path, "→"))
		}
		if depth > MaxViaDepth {
			return fmt.Errorf("引用深度超限（>%d）", MaxViaDepth)
		}
		cred, fields, err := res.resolveFields(name)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return errors.New("实例不存在")
			}
			return err
		}
		if !cred.Enabled {
			return errors.New("已禁用")
		}
		t, ok := st.reg.Get(cred.Type)
		if !ok {
			return fmt.Errorf("类型 %q 未声明", cred.Type)
		}
		inStack[name] = true
		stack = append(stack, name)
		defer func() {
			delete(inStack, name)
			stack = stack[:len(stack)-1]
		}()
		for _, f := range t.Fields {
			if f.Kind != "credential_ref" {
				continue
			}
			target := strings.TrimSpace(fields[f.Name])
			if target == "" {
				continue
			}
			if err := expand(target, depth+1); err != nil {
				return fmt.Errorf("引用链 %s→%s: %w", name, target, err)
			}
		}
		expanded[name] = true
		order = append(order, name)
		return nil
	}
	for _, r := range roots {
		if err := expand(r, 0); err != nil {
			out.Skipped = append(out.Skipped, SkipNote{Name: r, Reason: err.Error()})
		}
	}
	return order
}

// materialize 阶段③：按依赖序原子落盘（ContentFrom 直取 / renderer 渲染）。
// 物化时缺失/解密失败 SkipNote；renderer 未注册/渲染/落盘失败 fail-loud。
func (st *Stager) materialize(res *stageResolver, order []string, dir string, out *Staged, keep map[string]bool) error {
	for _, name := range order {
		cred, fields, err := res.resolveFields(name)
		if err != nil {
			reason := err.Error()
			if errors.Is(err, ErrNotFound) {
				reason = "物化时缺失"
			}
			out.Skipped = append(out.Skipped, SkipNote{Name: name, Reason: reason})
			continue
		}
		t, ok := st.reg.Get(cred.Type)
		if !ok {
			return fmt.Errorf("凭证 %s 类型 %q 未声明", name, cred.Type)
		}
		for _, fs := range t.Inject.Files {
			var content string
			if fs.ContentFrom != "" {
				if SkipByWhen(fs.When, fields) {
					continue
				}
				content = fields[fs.ContentFrom]
			} else {
				rn, ok := st.renderers.Get(t.Inject.Renderer)
				if !ok {
					return fmt.Errorf("类型 %s renderer %q 未注册", cred.Type, t.Inject.Renderer)
				}
				content, err = rn(name, fields, dir)
				if err != nil {
					return fmt.Errorf("实例 %s 渲染失败: %w", name, err)
				}
			}
			rel := Interpolate(fs.Path, name, fields, dir)
			final, err := st.writeConfined(dir, rel, content, fs.Mode)
			if err != nil {
				return fmt.Errorf("实例 %s 落盘失败: %w", name, err)
			}
			out.Files = append(out.Files, rel)
			keep[final] = true
		}
		out.Staged = append(out.Staged, name)
	}
	return nil
}

// assembleEnv 阶段④：base 条目（仅 ${staging_dir}）按绑定类型恒注入（零实例
// 也在）；per-instance 条目（含 ${name}/${field}）随实例追加；同名值去重后
// ":" 拼接。
func (st *Stager) assembleEnv(res *stageResolver, refs []string, order []string, dir string, out *Staged) error {
	boundTypes := map[string]bool{}
	for _, ref := range refs {
		typ, _, _ := strings.Cut(ref, ":")
		boundTypes[typ] = true
	}
	byName := map[string][]string{}
	var envOrder []string
	addEnv := func(name, val string) error {
		if name == "" || strings.ContainsAny(name, "=\x00") {
			return fmt.Errorf("env 名 %q 非法", name)
		}
		if _, ok := byName[name]; !ok {
			envOrder = append(envOrder, name)
		}
		if !slices.Contains(byName[name], val) {
			byName[name] = append(byName[name], val)
		}
		return nil
	}
	typs := make([]string, 0, len(boundTypes))
	for typ := range boundTypes {
		typs = append(typs, typ)
	}
	slices.Sort(typs)
	for _, typ := range typs {
		t, ok := st.reg.Get(typ)
		if !ok {
			continue
		}
		for _, e := range t.Inject.Env {
			if !perInstanceTemplate(e.Value) {
				if err := addEnv(e.Name, Interpolate(e.Value, "", map[string]string{}, dir)); err != nil {
					return err
				}
			}
		}
	}
	for _, name := range order {
		cred, fields, err := res.resolveFields(name)
		if err != nil {
			continue
		}
		t, ok := st.reg.Get(cred.Type)
		if !ok {
			continue
		}
		for _, e := range t.Inject.Env {
			if perInstanceTemplate(e.Value) {
				if err := addEnv(e.Name, Interpolate(e.Value, name, fields, dir)); err != nil {
					return err
				}
			}
		}
	}
	for _, n := range envOrder {
		out.Env = append(out.Env, n+"="+strings.Join(byName[n], ":"))
	}
	return nil
}

// writeConfined 相对路径限界检查（最后防线）+ 原子落盘：临时文件恒 0600，
// 写入/Perm/rename 任一步失败都删除临时文件，失败即返回（不留 .tmp 残留）。
func (st *Stager) writeConfined(baseDir, rel, content, mode string) (string, error) {
	if rel == "" || rel == "." || !filepath.IsLocal(rel) {
		return "", fmt.Errorf("路径 %q 非法（须为 staging 内相对路径）", rel)
	}
	final := filepath.Join(baseDir, rel)
	if final != baseDir && !strings.HasPrefix(final, baseDir+string(filepath.Separator)) {
		return "", fmt.Errorf("路径 %q 逃逸 staging 根", rel)
	}
	perm := os.FileMode(0o600)
	switch mode {
	case "", "0600":
	case "0644":
		perm = 0o644
	default:
		return "", fmt.Errorf("文件 %q mode %q 非白名单（0600|0644）", rel, mode)
	}
	if err := os.MkdirAll(filepath.Dir(final), 0o700); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(final), "."+filepath.Base(final)+".tmp-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if _, err := tmp.WriteString(content); err != nil {
		cleanup()
		return "", err
	}
	if err := tmp.Chmod(perm); err != nil {
		cleanup()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return "", err
	}
	if err := os.Rename(tmpName, final); err != nil {
		_ = os.Remove(tmpName)
		return "", err
	}
	return final, nil
}

// pruneStale 剪除保留清单之外的陈旧文件与 .tmp 残留（先文件后空目录；目录根
// 保留；剪除失败 fail-loud）。keep 是本次落盘的绝对路径集。
func pruneStale(dir string, keep map[string]bool) error {
	var errs []error
	if err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			errs = append(errs, werr)
			return nil
		}
		if p == dir || d.IsDir() || keep[p] {
			return nil
		}
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, fmt.Errorf("剪除陈旧文件 %s: %w", p, err))
		}
		return nil
	}); err != nil {
		errs = append(errs, err)
	}
	var dirs []string
	if err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, werr error) error {
		if werr == nil && d.IsDir() && p != dir {
			dirs = append(dirs, p)
		}
		return nil
	}); err != nil {
		errs = append(errs, err)
	}
	// 路径降序 = 子目录先于父目录（只删空目录，不受文件影响）。
	slices.SortFunc(dirs, func(a, b string) int { return cmp.Compare(b, a) })
	for _, d := range dirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, fmt.Errorf("读取待剪目录 %s: %w", d, err))
			}
			continue
		}
		if len(entries) == 0 {
			if err := os.Remove(d); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, fmt.Errorf("剪除空目录 %s: %w", d, err))
			}
		}
	}
	return errors.Join(errs...)
}

// RestageBindings 重物化全部已绑定 server（凭证变更即时生效通道）：返回绑定
// 快照、各 server 结果、失败表（Stage 失败的 server 不出现在结果中，旧明文
// 文件仍留磁盘——调用方据此告警，静默丢弃会让生命周期收敛失守）。
func (st *Stager) RestageBindings(ctx context.Context) (map[string][]string, map[string]*Staged, map[string]error) {
	st.mu.Lock()
	bindings := make(map[string][]string, len(st.loadedRefs))
	for server, refs := range st.loadedRefs {
		bindings[server] = append([]string(nil), refs...)
	}
	st.mu.Unlock()
	out := make(map[string]*Staged, len(bindings))
	failed := make(map[string]error)
	servers := make([]string, 0, len(bindings))
	for server := range bindings {
		servers = append(servers, server)
	}
	slices.Sort(servers) // 重放顺序确定（日志/结果稳定）
	for _, server := range servers {
		staged, err := st.Stage(ctx, server, bindings[server])
		if err != nil {
			failed[server] = err
			continue
		}
		out[server] = staged
	}
	return bindings, out, failed
}

// StagedServers 反查：哪些运行中 server 装载了该实例（空集非 nil）。
func (st *Stager) StagedServers(instance string) []string {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := []string{}
	for server, names := range st.loadedNames {
		if slices.Contains(names, instance) {
			out = append(out, server)
		}
	}
	slices.Sort(out)
	return out
}

// Cleanup 停机清理（删除本实例 staging 根；宿主在子进程全部退出后调用）。
func (st *Stager) Cleanup() error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if err := os.RemoveAll(st.instanceRoot()); err != nil {
		return fmt.Errorf("credstage: 清理 staging: %w", err)
	}
	return nil
}

// safeSegment staging 路径段（server/instance）不得含分隔符或点段。
func safeSegment(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	if strings.ContainsAny(s, `/\`) {
		return false
	}
	return filepath.IsLocal(s)
}
