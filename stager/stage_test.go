package stager

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

type fakeRegistry struct {
	mu       sync.RWMutex
	types    map[string]*TypeSpec
	infos    map[string]InstanceInfo
	instErrs map[string]error
	listErrs map[string]error
}

func newFakeRegistry() *fakeRegistry {
	return &fakeRegistry{
		types:    map[string]*TypeSpec{},
		infos:    map[string]InstanceInfo{},
		instErrs: map[string]error{},
		listErrs: map[string]error{},
	}
}

func (r *fakeRegistry) Type(name string) (*TypeSpec, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.types[name]
	return t, ok
}

func (r *fakeRegistry) Instances(typeName string) ([]InstanceInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if err := r.listErrs[typeName]; err != nil {
		return nil, err
	}
	out := []InstanceInfo{}
	for _, info := range r.infos {
		if info.Type == typeName {
			out = append(out, info)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (r *fakeRegistry) Instance(name string) (InstanceInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if err := r.instErrs[name]; err != nil {
		return InstanceInfo{}, err
	}
	info, ok := r.infos[name]
	if !ok {
		return InstanceInfo{}, fmt.Errorf("%w: %s", ErrInstanceNotFound, name)
	}
	return info, nil
}

func (r *fakeRegistry) setType(name string, spec *TypeSpec) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.types[name] = spec
}

func (r *fakeRegistry) removeType(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.types, name)
}

func (r *fakeRegistry) setInfo(info InstanceInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.infos[info.Name] = info
}

type fakeDecryptor struct {
	mu     sync.RWMutex
	fields map[string]map[string]string
	errs   map[string]error
}

func newFakeDecryptor() *fakeDecryptor {
	return &fakeDecryptor{fields: map[string]map[string]string{}, errs: map[string]error{}}
}

func (d *fakeDecryptor) Fields(_ context.Context, instance string) (map[string]string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if err := d.errs[instance]; err != nil {
		return nil, err
	}
	src := d.fields[instance]
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out, nil
}

func (d *fakeDecryptor) set(instance string, fields map[string]string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.fields[instance] = fields
}

func (d *fakeDecryptor) setErr(instance string, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.errs[instance] = err
}

func newTestStager(t *testing.T, cfg Config) *Stager {
	t.Helper()
	if cfg.Root == "" {
		cfg.Root = t.TempDir()
	}
	if cfg.InstanceID == "" {
		cfg.InstanceID = "test"
	}
	st, err := NewStager(cfg)
	if err != nil {
		t.Fatalf("NewStager: %v", err)
	}
	t.Cleanup(func() { _ = st.Cleanup() })
	return st
}

func sshSpec() *TypeSpec {
	return &TypeSpec{
		Fields: []FieldSpec{
			{Name: "address"}, {Name: "username"}, {Name: "private_key"}, {Name: "via"},
		},
		Files: []FileSpec{
			{Path: "keys/${name}.pem", Mode: "0600", ContentFrom: "private_key"},
			{Path: "config", Mode: "0644"},
		},
		Env:      []EnvSpec{{Name: "SSH_CONFIG", Value: "${staging_dir}/config"}},
		Renderer: "ssh-host",
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s: %v", path, err)
	}
	return string(data)
}

func TestStageBasic(t *testing.T) {
	t.Parallel()
	reg := newFakeRegistry()
	reg.setType("ssh", sshSpec())
	reg.setInfo(InstanceInfo{Name: "web", Type: "ssh", Enabled: true})
	dec := newFakeDecryptor()
	dec.set("web", map[string]string{"address": "10.0.0.1", "username": "ops", "private_key": "KEY"})
	st := newTestStager(t, Config{Registry: reg, Decryptor: dec})

	staged, err := st.Stage(t.Context(), "mcp-ssh", []string{"ssh:web"})
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if len(staged.Staged) != 1 || staged.Staged[0] != "web" || len(staged.Skipped) != 0 {
		t.Fatalf("staged = %+v", staged)
	}
	wantFiles := []string{"keys/web.pem", "config"}
	if len(staged.Files) != len(wantFiles) {
		t.Fatalf("files = %v", staged.Files)
	}
	for i, want := range wantFiles {
		if staged.Files[i] != want {
			t.Fatalf("files[%d] = %q, want %q", i, staged.Files[i], want)
		}
	}
	dir := st.serverDir("mcp-ssh")
	if got := readFile(t, filepath.Join(dir, "keys/web.pem")); got != "KEY" {
		t.Fatalf("key = %q", got)
	}
	conf := readFile(t, filepath.Join(dir, "config"))
	if !strings.Contains(conf, "Host web\n") || !strings.Contains(conf, "HostName 10.0.0.1\n") ||
		!strings.Contains(conf, "IdentityFile "+dir+"/keys/web.pem\n") {
		t.Fatalf("config = %q", conf)
	}
	if fi, err := os.Stat(filepath.Join(dir, "keys/web.pem")); err != nil {
		t.Fatalf("stat key: %v", err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %v, want 0600", fi.Mode().Perm())
	}
	if fi, err := os.Stat(filepath.Join(dir, "config")); err != nil {
		t.Fatalf("stat config: %v", err)
	} else if fi.Mode().Perm() != 0o644 {
		t.Fatalf("config mode = %v, want 0644", fi.Mode().Perm())
	}
	env := staged.EnvMap()
	if env["SSH_CONFIG"] != filepath.Join(dir, "config") {
		t.Fatalf("env = %+v", env)
	}
}

func TestStageWildcardAndScope(t *testing.T) {
	t.Parallel()
	reg := newFakeRegistry()
	reg.setType("ssh", sshSpec())
	for _, info := range []InstanceInfo{
		{Name: "a", Type: "ssh", Enabled: true, Scope: ScopeGlobal},
		{Name: "b", Type: "ssh", Enabled: true, Scope: "personal"},
		{Name: "c", Type: "ssh", Enabled: false, Scope: ScopeGlobal},
		{Name: "d", Type: "ssh", Enabled: true},
	} {
		reg.setInfo(info)
	}
	dec := newFakeDecryptor()
	for _, name := range []string{"a", "d"} {
		dec.set(name, map[string]string{"address": name, "username": "u"})
	}
	st := newTestStager(t, Config{Registry: reg, Decryptor: dec})

	staged, err := st.Stage(t.Context(), "srv", []string{"ssh:*"})
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if len(staged.Staged) != 2 || staged.Staged[0] != "a" || staged.Staged[1] != "d" {
		t.Fatalf("wildcard staged = %v（只应取启用且全局档）", staged.Staged)
	}
	// 裸类型名等价于通配。
	staged2, err := st.Stage(t.Context(), "srv2", []string{"ssh"})
	if err != nil {
		t.Fatalf("Stage bare: %v", err)
	}
	if len(staged2.Staged) != 2 {
		t.Fatalf("bare staged = %v", staged2.Staged)
	}
	// 无实例的类型通配 = 空结果，不报错。
	reg.setType("empty", &TypeSpec{})
	staged3, err := st.Stage(t.Context(), "srv3", []string{"empty:*"})
	if err != nil {
		t.Fatalf("Stage empty: %v", err)
	}
	if len(staged3.Staged) != 0 || len(staged3.Skipped) != 0 {
		t.Fatalf("empty staged = %+v", staged3)
	}
}

func TestStageSkipsAndConfigErrors(t *testing.T) {
	t.Parallel()
	reg := newFakeRegistry()
	reg.setType("ssh", sshSpec())
	reg.setType("token", &TypeSpec{Fields: []FieldSpec{{Name: "value"}}, Files: []FileSpec{{Path: "t", ContentFrom: "value"}}})
	reg.setInfo(InstanceInfo{Name: "ok", Type: "ssh", Enabled: true})
	reg.setInfo(InstanceInfo{Name: "off", Type: "ssh", Enabled: false})
	reg.setInfo(InstanceInfo{Name: "bad", Type: "ssh", Enabled: true})
	reg.setInfo(InstanceInfo{Name: "qerr", Type: "ssh", Enabled: true})
	dec := newFakeDecryptor()
	dec.set("ok", map[string]string{"address": "a", "username": "u"})
	dec.setErr("bad", errors.New("aad mismatch"))
	reg.instErrs["qerr"] = errors.New("db timeout")
	st := newTestStager(t, Config{Registry: reg, Decryptor: dec})

	staged, err := st.Stage(t.Context(), "srv", []string{"ssh:ok", "ssh:off", "ssh:missing", "ssh:bad", "ssh:qerr"})
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if len(staged.Staged) != 1 || staged.Staged[0] != "ok" {
		t.Fatalf("staged = %v", staged.Staged)
	}
	reasons := map[string]string{}
	for _, s := range staged.Skipped {
		reasons[s.Name] = s.Reason
	}
	if !strings.Contains(reasons["off"], "已禁用") {
		t.Fatalf("off reason = %q", reasons["off"])
	}
	if !strings.Contains(reasons["missing"], "实例不存在") {
		t.Fatalf("missing reason = %q", reasons["missing"])
	}
	if !strings.Contains(reasons["bad"], "解密失败") {
		t.Fatalf("bad reason = %q", reasons["bad"])
	}
	if !strings.Contains(reasons["qerr"], "实例查询失败") {
		t.Fatalf("qerr reason = %q", reasons["qerr"])
	}

	if _, err := st.Stage(t.Context(), "srv", []string{"nope:x"}); !errors.Is(err, ErrUnknownType) {
		t.Fatalf("unknown type err = %v", err)
	}
	if _, err := st.Stage(t.Context(), "srv", []string{"token:ok"}); !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("type mismatch err = %v", err)
	}
	reg.listErrs["ssh"] = errors.New("db down")
	if _, err := st.Stage(t.Context(), "srv", []string{"ssh:*"}); err == nil {
		t.Fatal("通配列表存储错误应上抛")
	}
	if _, err := st.Stage(t.Context(), "bad/server", []string{"ssh:ok"}); err == nil {
		t.Fatal("非法 server 段应报错")
	}
	empty, err := st.Stage(t.Context(), "srv", nil)
	if err != nil || len(empty.Staged) != 0 || len(empty.Files) != 0 {
		t.Fatalf("空 refs = %+v, %v", empty, err)
	}
}

func TestStageViaRecursion(t *testing.T) {
	t.Parallel()
	reg := newFakeRegistry()
	reg.setType("token", &TypeSpec{
		Fields: []FieldSpec{{Name: "value"}, {Name: "next", Kind: "credential_ref"}},
		Files:  []FileSpec{{Path: "token-${name}", ContentFrom: "value"}},
	})
	reg.setType("api", &TypeSpec{
		Fields: []FieldSpec{{Name: "base", Kind: "credential_ref"}, {Name: "key"}},
		Files:  []FileSpec{{Path: "api-${name}", ContentFrom: "key"}},
	})
	reg.setInfo(InstanceInfo{Name: "parent", Type: "token", Enabled: true})
	reg.setInfo(InstanceInfo{Name: "child", Type: "api", Enabled: true})
	reg.setInfo(InstanceInfo{Name: "r1", Type: "api", Enabled: true})
	reg.setInfo(InstanceInfo{Name: "r2", Type: "api", Enabled: true})
	dec := newFakeDecryptor()
	dec.set("parent", map[string]string{"value": "P"})
	dec.set("child", map[string]string{"base": "parent", "key": "K"})
	dec.set("r1", map[string]string{"base": "parent", "key": "K1"})
	dec.set("r2", map[string]string{"base": "parent", "key": "K2"})
	st := newTestStager(t, Config{Registry: reg, Decryptor: dec})

	staged, err := st.Stage(t.Context(), "srv", []string{"api:child"})
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if len(staged.Staged) != 2 || staged.Staged[0] != "parent" || staged.Staged[1] != "child" {
		t.Fatalf("via order = %v（被引用者应先物化）", staged.Staged)
	}
	if got := readFile(t, filepath.Join(st.serverDir("srv"), "token-parent")); got != "P" {
		t.Fatalf("token = %q", got)
	}
	if got := readFile(t, filepath.Join(st.serverDir("srv"), "api-child")); got != "K" {
		t.Fatalf("api = %q", got)
	}

	// 共享依赖只物化一次。
	shared, err := st.Stage(t.Context(), "srv2", []string{"api:r1", "api:r2"})
	if err != nil {
		t.Fatalf("Stage shared: %v", err)
	}
	if len(shared.Staged) != 3 || shared.Staged[0] != "parent" {
		t.Fatalf("shared staged = %v", shared.Staged)
	}
}

func TestStageViaFailures(t *testing.T) {
	t.Parallel()
	reg := newFakeRegistry()
	reg.setType("token", &TypeSpec{
		Fields: []FieldSpec{{Name: "value"}, {Name: "next", Kind: "credential_ref"}},
		Files:  []FileSpec{{Path: "token-${name}", ContentFrom: "value"}},
	})
	reg.setType("api", &TypeSpec{
		Fields: []FieldSpec{{Name: "base", Kind: "credential_ref"}, {Name: "key"}},
		Files:  []FileSpec{{Path: "api-${name}", ContentFrom: "key"}},
	})
	for _, info := range []InstanceInfo{
		{Name: "a", Type: "token", Enabled: true},
		{Name: "b", Type: "token", Enabled: true},
		{Name: "t1", Type: "token", Enabled: true},
		{Name: "t2", Type: "token", Enabled: true},
		{Name: "t3", Type: "token", Enabled: true},
		{Name: "child", Type: "api", Enabled: true},
		{Name: "offparent", Type: "token", Enabled: false},
	} {
		reg.setInfo(info)
	}
	dec := newFakeDecryptor()
	dec.set("a", map[string]string{"next": "b"})
	dec.set("b", map[string]string{"next": "a"})
	dec.set("t1", map[string]string{"next": "t2"})
	dec.set("t2", map[string]string{"next": "t3"})
	dec.set("child", map[string]string{"base": "ghost", "key": "K"})
	dec.set("offparent", map[string]string{"value": "x"})

	t.Run("cycle", func(t *testing.T) {
		t.Parallel()
		st := newTestStager(t, Config{Registry: reg, Decryptor: dec})
		staged, err := st.Stage(t.Context(), "srv", []string{"token:a"})
		if err != nil {
			t.Fatalf("Stage: %v", err)
		}
		if len(staged.Staged) != 0 || len(staged.Skipped) != 1 {
			t.Fatalf("cycle staged = %+v", staged)
		}
		if !strings.Contains(staged.Skipped[0].Reason, "引用环") {
			t.Fatalf("cycle reason = %q", staged.Skipped[0].Reason)
		}
	})
	t.Run("missing via", func(t *testing.T) {
		t.Parallel()
		st := newTestStager(t, Config{Registry: reg, Decryptor: dec})
		staged, err := st.Stage(t.Context(), "srv", []string{"api:child"})
		if err != nil {
			t.Fatalf("Stage: %v", err)
		}
		if len(staged.Staged) != 0 || len(staged.Skipped) != 1 {
			t.Fatalf("missing via staged = %+v", staged)
		}
		reason := staged.Skipped[0].Reason
		if !strings.Contains(reason, "引用链") || !strings.Contains(reason, "实例不存在") {
			t.Fatalf("missing via reason = %q", reason)
		}
	})
	t.Run("too deep", func(t *testing.T) {
		t.Parallel()
		st := newTestStager(t, Config{Registry: reg, Decryptor: dec, MaxViaDepth: 1})
		staged, err := st.Stage(t.Context(), "srv", []string{"token:t1"})
		if err != nil {
			t.Fatalf("Stage: %v", err)
		}
		if len(staged.Staged) != 0 || len(staged.Skipped) != 1 ||
			!strings.Contains(staged.Skipped[0].Reason, "引用深度超限") {
			t.Fatalf("deep staged = %+v", staged)
		}
	})
	t.Run("disabled via", func(t *testing.T) {
		t.Parallel()
		dec.set("child2", map[string]string{"base": "offparent", "key": "K"})
		reg.setInfo(InstanceInfo{Name: "child2", Type: "api", Enabled: true})
		st := newTestStager(t, Config{Registry: reg, Decryptor: dec})
		staged, err := st.Stage(t.Context(), "srv", []string{"api:child2"})
		if err != nil {
			t.Fatalf("Stage: %v", err)
		}
		if len(staged.Staged) != 0 || !strings.Contains(staged.Skipped[0].Reason, "已禁用") {
			t.Fatalf("disabled via staged = %+v", staged)
		}
	})
}

func TestStageWriteAfterPrune(t *testing.T) {
	t.Parallel()
	reg := newFakeRegistry()
	reg.setType("multi", &TypeSpec{
		Fields: []FieldSpec{{Name: "old"}, {Name: "new"}},
		Files: []FileSpec{
			{Path: "old.txt", ContentFrom: "old"},
			{Path: "new.txt", ContentFrom: "new"},
			{Path: "sub/old2.txt", ContentFrom: "old"},
		},
	})
	reg.setInfo(InstanceInfo{Name: "one", Type: "multi", Enabled: true})
	dec := newFakeDecryptor()
	dec.set("one", map[string]string{"old": "OLD", "new": "NEW"})

	oldExistsDuringWrite := false
	st := newTestStager(t, Config{
		Registry: reg, Decryptor: dec,
		Renderers: map[string]Renderer{
			"probe": func(_ string, _ map[string]string, stagingDir string) (string, error) {
				if _, err := os.Stat(filepath.Join(stagingDir, "old.txt")); err == nil {
					oldExistsDuringWrite = true
				}
				return "NEW2", nil
			},
		},
	})
	if _, err := st.Stage(t.Context(), "srv", []string{"multi:one"}); err != nil {
		t.Fatalf("first Stage: %v", err)
	}
	dir := st.serverDir("srv")
	if _, err := os.Stat(filepath.Join(dir, "sub/old2.txt")); err != nil {
		t.Fatalf("旧文件应存在: %v", err)
	}

	reg.setType("multi", &TypeSpec{
		Renderer: "probe",
		Files:    []FileSpec{{Path: "new.txt"}},
	})
	staged, err := st.Stage(t.Context(), "srv", []string{"multi:one"})
	if err != nil {
		t.Fatalf("second Stage: %v", err)
	}
	if !oldExistsDuringWrite {
		t.Fatal("写-后-剪被破坏：渲染阶段旧文件已不存在")
	}
	if got := readFile(t, filepath.Join(dir, "new.txt")); got != "NEW2" {
		t.Fatalf("new = %q", got)
	}
	for _, stale := range []string{"old.txt", "sub/old2.txt", "sub"} {
		if _, err := os.Stat(filepath.Join(dir, stale)); !os.IsNotExist(err) {
			t.Fatalf("陈旧路径 %s 未剪除（err=%v）", stale, err)
		}
	}
	if len(staged.Files) != 1 || staged.Files[0] != "new.txt" {
		t.Fatalf("files = %v", staged.Files)
	}
}

func TestStageEnvAssembly(t *testing.T) {
	t.Parallel()
	reg := newFakeRegistry()
	reg.setType("kube", &TypeSpec{
		Fields: []FieldSpec{{Name: "server"}},
		Files:  []FileSpec{{Path: "kube-${name}.yaml", ContentFrom: "server"}},
		Env: []EnvSpec{
			{Name: "KUBECONFIG", Value: "${staging_dir}/kube-${name}.yaml"},
			{Name: "KUBE_BASE", Value: "${staging_dir}"},
			{Name: "STATIC", Value: "fixed"},
			{Name: "DUP", Value: "same"},
			{Name: "DUP", Value: "same"},
		},
	})
	reg.setInfo(InstanceInfo{Name: "k1", Type: "kube", Enabled: true})
	reg.setInfo(InstanceInfo{Name: "k2", Type: "kube", Enabled: true})
	dec := newFakeDecryptor()
	dec.set("k1", map[string]string{"server": "s1"})
	dec.set("k2", map[string]string{"server": "s2"})
	st := newTestStager(t, Config{Registry: reg, Decryptor: dec})

	staged, err := st.Stage(t.Context(), "srv", []string{"kube:*"})
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	dir := st.serverDir("srv")
	env := staged.EnvMap()
	if env["KUBECONFIG"] != filepath.Join(dir, "kube-k1.yaml")+":"+filepath.Join(dir, "kube-k2.yaml") {
		t.Fatalf("KUBECONFIG = %q", env["KUBECONFIG"])
	}
	if env["KUBE_BASE"] != dir || env["STATIC"] != "fixed" || env["DUP"] != "same" {
		t.Fatalf("env = %+v", env)
	}

	// 零实例：base 条目仍注入（懒拉起子进程 env 烘焙语义）。
	reg2 := newFakeRegistry()
	reg2.setType("kube", &TypeSpec{Env: []EnvSpec{
		{Name: "KUBE_BASE", Value: "${staging_dir}"},
		{Name: "STATIC", Value: "fixed"},
	}})
	st2 := newTestStager(t, Config{Registry: reg2, Decryptor: newFakeDecryptor()})
	staged2, err := st2.Stage(t.Context(), "srv", []string{"kube:*"})
	if err != nil {
		t.Fatalf("Stage zero: %v", err)
	}
	env2 := staged2.EnvMap()
	if env2["KUBE_BASE"] != st2.serverDir("srv") || env2["STATIC"] != "fixed" {
		t.Fatalf("zero-instance env = %+v", env2)
	}
	if _, ok := env2["KUBECONFIG"]; ok {
		t.Fatalf("零实例不应有 per-instance env: %+v", env2)
	}
}

func TestStageSkipByWhenFile(t *testing.T) {
	t.Parallel()
	reg := newFakeRegistry()
	reg.setType("host", &TypeSpec{
		Fields: []FieldSpec{{Name: "address"}, {Name: "private_key"}},
		Files: []FileSpec{
			{Path: "key.pem", ContentFrom: "private_key", When: "private_key != ''"},
			{Path: "conf", ContentFrom: "address"},
		},
	})
	reg.setInfo(InstanceInfo{Name: "no-key", Type: "host", Enabled: true})
	reg.setInfo(InstanceInfo{Name: "with-key", Type: "host", Enabled: true})
	dec := newFakeDecryptor()
	dec.set("no-key", map[string]string{"address": "a"})
	dec.set("with-key", map[string]string{"address": "b", "private_key": "K"})
	st := newTestStager(t, Config{Registry: reg, Decryptor: dec})

	staged, err := st.Stage(t.Context(), "srv", []string{"host:no-key"})
	if err != nil {
		t.Fatal(err)
	}
	if len(staged.Files) != 1 || staged.Files[0] != "conf" {
		t.Fatalf("no-key files = %v", staged.Files)
	}
	if _, err := os.Stat(filepath.Join(st.serverDir("srv"), "key.pem")); !os.IsNotExist(err) {
		t.Fatalf("条件文件不应落盘: %v", err)
	}

	staged2, err := st.Stage(t.Context(), "srv2", []string{"host:with-key"})
	if err != nil {
		t.Fatal(err)
	}
	if len(staged2.Files) != 2 {
		t.Fatalf("with-key files = %v", staged2.Files)
	}
}

func TestStageConfinement(t *testing.T) {
	t.Parallel()
	reg := newFakeRegistry()
	reg.setType("evil", &TypeSpec{
		Fields: []FieldSpec{{Name: "path"}, {Name: "content"}},
		Files:  []FileSpec{{Path: "${path}", ContentFrom: "content"}},
	})
	reg.setInfo(InstanceInfo{Name: "e", Type: "evil", Enabled: true})
	dec := newFakeDecryptor()
	st := newTestStager(t, Config{Registry: reg, Decryptor: dec})

	for _, path := range []string{"../../escape", "/abs/path", "..", "sub/../../../x", ""} {
		dec.set("e", map[string]string{"path": path, "content": "x"})
		_, err := st.Stage(t.Context(), "srv", []string{"evil:e"})
		if !errors.Is(err, ErrPathEscape) {
			t.Fatalf("path %q err = %v, want ErrPathEscape", path, err)
		}
	}

	// 非法文件权限。
	reg.setType("evil", &TypeSpec{
		Fields: []FieldSpec{{Name: "content"}},
		Files:  []FileSpec{{Path: "x", ContentFrom: "content", Mode: "0777"}},
	})
	dec.set("e", map[string]string{"content": "x"})
	if _, err := st.Stage(t.Context(), "srv", []string{"evil:e"}); !errors.Is(err, ErrBadMode) {
		t.Fatalf("mode err = %v", err)
	}

	// renderer 未注册 / 渲染失败。
	reg.setType("evil", &TypeSpec{Files: []FileSpec{{Path: "x"}}})
	dec.set("e", map[string]string{})
	if _, err := st.Stage(t.Context(), "srv", []string{"evil:e"}); !errors.Is(err, ErrNoRenderer) {
		t.Fatalf("renderer err = %v", err)
	}
	st2 := newTestStager(t, Config{
		Registry: reg, Decryptor: dec,
		Renderers: map[string]Renderer{
			"boom": func(string, map[string]string, string) (string, error) {
				return "", errors.New("render exploded")
			},
		},
	})
	reg.setType("evil", &TypeSpec{Renderer: "boom", Files: []FileSpec{{Path: "x"}}})
	if _, err := st2.Stage(t.Context(), "srv", []string{"evil:e"}); err == nil || !strings.Contains(err.Error(), "渲染失败") {
		t.Fatalf("renderer error = %v", err)
	}
}

func TestNewStagerErrors(t *testing.T) {
	t.Parallel()
	reg := newFakeRegistry()
	dec := newFakeDecryptor()
	tests := []struct {
		name string
		cfg  Config
	}{
		{"nil registry", Config{Decryptor: dec, Root: t.TempDir()}},
		{"nil decryptor", Config{Registry: reg, Root: t.TempDir()}},
		{"empty root", Config{Registry: reg, Decryptor: dec}},
		{"bad instance slash", Config{Registry: reg, Decryptor: dec, Root: t.TempDir(), InstanceID: "a/b"}},
		{"bad instance dotdot", Config{Registry: reg, Decryptor: dec, Root: t.TempDir(), InstanceID: ".."}},
		{"nil renderer", Config{Registry: reg, Decryptor: dec, Root: t.TempDir(), Renderers: map[string]Renderer{"x": nil}}},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewStager(tt.cfg); err == nil {
				t.Fatal("应报错")
			}
		})
	}
}

func TestRestageBindings(t *testing.T) {
	t.Parallel()
	reg := newFakeRegistry()
	reg.setType("ssh", sshSpec())
	reg.setInfo(InstanceInfo{Name: "web", Type: "ssh", Enabled: true})
	reg.setInfo(InstanceInfo{Name: "db", Type: "ssh", Enabled: true})
	dec := newFakeDecryptor()
	dec.set("web", map[string]string{"address": "10.0.0.1", "username": "u"})
	dec.set("db", map[string]string{"address": "10.0.0.2", "username": "u"})
	st := newTestStager(t, Config{Registry: reg, Decryptor: dec})

	if _, err := st.Stage(t.Context(), "srv-1", []string{"ssh:web"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Stage(t.Context(), "srv-2", []string{"ssh:db"}); err != nil {
		t.Fatal(err)
	}
	dec.set("web", map[string]string{"address": "10.0.0.9", "username": "u"})
	bindings, out, failed := st.RestageBindings(t.Context())
	if len(bindings) != 2 || len(out) != 2 || len(failed) != 0 {
		t.Fatalf("bindings=%v out=%v failed=%v", bindings, out, failed)
	}
	conf := readFile(t, filepath.Join(st.serverDir("srv-1"), "config"))
	if !strings.Contains(conf, "HostName 10.0.0.9") {
		t.Fatalf("重物化未生效: %q", conf)
	}

	// 类型被移除后重放：失败 server 出现在 failed，不出现在 out。
	reg.removeType("ssh")
	_, out2, failed2 := st.RestageBindings(t.Context())
	if len(out2) != 0 || len(failed2) != 2 {
		t.Fatalf("out=%v failed=%v", out2, failed2)
	}
	for _, err := range failed2 {
		if !errors.Is(err, ErrUnknownType) {
			t.Fatalf("failed err = %v", err)
		}
	}
}

func TestStagedServersAndCleanup(t *testing.T) {
	t.Parallel()
	reg := newFakeRegistry()
	reg.setType("ssh", sshSpec())
	reg.setType("token", &TypeSpec{Files: []FileSpec{{Path: "t", ContentFrom: "value"}}})
	for _, info := range []InstanceInfo{
		{Name: "a", Type: "ssh", Enabled: true},
		{Name: "b", Type: "ssh", Enabled: true},
		{Name: "t", Type: "token", Enabled: true},
	} {
		reg.setInfo(info)
	}
	dec := newFakeDecryptor()
	dec.set("a", map[string]string{"address": "a", "username": "u"})
	dec.set("b", map[string]string{"address": "b", "username": "u"})
	dec.set("t", map[string]string{"value": "v"})
	st := newTestStager(t, Config{Registry: reg, Decryptor: dec})

	if _, err := st.Stage(t.Context(), "server1", []string{"ssh:a", "token:t"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Stage(t.Context(), "server2", []string{"ssh:*"}); err != nil {
		t.Fatal(err)
	}
	if got := st.StagedServers("a"); len(got) != 2 || got[0] != "server1" || got[1] != "server2" {
		t.Fatalf("StagedServers(a) = %v", got)
	}
	if got := st.StagedServers("b"); len(got) != 1 || got[0] != "server2" {
		t.Fatalf("StagedServers(b) = %v", got)
	}
	if got := st.StagedServers("t"); len(got) != 1 || got[0] != "server1" {
		t.Fatalf("StagedServers(t) = %v", got)
	}
	if got := st.StagedServers("missing"); got == nil || len(got) != 0 {
		t.Fatalf("StagedServers(missing) = %v (want non-nil empty)", got)
	}

	if err := st.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(st.InstanceDir()); !os.IsNotExist(err) {
		t.Fatalf("Cleanup 后目录仍在: %v", err)
	}
	// Cleanup 后可重新物化（MkdirAll 自愈）。
	if _, err := st.Stage(t.Context(), "server1", []string{"ssh:a"}); err != nil {
		t.Fatalf("Cleanup 后 Stage: %v", err)
	}
}

func TestConcurrentStage(t *testing.T) {
	t.Parallel()
	reg := newFakeRegistry()
	reg.setType("ssh", sshSpec())
	dec := newFakeDecryptor()
	for _, name := range []string{"a", "b", "c", "d"} {
		reg.setInfo(InstanceInfo{Name: name, Type: "ssh", Enabled: true})
		dec.set(name, map[string]string{"address": name, "username": "u"})
	}
	st := newTestStager(t, Config{Registry: reg, Decryptor: dec})

	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for _, name := range []string{"a", "b", "c", "d"} {
		name := name
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := st.Stage(context.Background(), "srv-"+name, []string{"ssh:" + name}); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("并发 Stage: %v", err)
	}
	for _, name := range []string{"a", "b", "c", "d"} {
		if got := readFile(t, filepath.Join(st.serverDir("srv-"+name), "keys", name+".pem")); got != "" {
			// 无 private_key 时文件存在但为空。
			t.Fatalf("key content = %q", got)
		}
	}
}

func TestParseRefAndEnvMap(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in      string
		want    Ref
		wantErr bool
	}{
		{"ssh:web", Ref{Type: "ssh", Name: "web"}, false},
		{" ssh : web ", Ref{Type: "ssh", Name: "web"}, false},
		{"ssh:*", Ref{Type: "ssh", Wildcard: true}, false},
		{"ssh", Ref{Type: "ssh", Wildcard: true}, false},
		{"ssh:", Ref{Type: "ssh", Wildcard: true}, false},
		{"", Ref{}, true},
		{":x", Ref{}, true},
	}
	for _, tt := range tests {
		got, err := ParseRef(tt.in)
		if (err != nil) != tt.wantErr {
			t.Fatalf("ParseRef(%q) err = %v", tt.in, err)
		}
		if !tt.wantErr && got != tt.want {
			t.Fatalf("ParseRef(%q) = %+v, want %+v", tt.in, got, tt.want)
		}
	}

	s := &Staged{Env: []string{"A=1", "B=x=y", "broken"}}
	m := s.EnvMap()
	if m["A"] != "1" || m["B"] != "x=y" || len(m) != 2 {
		t.Fatalf("EnvMap = %+v", m)
	}
}
