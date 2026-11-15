package credstage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// ── 测试替身 ──

type fakeRegistry struct {
	mu    sync.Mutex
	types map[string]*Type
}

func newFakeRegistry(types ...*Type) *fakeRegistry {
	r := &fakeRegistry{types: map[string]*Type{}}
	for _, t := range types {
		r.types[t.Name] = t
	}
	return r
}

func (r *fakeRegistry) Get(name string) (*Type, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.types[name]
	return t, ok
}

func (r *fakeRegistry) remove(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.types, name)
}

type fakeDecryptor struct {
	mu       sync.Mutex
	creds    map[string]*Credential
	fields   map[string]map[string]string
	decErrs  map[string]error
	decCalls map[string]int
	listCall int
	listErr  error
}

func newFakeDecryptor() *fakeDecryptor {
	return &fakeDecryptor{
		creds:    map[string]*Credential{},
		fields:   map[string]map[string]string{},
		decErrs:  map[string]error{},
		decCalls: map[string]int{},
	}
}

func (d *fakeDecryptor) put(name, typ, scope string, enabled bool, fields map[string]string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.creds[name] = &Credential{Name: name, Type: typ, Enabled: enabled, Scope: scope}
	d.fields[name] = fields
}

func (d *fakeDecryptor) setFields(name string, fields map[string]string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.fields[name] = fields
}

func (d *fakeDecryptor) setDecErr(name string, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.decErrs[name] = err
}

func (d *fakeDecryptor) Get(_ context.Context, name string) (*Credential, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, ok := d.creds[name]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *c
	return &cp, nil
}

func (d *fakeDecryptor) List(context.Context) ([]Credential, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.listCall++
	if d.listErr != nil {
		return nil, d.listErr
	}
	out := make([]Credential, 0, len(d.creds))
	for _, c := range d.creds {
		out = append(out, *c)
	}
	return out, nil
}

func (d *fakeDecryptor) DecryptFields(_ context.Context, cred *Credential) (map[string]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.decCalls[cred.Name]++
	if err := d.decErrs[cred.Name]; err != nil {
		return nil, err
	}
	out := make(map[string]string, len(d.fields[cred.Name]))
	for k, v := range d.fields[cred.Name] {
		out[k] = v
	}
	return out, nil
}

func (d *fakeDecryptor) calls(name string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.decCalls[name]
}

func (d *fakeDecryptor) lists() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.listCall
}

// tokenType 直接 content_from 落盘的简单类型（base+per-instance env 各一）。
func tokenType() *Type {
	return &Type{
		Name:   "token",
		Fields: []FieldDef{{Name: "value", Kind: "secret"}},
		Inject: InjectSpec{
			Files: []FileSpec{{Path: "tokens/${name}", Mode: "0600", ContentFrom: "value"}},
			Env: []EnvSpec{
				{Name: "BASE_DIR", Value: "${staging_dir}"},
				{Name: "TOKENS", Value: "${staging_dir}/tokens/${name}"},
			},
		},
	}
}

// sshType 渲染器+条件文件+via 引用字段。
func sshType() *Type {
	return &Type{
		Name: "ssh",
		Fields: []FieldDef{
			{Name: "address"}, {Name: "username"}, {Name: "port"},
			{Name: "private_key", Kind: "secret"},
			{Name: "via", Kind: "credential_ref", RefType: "ssh"},
		},
		Inject: InjectSpec{
			Renderer: RendererSSHHost,
			Files: []FileSpec{
				{Path: "ssh/${name}.conf", Mode: "0600"},
				{Path: "keys/${name}.pem", Mode: "0600", ContentFrom: "private_key", When: "private_key != ''"},
			},
			Env: []EnvSpec{
				{Name: "BASE_DIR", Value: "${staging_dir}"},
				{Name: "SSH_CONFIGS", Value: "${staging_dir}/ssh/${name}.conf"},
			},
		},
	}
}

func newTestStager(t *testing.T, dec *fakeDecryptor, types ...*Type) *Stager {
	t.Helper()
	reg := newFakeRegistry(types...)
	st, err := New(Options{Registry: reg, Decryptor: dec, Root: t.TempDir(), InstanceID: "inst"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return st
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	return string(b)
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%s): %v", path, err)
	}
	return info.Mode().Perm()
}

// ── 基础物化 ──

func TestStageContentFromAndEnv(t *testing.T) {
	dec := newFakeDecryptor()
	dec.put("tok1", "token", ScopeGlobal, true, map[string]string{"value": "v1"})
	st := newTestStager(t, dec, tokenType())

	out, err := st.Stage(context.Background(), "srv", []string{"token:tok1"})
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if strings.Join(out.Staged, ",") != "tok1" {
		t.Fatalf("Staged=%v", out.Staged)
	}
	if strings.Join(out.Files, ",") != "tokens/tok1" {
		t.Fatalf("Files=%v", out.Files)
	}
	file := filepath.Join(st.instanceRoot(), "srv", "tokens", "tok1")
	if got := readFile(t, file); got != "v1" {
		t.Fatalf("content=%q", got)
	}
	if got := fileMode(t, file); got != 0o600 {
		t.Fatalf("mode=%o, want 600", got)
	}
	wantBase := "BASE_DIR=" + filepath.Join(st.instanceRoot(), "srv")
	wantTok := "TOKENS=" + filepath.Join(st.instanceRoot(), "srv", "tokens", "tok1")
	if len(out.Env) != 2 || out.Env[0] != wantBase || out.Env[1] != wantTok {
		t.Fatalf("Env=%v, want [%q %q]", out.Env, wantBase, wantTok)
	}
	if got := st.StagedServers("tok1"); len(got) != 1 || got[0] != "srv" {
		t.Fatalf("StagedServers=%v", got)
	}
	if got := st.StagedServers("nope"); got == nil || len(got) != 0 {
		t.Fatalf("空集应非 nil: %v", got)
	}
	if dec.calls("tok1") != 1 {
		t.Fatalf("decrypt calls=%d, want 1", dec.calls("tok1"))
	}
}

func TestStageRendererAndConditionalFile(t *testing.T) {
	dec := newFakeDecryptor()
	dec.put("h1", "ssh", ScopeGlobal, true, map[string]string{
		"address": "10.0.0.1", "username": "root",
	})
	st := newTestStager(t, dec, sshType())
	out, err := st.Stage(context.Background(), "srv", []string{"ssh:h1"})
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if strings.Join(out.Files, ",") != "ssh/h1.conf" {
		t.Fatalf("Files=%v（private_key 为空应跳过 keys 文件）", out.Files)
	}
	conf := readFile(t, filepath.Join(st.instanceRoot(), "srv", "ssh", "h1.conf"))
	for _, want := range []string{"Host h1", "HostName 10.0.0.1", "Port 22", "User root", "StrictHostKeyChecking accept-new"} {
		if !strings.Contains(conf, want) {
			t.Fatalf("conf 缺 %q:\n%s", want, conf)
		}
	}
	if !strings.Contains(strings.Join(out.Env, "\n"), "SSH_CONFIGS="+filepath.Join(st.instanceRoot(), "srv", "ssh", "h1.conf")) {
		t.Fatalf("Env=%v", out.Env)
	}

	// 有私钥时 keys 文件落盘（条件文件的正向）。
	dec.setFields("h1", map[string]string{"address": "10.0.0.1", "username": "root", "private_key": "PEMDATA"})
	out, err = st.Stage(context.Background(), "srv", []string{"ssh:h1"})
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if !strings.Contains(strings.Join(out.Files, ","), "keys/h1.pem") {
		t.Fatalf("Files=%v", out.Files)
	}
	if got := readFile(t, filepath.Join(st.instanceRoot(), "srv", "keys", "h1.pem")); got != "PEMDATA" {
		t.Fatalf("key=%q", got)
	}
}

func TestStageTwoInstancesEnvJoin(t *testing.T) {
	dec := newFakeDecryptor()
	dec.put("a", "token", ScopeGlobal, true, map[string]string{"value": "va"})
	dec.put("b", "token", ScopeGlobal, true, map[string]string{"value": "vb"})
	st := newTestStager(t, dec, tokenType())
	out, err := st.Stage(context.Background(), "srv", []string{"token:a", "token:b"})
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if strings.Join(out.Staged, ",") != "a,b" {
		t.Fatalf("Staged=%v", out.Staged)
	}
	want := "TOKENS=" + filepath.Join(st.instanceRoot(), "srv", "tokens", "a") +
		":" + filepath.Join(st.instanceRoot(), "srv", "tokens", "b")
	if !strings.Contains(strings.Join(out.Env, "\n"), want) {
		t.Fatalf("Env=%v, want contains %q", out.Env, want)
	}
}

func TestWriteAfterPrune(t *testing.T) {
	dec := newFakeDecryptor()
	dec.put("a", "token", ScopeGlobal, true, map[string]string{"value": "va"})
	dec.put("b", "token", ScopeGlobal, true, map[string]string{"value": "vb"})
	st := newTestStager(t, dec, tokenType())
	ctx := context.Background()
	if _, err := st.Stage(ctx, "srv", []string{"token:a", "token:b"}); err != nil {
		t.Fatalf("Stage1: %v", err)
	}
	dir := filepath.Join(st.instanceRoot(), "srv")
	// 手工制造陈旧文件/残留 .tmp/空目录。
	stale := filepath.Join(dir, "tokens", "stale")
	if err := os.WriteFile(stale, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tokens", "leak.tmp"), []byte("tmp"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "old", "deep"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "old", "deep", "x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := st.Stage(ctx, "srv", []string{"token:b"})
	if err != nil {
		t.Fatalf("Stage2: %v", err)
	}
	if strings.Join(out.Files, ",") != "tokens/b" {
		t.Fatalf("Files=%v", out.Files)
	}
	for _, gone := range []string{
		filepath.Join(dir, "tokens", "a"), stale, filepath.Join(dir, "tokens", "leak.tmp"),
		filepath.Join(dir, "old"),
	} {
		if _, err := os.Stat(gone); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s 应被剪除: %v", gone, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "tokens", "b")); err != nil {
		t.Fatalf("保留文件不存在: %v", err)
	}
	// 目录里不得有 .tmp 残留。
	entries, err := os.ReadDir(filepath.Join(dir, "tokens"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Fatalf("残留临时文件: %s", e.Name())
		}
	}

	// 解绑（refs 空）→ 全部文件剪除，server 目录保留。
	out, err = st.Stage(ctx, "srv", nil)
	if err != nil {
		t.Fatalf("Stage3: %v", err)
	}
	if len(out.Files) != 0 || len(out.Staged) != 0 || len(out.Env) != 0 {
		t.Fatalf("解绑产物应为空: %+v", out)
	}
	entries, err = os.ReadDir(dir)
	if err != nil {
		t.Fatalf("server 目录应保留: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("解绑后仍有残留: %v", entries)
	}
	if got := st.StagedServers("b"); len(got) != 0 {
		t.Fatalf("解绑后反查=%v", got)
	}
}

func TestBaseEnvInjectedWithZeroInstances(t *testing.T) {
	dec := newFakeDecryptor()
	st := newTestStager(t, dec, tokenType())
	out, err := st.Stage(context.Background(), "srv", []string{"token:*"})
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if len(out.Staged) != 0 || len(out.Files) != 0 {
		t.Fatalf("零实例不应物化: %+v", out)
	}
	env := strings.Join(out.Env, "\n")
	if !strings.Contains(env, "BASE_DIR="+filepath.Join(st.instanceRoot(), "srv")) {
		t.Fatalf("base env 未注入: %v", out.Env)
	}
	if strings.Contains(env, "TOKENS=") {
		t.Fatalf("per-instance env 不应出现: %v", out.Env)
	}
}

// ── 引用解析 / via ──

func TestWildcardOnlyGlobalEnabled(t *testing.T) {
	dec := newFakeDecryptor()
	dec.put("g1", "token", ScopeGlobal, true, map[string]string{"value": "1"})
	dec.put("g2", "token", "", true, map[string]string{"value": "2"})
	dec.put("t1", "token", "team", true, map[string]string{"value": "3"})
	dec.put("off", "token", ScopeGlobal, false, map[string]string{"value": "4"})
	dec.put("other", "ssh", ScopeGlobal, true, map[string]string{"address": "x", "username": "u"})
	st := newTestStager(t, dec, tokenType(), sshType())

	out, err := st.Stage(context.Background(), "srv", []string{"token:*"})
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if strings.Join(out.Staged, ",") != "g1,g2" {
		t.Fatalf("通配展开=%v（只取 global+enabled）", out.Staged)
	}
	// 无 name 同通配。
	out, err = st.Stage(context.Background(), "srv", []string{"token"})
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if strings.Join(out.Staged, ",") != "g1,g2" {
		t.Fatalf("无 name 展开=%v", out.Staged)
	}
	// 显式引用团队档允许。
	out, err = st.Stage(context.Background(), "srv", []string{"token:t1"})
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if strings.Join(out.Staged, ",") != "t1" {
		t.Fatalf("显式团队档=%v", out.Staged)
	}
	// 禁用跳过。
	out, err = st.Stage(context.Background(), "srv", []string{"token:off"})
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if len(out.Skipped) != 1 || out.Skipped[0].Reason != "已禁用" {
		t.Fatalf("Skipped=%+v", out.Skipped)
	}
}

func TestViaChainOrderAndProxyJump(t *testing.T) {
	dec := newFakeDecryptor()
	dec.put("base", "ssh", ScopeGlobal, true, map[string]string{"address": "10.0.0.1", "username": "root"})
	dec.put("mid", "ssh", ScopeGlobal, true, map[string]string{"address": "10.0.0.2", "username": "root", "via": "base"})
	dec.put("top", "ssh", ScopeGlobal, true, map[string]string{"address": "10.0.0.3", "username": "root", "via": "mid"})
	st := newTestStager(t, dec, sshType())

	out, err := st.Stage(context.Background(), "srv", []string{"ssh:top"})
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if strings.Join(out.Staged, ",") != "base,mid,top" {
		t.Fatalf("依赖序=%v", out.Staged)
	}
	mid := readFile(t, filepath.Join(st.instanceRoot(), "srv", "ssh", "mid.conf"))
	if !strings.Contains(mid, "ProxyJump base") {
		t.Fatalf("mid conf=%s", mid)
	}
	top := readFile(t, filepath.Join(st.instanceRoot(), "srv", "ssh", "top.conf"))
	if !strings.Contains(top, "ProxyJump mid") {
		t.Fatalf("top conf=%s", top)
	}
	env := strings.Join(out.Env, "\n")
	want := "SSH_CONFIGS=" + filepath.Join(st.instanceRoot(), "srv", "ssh", "base.conf") +
		":" + filepath.Join(st.instanceRoot(), "srv", "ssh", "mid.conf") +
		":" + filepath.Join(st.instanceRoot(), "srv", "ssh", "top.conf")
	if !strings.Contains(env, want) {
		t.Fatalf("Env=%v, want %q", out.Env, want)
	}
	// 每个实例只解密一次（via 链共享 resolver 缓存）。
	for _, name := range []string{"base", "mid", "top"} {
		if dec.calls(name) != 1 {
			t.Fatalf("%s decrypt calls=%d, want 1", name, dec.calls(name))
		}
	}
}

func TestViaCycleDetected(t *testing.T) {
	dec := newFakeDecryptor()
	dec.put("a", "ssh", ScopeGlobal, true, map[string]string{"address": "1", "username": "u", "via": "b"})
	dec.put("b", "ssh", ScopeGlobal, true, map[string]string{"address": "2", "username": "u", "via": "a"})
	st := newTestStager(t, dec, sshType())

	out, err := st.Stage(context.Background(), "srv", []string{"ssh:a"})
	if err != nil {
		t.Fatalf("环应作为根跳过而非整单失败: %v", err)
	}
	if len(out.Staged) != 0 || len(out.Files) != 0 {
		t.Fatalf("环上不应物化: %+v", out)
	}
	if len(out.Skipped) != 1 || out.Skipped[0].Name != "a" {
		t.Fatalf("Skipped=%+v", out.Skipped)
	}
	if reason := out.Skipped[0].Reason; !strings.Contains(reason, "引用环") || !strings.Contains(reason, "a→b→a") {
		t.Fatalf("环原因=%q", reason)
	}

	// 自环。
	dec.put("self", "ssh", ScopeGlobal, true, map[string]string{"address": "1", "username": "u", "via": "self"})
	out, err = st.Stage(context.Background(), "srv", []string{"ssh:self"})
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if len(out.Skipped) != 1 || !strings.Contains(out.Skipped[0].Reason, "引用环: self→self") {
		t.Fatalf("自环 Skipped=%+v", out.Skipped)
	}
}

func TestViaDepthLimit(t *testing.T) {
	dec := newFakeDecryptor()
	names := []string{"a", "b", "c", "d", "e"}
	for i, n := range names {
		fields := map[string]string{"address": "1", "username": "u"}
		if i < len(names)-1 {
			fields["via"] = names[i+1]
		}
		dec.put(n, "ssh", ScopeGlobal, true, fields)
	}
	st := newTestStager(t, dec, sshType())
	out, err := st.Stage(context.Background(), "srv", []string{"ssh:a"})
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if len(out.Skipped) != 1 || !strings.Contains(out.Skipped[0].Reason, "引用深度超限") {
		t.Fatalf("Skipped=%+v", out.Skipped)
	}
}

func TestViaUnavailableSkipsRoot(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(dec *fakeDecryptor)
		want   string
	}{
		{"依赖缺失", func(*fakeDecryptor) {}, "实例不存在"},
		{"依赖禁用", func(dec *fakeDecryptor) {
			dec.put("base", "ssh", ScopeGlobal, false, map[string]string{"address": "1", "username": "u"})
		}, "已禁用"},
		{"依赖解密失败", func(dec *fakeDecryptor) {
			dec.put("base", "ssh", ScopeGlobal, true, map[string]string{"address": "1", "username": "u"})
			dec.setDecErr("base", errors.New("bad key"))
		}, "bad key"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dec := newFakeDecryptor()
			dec.put("top", "ssh", ScopeGlobal, true, map[string]string{"address": "2", "username": "u", "via": "base"})
			tc.mutate(dec)
			st := newTestStager(t, dec, sshType())
			out, err := st.Stage(context.Background(), "srv", []string{"ssh:top"})
			if err != nil {
				t.Fatalf("Stage: %v", err)
			}
			if len(out.Staged) != 0 {
				t.Fatalf("链断不应物化: %+v", out)
			}
			if len(out.Skipped) != 1 || !strings.Contains(out.Skipped[0].Reason, tc.want) {
				t.Fatalf("Skipped=%+v, want %q", out.Skipped, tc.want)
			}
		})
	}
}

func TestRefErrors(t *testing.T) {
	dec := newFakeDecryptor()
	dec.put("x", "ssh", ScopeGlobal, true, map[string]string{"address": "1", "username": "u"})
	st := newTestStager(t, dec, tokenType(), sshType())
	ctx := context.Background()

	if _, err := st.Stage(ctx, "srv", []string{"nope:x"}); err == nil || !strings.Contains(err.Error(), "类型未声明") {
		t.Fatalf("类型未声明 err=%v", err)
	}
	if _, err := st.Stage(ctx, "srv", []string{"token:x"}); err == nil || !strings.Contains(err.Error(), "类型不符") {
		t.Fatalf("类型不符应报错: %v", err)
	}

	out, err := st.Stage(ctx, "srv", []string{"token:missing"})
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if len(out.Skipped) != 1 || out.Skipped[0].Reason != "实例不存在" {
		t.Fatalf("Skipped=%+v", out.Skipped)
	}
}

func TestListCachedAcrossWildcardAndExplicit(t *testing.T) {
	dec := newFakeDecryptor()
	dec.put("a", "token", ScopeGlobal, true, map[string]string{"value": "1"})
	st := newTestStager(t, dec, tokenType())
	out, err := st.Stage(context.Background(), "srv", []string{"token:*", "token:a"})
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if strings.Join(out.Staged, ",") != "a" {
		t.Fatalf("重复引用应去重: %v", out.Staged)
	}
	if dec.lists() != 1 {
		t.Fatalf("List calls=%d, want 1", dec.lists())
	}
	if dec.calls("a") != 1 {
		t.Fatalf("decrypt calls=%d, want 1", dec.calls("a"))
	}
}

// ── 落盘安全 / 渲染器错误 ──

func TestStageServerNameRejected(t *testing.T) {
	dec := newFakeDecryptor()
	st := newTestStager(t, dec, tokenType())
	for _, server := range []string{"../x", "a/b", `a\b`, ".", "..", ""} {
		if _, err := st.Stage(context.Background(), server, []string{"token:*"}); err == nil || !strings.Contains(err.Error(), "server 名") {
			t.Fatalf("server=%q err=%v", server, err)
		}
	}
	if _, err := New(Options{Registry: newFakeRegistry(), Decryptor: dec, Root: t.TempDir(), InstanceID: "../x"}); err == nil {
		t.Fatal("非法 InstanceID 应报错")
	}
}

func TestFilePathEscapeRejected(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"父目录逃逸", "../evil"},
		{"绝对路径", "/etc/passwd"},
		{"点路径", "."},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			typ := tokenType()
			typ.Inject.Files = []FileSpec{{Path: tc.path, Mode: "0600", ContentFrom: "value"}}
			dec := newFakeDecryptor()
			dec.put("a", "token", ScopeGlobal, true, map[string]string{"value": "v"})
			st := newTestStager(t, dec, typ)
			if _, err := st.Stage(context.Background(), "srv", []string{"token:a"}); err == nil {
				t.Fatalf("path=%q 应被拒", tc.path)
			}
		})
	}
	// 归一化后仍在 staging 内的相对路径允许（tokens/../x 解析为 x）。
	typ := tokenType()
	typ.Inject.Files = []FileSpec{{Path: "tokens/../norm-${name}", Mode: "0600", ContentFrom: "value"}}
	dec := newFakeDecryptor()
	dec.put("a", "token", ScopeGlobal, true, map[string]string{"value": "v"})
	st := newTestStager(t, dec, typ)
	out, err := st.Stage(context.Background(), "srv", []string{"token:a"})
	if err != nil || strings.Join(out.Files, ",") != "tokens/../norm-a" {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	if _, err := os.Stat(filepath.Join(st.instanceRoot(), "srv", "norm-a")); err != nil {
		t.Fatalf("归一化文件不存在: %v", err)
	}
}

func TestRendererFailLoud(t *testing.T) {
	dec := newFakeDecryptor()
	dec.put("a", "token", ScopeGlobal, true, map[string]string{"value": "v"})
	typ := tokenType()
	typ.Inject.Files = []FileSpec{{Path: "x", Mode: "0600"}} // 无 ContentFrom
	typ.Inject.Renderer = "missing"
	st := newTestStager(t, dec, typ)
	if _, err := st.Stage(context.Background(), "srv", []string{"token:a"}); err == nil || !strings.Contains(err.Error(), "未注册") {
		t.Fatalf("err=%v", err)
	}

	rend := NewRenderers()
	if err := rend.Register("boom", func(string, map[string]string, string) (string, error) {
		return "", errors.New("render boom")
	}); err != nil {
		t.Fatal(err)
	}
	typ.Inject.Renderer = "boom"
	reg := newFakeRegistry(typ)
	st2, err := New(Options{Registry: reg, Decryptor: dec, Root: t.TempDir(), Renderers: rend})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st2.Stage(context.Background(), "srv", []string{"token:a"}); err == nil || !strings.Contains(err.Error(), "渲染失败") {
		t.Fatalf("err=%v", err)
	}
}

func TestBadFileModeRejected(t *testing.T) {
	typ := tokenType()
	typ.Inject.Files[0].Mode = "0777"
	dec := newFakeDecryptor()
	dec.put("a", "token", ScopeGlobal, true, map[string]string{"value": "v"})
	st := newTestStager(t, dec, typ)
	if _, err := st.Stage(context.Background(), "srv", []string{"token:a"}); err == nil || !strings.Contains(err.Error(), "非白名单") {
		t.Fatalf("err=%v", err)
	}
}

// ── Restage / Cleanup ──

func TestRestageBindings(t *testing.T) {
	dec := newFakeDecryptor()
	dec.put("tok1", "token", ScopeGlobal, true, map[string]string{"value": "v1"})
	st := newTestStager(t, dec, tokenType())
	ctx := context.Background()
	if _, err := st.Stage(ctx, "srv", []string{"token:tok1"}); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	file := filepath.Join(st.instanceRoot(), "srv", "tokens", "tok1")
	dec.setFields("tok1", map[string]string{"value": "v2"})

	bindings, staged, failed := st.RestageBindings(ctx)
	if len(failed) != 0 {
		t.Fatalf("failed=%v", failed)
	}
	if strings.Join(bindings["srv"], ",") != "token:tok1" {
		t.Fatalf("bindings=%v", bindings)
	}
	if staged["srv"] == nil || strings.Join(staged["srv"].Staged, ",") != "tok1" {
		t.Fatalf("staged=%+v", staged)
	}
	if got := readFile(t, file); got != "v2" {
		t.Fatalf("重物化内容=%q", got)
	}

	// 类型从注册表消失 → 该 server 进入 failed，且不出现在结果中。
	reg := st.reg.(*fakeRegistry)
	reg.remove("token")
	_, staged, failed = st.RestageBindings(ctx)
	if failed["srv"] == nil || staged["srv"] != nil {
		t.Fatalf("failed=%v staged=%v", failed, staged)
	}
	if got := readFile(t, file); got != "v2" {
		t.Fatalf("失败重物化不应动旧文件: %q", got)
	}
}

func TestCleanup(t *testing.T) {
	dec := newFakeDecryptor()
	dec.put("a", "token", ScopeGlobal, true, map[string]string{"value": "v"})
	st := newTestStager(t, dec, tokenType())
	if _, err := st.Stage(context.Background(), "srv", []string{"token:a"}); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	root := st.instanceRoot()
	if err := st.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Cleanup 后目录仍存在: %v", err)
	}
	if err := st.Cleanup(); err != nil {
		t.Fatalf("重复 Cleanup 应幂等: %v", err)
	}
}

func TestNewValidation(t *testing.T) {
	dec := newFakeDecryptor()
	if _, err := New(Options{Decryptor: dec, Root: t.TempDir()}); err == nil {
		t.Fatal("缺 Registry 应报错")
	}
	if _, err := New(Options{Registry: newFakeRegistry(), Root: t.TempDir()}); err == nil {
		t.Fatal("缺 Decryptor 应报错")
	}
	if _, err := New(Options{Registry: newFakeRegistry(), Decryptor: dec}); err == nil {
		t.Fatal("缺 Root 应报错")
	}
	st, err := New(Options{Registry: newFakeRegistry(), Decryptor: dec, Root: t.TempDir()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if st.inst != "default" {
		t.Fatalf("缺省 InstanceID=%q", st.inst)
	}
	info, err := os.Stat(st.instanceRoot())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("staging 根权限=%o", info.Mode().Perm())
	}
}

func TestStageSkipsMissingExplicitRefs(t *testing.T) {
	dec := newFakeDecryptor()
	dec.put("ok", "token", ScopeGlobal, true, map[string]string{"value": "v"})
	st := newTestStager(t, dec, tokenType())
	out, err := st.Stage(context.Background(), "srv", []string{"token:missing", "token:ok"})
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if strings.Join(out.Staged, ",") != "ok" {
		t.Fatalf("Staged=%v", out.Staged)
	}
	if len(out.Skipped) != 1 || out.Skipped[0].Name != "missing" {
		t.Fatalf("Skipped=%+v", out.Skipped)
	}
}

func TestStageDecryptErrorSkip(t *testing.T) {
	dec := newFakeDecryptor()
	dec.put("bad", "token", ScopeGlobal, true, map[string]string{"value": "v"})
	dec.setDecErr("bad", fmt.Errorf("密文损坏"))
	st := newTestStager(t, dec, tokenType())
	out, err := st.Stage(context.Background(), "srv", []string{"token:bad"})
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if len(out.Staged) != 0 || len(out.Skipped) != 1 || !strings.Contains(out.Skipped[0].Reason, "密文损坏") {
		t.Fatalf("out=%+v", out)
	}
}
