package credstage

import (
	"errors"
	"strings"
	"testing"
)

func TestInterpolate(t *testing.T) {
	fields := map[string]string{"address": "10.0.0.1", "name_field": "${name}"}
	tpl := "${name}@${address} dir=${staging_dir} self=${name_field} unknown=${nope}"
	got := Interpolate(tpl, "host1", fields, "/stage")
	want := "host1@10.0.0.1 dir=/stage self=${name} unknown=${nope}"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestPerInstanceTemplate(t *testing.T) {
	tests := []struct {
		tpl  string
		want bool
	}{
		{"${staging_dir}/x", false},
		{"${staging_dir}/${name}", true},
		{"${address}", true},
		{"literal", false},
	}
	for _, tc := range tests {
		if got := perInstanceTemplate(tc.tpl); got != tc.want {
			t.Fatalf("perInstanceTemplate(%q)=%v, want %v", tc.tpl, got, tc.want)
		}
	}
}

func TestSkipByWhen(t *testing.T) {
	tests := []struct {
		when   string
		fields map[string]string
		want   bool
	}{
		{"", nil, false},
		{"private_key != ''", map[string]string{}, true},
		{"private_key != ''", map[string]string{"private_key": "x"}, false},
		{"'private_key' != ''", map[string]string{}, true},
		{"private_key == ''", map[string]string{}, false},
		{"private_key != 'x'", map[string]string{}, false},
	}
	for _, tc := range tests {
		if got := SkipByWhen(tc.when, tc.fields); got != tc.want {
			t.Fatalf("SkipByWhen(%q)=%v, want %v", tc.when, got, tc.want)
		}
	}
}

func TestRenderSSHHost(t *testing.T) {
	out, err := RenderSSHHost("h1", map[string]string{
		"address": "10.0.0.1", "username": "root", "private_key": "PEM", "via": "jump",
	}, "/stage")
	if err != nil {
		t.Fatalf("RenderSSHHost: %v", err)
	}
	for _, want := range []string{
		"Host h1", "HostName 10.0.0.1", "Port 22", "User root",
		"IdentityFile /stage/keys/h1.pem", "IdentitiesOnly yes",
		"StrictHostKeyChecking accept-new", "ProxyJump jump",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("缺 %q:\n%s", want, out)
		}
	}
	out, err = RenderSSHHost("h2", map[string]string{"address": "x", "username": "u", "port": "2222"}, "")
	if err != nil || !strings.Contains(out, "Port 2222") || strings.Contains(out, "IdentityFile") {
		t.Fatalf("out=%q err=%v", out, err)
	}
	if _, err := RenderSSHHost("h3", map[string]string{"address": "x"}, ""); err == nil {
		t.Fatal("缺 username 应报错")
	}
	if _, err := RenderSSHHost("h3", map[string]string{"username": "u"}, ""); err == nil {
		t.Fatal("缺 address 应报错")
	}
}

func TestRenderDatasourcesYAML(t *testing.T) {
	out, err := RenderDatasourcesYAML("ds1", map[string]string{
		"prometheus_url":   "http://prom:9090",
		"prometheus_token": "ptok",
		"alertmanager_url": "http://am:9093",
		"loki_url":         "  ",
	}, "")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{"prometheus:", "http://prom:9090", "token: ptok", "alertmanager:", "http://am:9093"} {
		if !strings.Contains(out, want) {
			t.Fatalf("缺 %q:\n%s", want, out)
		}
	}
	for _, absent := range []string{"loki:", "nightingale:", "elastic:", "n8n:"} {
		if strings.Contains(out, absent) {
			t.Fatalf("空源不应输出 %q:\n%s", absent, out)
		}
	}
	if _, err := RenderDatasourcesYAML("empty", map[string]string{}, ""); err == nil {
		t.Fatal("零数据源应报错")
	}
	out, err = RenderDatasourcesYAML("anon", map[string]string{"prometheus_url": "http://p"}, "")
	if err != nil || strings.Contains(out, "token:") {
		t.Fatalf("匿名源不应输出 token 行: %q err=%v", out, err)
	}
}

func TestKubeconfigServer(t *testing.T) {
	current := `
apiVersion: v1
current-context: prod
contexts:
  - name: prod
    context:
      cluster: prod-cluster
  - name: dev
    context:
      cluster: dev-cluster
clusters:
  - name: dev-cluster
    cluster:
      server: https://dev:6443
  - name: prod-cluster
    cluster:
      server: https://prod:6443
`
	if got := KubeconfigServer(current); got != "https://prod:6443" {
		t.Fatalf("current-context=%q", got)
	}
	fallback := `
contexts:
  - name: dev
    context:
      cluster: dev-cluster
clusters:
  - name: dev-cluster
    cluster:
      server: https://dev:6443
`
	if got := KubeconfigServer(fallback); got != "https://dev:6443" {
		t.Fatalf("fallback=%q", got)
	}
	if got := KubeconfigServer("not: [yaml"); got != "" {
		t.Fatalf("坏 YAML=%q", got)
	}
	if got := KubeconfigServer(""); got != "" {
		t.Fatalf("空串=%q", got)
	}
}

func TestRenderersRegistry(t *testing.T) {
	r := NewRenderers()
	for _, name := range []string{RendererSSHHost, RendererDatasourcesYAML} {
		if _, ok := r.Get(name); !ok {
			t.Fatalf("缺内建 renderer %s", name)
		}
	}
	fn := func(string, map[string]string, string) (string, error) { return "x", nil }
	if err := r.Register("custom", fn); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := r.Register("custom", fn); err == nil {
		t.Fatal("重名应报错")
	}
	if err := r.Register("", fn); err == nil {
		t.Fatal("空名应报错")
	}
	if err := r.Register("nilfn", nil); err == nil {
		t.Fatal("nil fn 应报错")
	}
	if got, ok := r.Get("custom"); !ok || got == nil {
		t.Fatal("自定义 renderer 未注册")
	}
	var nilR *Renderers
	if _, ok := nilR.Get("x"); ok {
		t.Fatal("nil 注册表应返回 false")
	}
}

func TestIsGlobalScope(t *testing.T) {
	if !IsGlobalScope("") || !IsGlobalScope(ScopeGlobal) || IsGlobalScope("team") || IsGlobalScope("user") {
		t.Fatal("scope 判定错误")
	}
}

func TestErrNotFoundWrap(t *testing.T) {
	err := errors.Join(errors.New("x"), ErrNotFound)
	if !errors.Is(err, ErrNotFound) {
		t.Fatal("ErrNotFound 应可 errors.Is")
	}
}
