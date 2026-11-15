package stager

import (
	"strings"
	"testing"
)

func TestInterpolate(t *testing.T) {
	t.Parallel()
	fields := map[string]string{"address": "10.0.0.1", "self": "${name}"}
	tests := []struct {
		tpl  string
		want string
	}{
		{"${name}@${address}", "web@10.0.0.1"},
		{"${staging_dir}/config", "/stage/config"},
		{"${unknown}", "${unknown}"},
		{"${self}", "${name}"}, // 单次替换，不递归
		{"plain", "plain"},
	}
	for _, tt := range tests {
		if got := Interpolate(tt.tpl, "web", fields, "/stage"); got != tt.want {
			t.Fatalf("Interpolate(%q) = %q, want %q", tt.tpl, got, tt.want)
		}
	}
}

func TestSkipByWhen(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		when   string
		fields map[string]string
		want   bool
	}{
		{"empty when", "", map[string]string{}, false},
		{"missing field skips", "private_key != ''", map[string]string{}, true},
		{"empty field skips", "private_key != ''", map[string]string{"private_key": ""}, true},
		{"present field keeps", "private_key != ''", map[string]string{"private_key": "x"}, false},
		{"double quote variant", `private_key != ""`, map[string]string{}, true},
		{"quoted field name", "'private_key' != ''", map[string]string{}, true},
		{"malformed keeps", "private_key == ''", map[string]string{}, false},
		{"unsupported rhs keeps", "private_key != 'x'", map[string]string{}, false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := SkipByWhen(tt.when, tt.fields); got != tt.want {
				t.Fatalf("SkipByWhen(%q) = %v, want %v", tt.when, got, tt.want)
			}
		})
	}
}

func TestRenderSSHHost(t *testing.T) {
	t.Parallel()
	got, err := RenderSSHHost("web", map[string]string{
		"address": "10.0.0.1", "username": "ops", "port": "2222",
		"private_key": "KEY", "via": "bastion",
	}, "/stage")
	if err != nil {
		t.Fatalf("RenderSSHHost: %v", err)
	}
	want := "Host web\n" +
		"  HostName 10.0.0.1\n  Port 2222\n  User ops\n" +
		"  IdentityFile /stage/keys/web.pem\n  IdentitiesOnly yes\n" +
		"  StrictHostKeyChecking accept-new\n" +
		"  ProxyJump bastion\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}

	minimal, err := RenderSSHHost("db", map[string]string{"address": "db", "username": "u"}, "/s")
	if err != nil {
		t.Fatalf("minimal: %v", err)
	}
	if !strings.Contains(minimal, "  Port 22\n") || strings.Contains(minimal, "IdentityFile") || strings.Contains(minimal, "ProxyJump") {
		t.Fatalf("minimal = %q", minimal)
	}
	for _, fields := range []map[string]string{
		{"username": "u"},
		{"address": "a"},
		{},
	} {
		if _, err := RenderSSHHost("x", fields, "/s"); err == nil {
			t.Fatalf("fields %v 应报错", fields)
		}
	}
}

func TestRenderDatasourcesYAML(t *testing.T) {
	t.Parallel()
	fields := map[string]string{
		"prometheus_url": "https://prom.example", "prometheus_token": "pt",
		"alertmanager_url": "https://am.example",
		"nightingale_url":  "https://n9e.example", "nightingale_token": "nt",
		"loki_url": "https://loki.example", "loki_token": "lt",
		"es_url": "https://es.example", "es_token": "et",
		"n8n_url": "https://n8n.example", "n8n_api_key": "nk",
		"unused": "x",
	}
	got, err := RenderDatasourcesYAML("obs", fields, "/stage")
	if err != nil {
		t.Fatalf("RenderDatasourcesYAML: %v", err)
	}
	want := "datasources:\n" +
		"  prometheus:\n    url: \"https://prom.example\"\n    token: \"pt\"\n" +
		"  alertmanager:\n    url: \"https://am.example\"\n" +
		"  nightingale:\n    url: \"https://n9e.example\"\n    token: \"nt\"\n" +
		"  loki:\n    url: \"https://loki.example\"\n    token: \"lt\"\n" +
		"  elastic:\n    url: \"https://es.example\"\n    token: \"et\"\n" +
		"  n8n:\n    url: \"https://n8n.example\"\n    token: \"nk\"\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}

	onlyURL, err := RenderDatasourcesYAML("obs", map[string]string{"loki_url": "https://l"}, "/s")
	if err != nil {
		t.Fatal(err)
	}
	if onlyURL != "datasources:\n  loki:\n    url: \"https://l\"\n" {
		t.Fatalf("onlyURL = %q", onlyURL)
	}

	if _, err := RenderDatasourcesYAML("obs", nil, "/s"); err == nil {
		t.Fatal("无数据源应报错")
	}
}

func TestRenderDatasourcesQuote(t *testing.T) {
	t.Parallel()
	got, err := RenderDatasourcesYAML("obs", map[string]string{"prometheus_url": "https://x/a?b=\"c\"\\d"}, "/s")
	if err != nil {
		t.Fatal(err)
	}
	want := "datasources:\n  prometheus:\n    url: \"https://x/a?b=\\\"c\\\"\\\\d\"\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestBuiltinRenderersRegistered(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"ssh-host", "datasources-yaml"} {
		if _, ok := builtinRenderers[name]; !ok {
			t.Fatalf("内建 renderer %q 未注册", name)
		}
	}
}
