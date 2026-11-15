package stager

import "testing"

func TestKubeconfigServer(t *testing.T) {
	t.Parallel()
	const standard = `apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: abc
    server: https://c1.example:6443
  name: c1
- cluster:
    server: https://c2.example:6443
  name: c2
contexts:
- context:
    cluster: c2
    user: u1
  name: ctx1
current-context: ctx1
kind: Config
users: []
`
	const indented = `clusters:
  - name: c1
    cluster:
      server: "https://c1.example"
contexts:
  - name: ctx1
    context:
      cluster: c1
current-context: "ctx1"
`
	const jsonForm = `{"current-context":"ctx1","contexts":[{"name":"ctx1","context":{"cluster":"c2"}}],"clusters":[{"name":"c1","cluster":{"server":"https://c1"}},{"name":"c2","cluster":{"server":"https://c2"}}]}`
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"standard current context", standard, "https://c2.example:6443"},
		{"no current context fallback first", `clusters:
- cluster:
    server: https://first
  name: first
- cluster:
    server: https://second
  name: second
`, "https://first"},
		{"unknown current context fallback first", `clusters:
- cluster:
    server: https://first
  name: first
contexts:
- context:
    cluster: nope
  name: ctx
current-context: missing
`, "https://first"},
		{"indented list", indented, "https://c1.example"},
		{"json", jsonForm, "https://c2"},
		{"comment with hash fragment", `clusters:
- cluster:
    server: https://x/#frag
  name: c1
`, "https://x/#frag"},
		{"empty", "", ""},
		{"invalid", "not: [valid", ""},
		{"no clusters", "current-context: x\n", ""},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := KubeconfigServer(tt.in); got != tt.want {
				t.Fatalf("KubeconfigServer = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestKubeconfigServerJSONInvalid(t *testing.T) {
	t.Parallel()
	if got := KubeconfigServer(`{"clusters": "nope"}`); got != "" {
		t.Fatalf("got %q", got)
	}
}
