package kbgroup

import (
	"os"
	"path/filepath"
	"testing"
)

// TestKeyFromTitleNormalize 契约：去全部空白 + 小写归一；空输入空键。
func TestKeyFromTitleNormalize(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"对主机做一次安全审计", "对主机做一次安全审计"},
		{"OOM 排查", "oom排查"},
		{"  系统 性能\t瓶颈\n", "系统性能瓶颈"},
		{"MySQL CPU 100%", "mysqlcpu100%"},
		{"\u00a0全角\u3000空白\u2003混排\u00a0", "全角空白混排"},
		{"", ""},
		{" \t\n ", ""},
	}
	for _, c := range cases {
		if got := KeyFromTitle(c.in); got != c.want {
			t.Errorf("KeyFromTitle(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

// TestTeamSlugOf 契约：只认 teams/<slug>/…，其余一律空（防跨队泄漏的第一道语义）。
func TestTeamSlugOf(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"teams/alpha/cases/a.md", "alpha"},
		{"teams/alpha/", "alpha"},
		{"teams/alpha/cases/nested/b.md", "alpha"},
		{"teams/alpha-beta/cases/a.md", "alpha-beta"},
		{"teams/alpha", ""},       // 无后续段：不是团队档
		{"teams//cases/a.md", ""}, // 空 slug
		{"teams/", ""},
		{"knowledge/ops.md", ""},
		{"cases/global.md", ""},
		{"Teams/alpha/cases/a.md", ""}, // 大小写敏感
		{"teamsx/alpha/a.md", ""},
		{"/teams/alpha/a.md", ""}, // 只认相对路径
		{"", ""},
	}
	for _, c := range cases {
		if got := TeamSlugOf(c.in); got != c.want {
			t.Errorf("TeamSlugOf(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

// TestInputFromTitleLine 契约：全角优先、半角「: 」回落、无冒号整行成输入、
// 非标题行返回空。
func TestInputFromTitleLine(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"# 案例 0908-2apd：对主机做一次安全审计", "对主机做一次安全审计"},
		{"# 案例 0909-1abc: 磁盘满了怎么清理", "磁盘满了怎么清理"},
		{"# 案例 0909-node", "案例 0909-node"}, // 无冒号：整行成组（旧格式）
		{"# 案例 0909-half:no-space", "案例 0909-half:no-space"},
		{"# 案例 0909-both: ascii：全角", "全角"}, // 全角优先（即使在后面）
		{"  # 案例 0909-x：前后空白  ", "前后空白"},
		{"# 案例 0909-x：", ""},
		{"# 案例 0909-x：   ", ""},
		{"# ", ""},
		{"## load-triage", ""},
		{"没有井号 案例 x：y", ""},
		{"", ""},
		{"   ", ""},
	}
	for _, c := range cases {
		if got := InputFromTitleLine(c.in); got != c.want {
			t.Errorf("InputFromTitleLine(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

// writeDoc 测试夹具：落盘一份案例文档。
func writeDoc(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestKeyFromDoc 契约：同输入不同空白/全半角冒号同组；非案例格式/不可读/空输入
// 返回空；KeyFromDoc 必须等于 KeyFromTitle(InputFromDoc)。
func TestKeyFromDoc(t *testing.T) {
	dir := t.TempDir()
	full := writeDoc(t, dir, "a.md", "# 案例 0908-2apd：对主机做一次安全审计\n\n- 会话：sess-x\n")
	if got := KeyFromDoc(full); got != "对主机做一次安全审计" {
		t.Errorf("full-width colon: got %q", got)
	}
	same := writeDoc(t, dir, "b.md", "\n\n# 案例 1008-zzzz：对主机 做 一次安全审计\n\n正文\n")
	if KeyFromDoc(full) != KeyFromDoc(same) {
		t.Errorf("同输入不同空白应同组: %q vs %q", KeyFromDoc(full), KeyFromDoc(same))
	}
	ascii := writeDoc(t, dir, "c.md", "# 案例 0909-1abc: 磁盘满了怎么清理\n")
	if got := KeyFromDoc(ascii); got != "磁盘满了怎么清理" {
		t.Errorf("half-width colon: got %q", got)
	}
	noColon := writeDoc(t, dir, "d.md", "# 案例 0909-node\n")
	if got := KeyFromDoc(noColon); got != "案例0909-node" {
		t.Errorf("无冒号整行成组: got %q", got)
	}
	nonCase := writeDoc(t, dir, "e.md", "## load-triage\n负载排查手册\n")
	if got := KeyFromDoc(nonCase); got != "" {
		t.Errorf("非 # 行应返回空: got %q", got)
	}
	if got := KeyFromDoc(filepath.Join(dir, "missing.md")); got != "" {
		t.Errorf("不可读应返回空: got %q", got)
	}
	emptyTitle := writeDoc(t, dir, "f.md", "# 案例 0909-x：\n")
	if got := KeyFromDoc(emptyTitle); got != "" {
		t.Errorf("空输入段应返回空: got %q", got)
	}
	emptyFile := writeDoc(t, dir, "g.md", "")
	if got := KeyFromDoc(emptyFile); got != "" {
		t.Errorf("空文件应返回空: got %q", got)
	}

	// 单源性质：键 = 输入段的归一化形态（两个消费面不得分叉）。
	for _, p := range []string{full, same, ascii, noColon, emptyTitle} {
		if got, want := KeyFromDoc(p), KeyFromTitle(InputFromDoc(p)); got != want {
			t.Errorf("KeyFromDoc(%s)=%q 与 KeyFromTitle(InputFromDoc)=%q 分叉", p, got, want)
		}
	}
}

// TestInputFromDoc 契约：读文件面与纯解析面同源。
func TestInputFromDoc(t *testing.T) {
	dir := t.TempDir()
	p := writeDoc(t, dir, "a.md", "\n# 案例 0908-2apd：对主机做一次安全审计\n")
	if got, want := InputFromDoc(p), "对主机做一次安全审计"; got != want {
		t.Errorf("InputFromDoc=%q want %q", got, want)
	}
	if got, want := InputFromDoc(p), InputFromTitleLine("# 案例 0908-2apd：对主机做一次安全审计"); got != want {
		t.Errorf("IO 面与解析面分叉: %q vs %q", got, want)
	}
}
