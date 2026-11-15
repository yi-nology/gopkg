package kbgroup

import (
	"bufio"
	"os"
	"strings"
	"unicode"
)

// KeyFromTitle 归一化用户输入为组键：去全部空白 + 小写（「OOM 排查」≡「oom排查」；
// 中文输入主体无空格语义，空格差异多为录入噪声）。返回空串表示无组。
func KeyFromTitle(title string) string {
	var b strings.Builder
	for _, r := range title {
		if unicode.IsSpace(r) {
			continue
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

// TeamSlugOf 团队档路径判定：teams/<slug>/… 前缀 → slug，其余（knowledge 根手册
// 与 cases/ 全局归档）返回空。检索包装层（按会话团队过滤）、飞轮归档落点与控制台
// 文档清单共用——团队路径语义单源，漂移会让语料跨队泄漏或落点错队。
//
// 只认 "/" 分隔的相对路径（归档内路径形态）；teams/<slug> 无后续段、空 slug、
// 非 teams/ 前缀一律返回空。
func TeamSlugOf(rel string) string {
	rest, ok := strings.CutPrefix(rel, "teams/")
	if !ok {
		return ""
	}
	slug, _, ok := strings.Cut(rest, "/")
	if !ok || slug == "" {
		return ""
	}
	return slug
}

// KeyFromDoc 从案例文件标题行提取组键（首个非空行须为「# 」标题行；首个全角「：」
// 之后为用户输入段，无全角冒号退化尝试半角——旧格式文件整行成组）。非案例格式/
// 不可读返回 ""（调用方按无组处理，不参与饱和判定）。
func KeyFromDoc(path string) string {
	t := InputFromDoc(path)
	if t == "" {
		return ""
	}
	return KeyFromTitle(t)
}

// InputFromDoc 从案例文件标题行提取**用户输入段**（人读形态，未归一化）：
// 「# 案例 <caseID>：<用户输入>」⇒ 取冒号后的输入段。非案例格式/不可读返回 ""。
//
// 与 [KeyFromDoc] 同处且共用解析规则：组键是输入段的归一化形态（去空白+小写），
// 两者必须同源——若各持一份冒号解析规则，标题行格式一变（全角冒号 ↔ 半角）就会
// 出现「键算得出、输入取不出」的分叉。治理台展示的是输入（用户当时说了什么），
// 不是归一化后的键。
func InputFromDoc(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }() // 只读扫描：关闭错误不影响解析结果
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "# ") {
			return ""
		}
		return InputFromTitleLine(line)
	}
	return ""
}

// InputFromTitleLine 从**标题行文本**提取用户输入段（纯函数，无 IO）。
//
// 入参须是「# 」开头的标题行；非标题行返回 ""（调用方按无输入处理）。解析规则
// 与 [InputFromDoc] 只有一份（后者内部也调本函数——同源不分叉）：优先取首个全角
// 「：」之后的段，无全角冒号时退化取首个半角「: 」之后的段，都没有则整行成输入
// （旧格式兼容）。
func InputFromTitleLine(titleLine string) string {
	line := strings.TrimSpace(titleLine)
	if !strings.HasPrefix(line, "# ") {
		return ""
	}
	t := strings.TrimPrefix(line, "# ")
	for _, sep := range []string{"：", ": "} {
		if i := strings.Index(t, sep); i >= 0 {
			t = t[i+len(sep):]
			break
		}
	}
	return strings.TrimSpace(t)
}
