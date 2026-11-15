package stager

import (
	"fmt"
	"strings"
)

// builtinRenderers 内建渲染器注册表（类型声明以名字引用）。YAML/def 只
// 声明「什么」，渲染器实现「怎么」——受控注入面的关键收窄。
var builtinRenderers = map[string]Renderer{
	"ssh-host":         RenderSSHHost,
	"datasources-yaml": RenderDatasourcesYAML,
}

// Interpolate 占位符插值：${name}/${staging_dir} 与任意 ${<字段名>}。
// 未提供的占位符原样保留（不静默清空）；单次替换，不递归展开字段值里的
// 占位符。
func Interpolate(tpl, name string, fields map[string]string, stagingDir string) string {
	pairs := []string{"${name}", name, "${staging_dir}", stagingDir}
	for k, v := range fields {
		pairs = append(pairs, "${"+k+"}", v)
	}
	return strings.NewReplacer(pairs...).Replace(tpl)
}

// SkipByWhen v1 条件注入语义：仅支持 "<field> != ”"（也接受双引号空串）
// ——字段为空则跳过该文件。无法识别的 when 返回 false（不跳过），避免
// 配置笔误把文件静默吞掉。
func SkipByWhen(when string, fields map[string]string) bool {
	if strings.TrimSpace(when) == "" {
		return false
	}
	parts := strings.SplitN(when, " != ", 2)
	if len(parts) != 2 {
		return false
	}
	rhs := strings.TrimSpace(parts[1])
	if rhs != "''" && rhs != `""` {
		return false
	}
	field := strings.Trim(strings.TrimSpace(parts[0]), "'\"")
	return field != "" && fields[field] == ""
}

// RenderSSHHost 生成单个 OpenSSH Host 块：address/username 必填，port 缺省
// 22，private_key 存在时指向 <staging>/keys/<name>.pem，via 存在时写
// ProxyJump。
func RenderSSHHost(name string, fields map[string]string, stagingDir string) (string, error) {
	address := strings.TrimSpace(fields["address"])
	user := strings.TrimSpace(fields["username"])
	if address == "" || user == "" {
		return "", fmt.Errorf("实例 %s 缺 address/username", name)
	}
	port := strings.TrimSpace(fields["port"])
	if port == "" {
		port = "22"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Host %s\n", name)
	fmt.Fprintf(&b, "  HostName %s\n  Port %s\n  User %s\n", address, port, user)
	if key := fields["private_key"]; key != "" {
		fmt.Fprintf(&b, "  IdentityFile %s/keys/%s.pem\n  IdentitiesOnly yes\n", stagingDir, name)
	}
	b.WriteString("  StrictHostKeyChecking accept-new\n")
	if via := fields["via"]; via != "" {
		fmt.Fprintf(&b, "  ProxyJump %s\n", via)
	}
	return b.String(), nil
}

// datasourceSpec 数据源段声明（字段名与参考实现同源）。
type datasourceSpec struct {
	key        string
	urlField   string
	tokenField string // 空=该源无 token
}

var datasourceSpecs = []datasourceSpec{
	{key: "prometheus", urlField: "prometheus_url", tokenField: "prometheus_token"},
	{key: "alertmanager", urlField: "alertmanager_url"},
	{key: "nightingale", urlField: "nightingale_url", tokenField: "nightingale_token"},
	{key: "loki", urlField: "loki_url", tokenField: "loki_token"},
	{key: "elastic", urlField: "es_url", tokenField: "es_token"},
	{key: "n8n", urlField: "n8n_url", tokenField: "n8n_api_key"},
}

// RenderDatasourcesYAML 组合数据源声明 YAML：只输出填写了地址的源段；
// token 空则省略该行（匿名访问）。至少需要一个地址，否则返回错误。
//
// YAML 由 stdlib 手写（不引 yaml 库）：输出结构受控、标量统一双引号，
// 语义等价于结构体序列化。
func RenderDatasourcesYAML(name string, fields map[string]string, stagingDir string) (string, error) {
	_ = stagingDir // 落点由 FileSpec 声明；渲染器只产出内容
	var b strings.Builder
	n := 0
	for _, spec := range datasourceSpecs {
		url := strings.TrimSpace(fields[spec.urlField])
		if url == "" {
			continue
		}
		if n == 0 {
			b.WriteString("datasources:\n")
		}
		n++
		fmt.Fprintf(&b, "  %s:\n    url: %s\n", spec.key, yamlQuote(url))
		if spec.tokenField != "" {
			if tok := fields[spec.tokenField]; tok != "" {
				fmt.Fprintf(&b, "    token: %s\n", yamlQuote(tok))
			}
		}
	}
	if n == 0 {
		return "", fmt.Errorf("实例 %s 至少需要一个数据源地址", name)
	}
	return b.String(), nil
}

// yamlQuote 双引号标量（转义反斜杠/引号/常见控制字符）。
func yamlQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
