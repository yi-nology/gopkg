package credstage

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// Interpolate 占位符插值：${name}/${staging_dir} 与任意 ${<字段名>}。
// 单遍替换（字段值里再出现占位符不会二次展开）。
func Interpolate(tpl, name string, fields map[string]string, stagingDir string) string {
	pairs := make([]string, 0, 4+2*len(fields))
	pairs = append(pairs, "${name}", name, "${staging_dir}", stagingDir)
	for k, v := range fields {
		pairs = append(pairs, "${"+k+"}", v)
	}
	return strings.NewReplacer(pairs...).Replace(tpl)
}

// perInstanceTemplate 注入值是否引用实例级占位符（${name}/${<field>}）——
// 仅含 ${staging_dir} 的条目与实例无关，零实例也必须注入。
func perInstanceTemplate(tpl string) bool {
	return strings.Contains(strings.ReplaceAll(tpl, "${staging_dir}", ""), "${")
}

// SkipByWhen v1 仅支持 "<field> != ”"：字段为空则跳过该文件；其余形态不跳过。
func SkipByWhen(when string, fields map[string]string) bool {
	if when == "" {
		return false
	}
	parts := strings.SplitN(when, " != ", 2)
	if len(parts) != 2 || parts[1] != "''" {
		return false
	}
	field := strings.TrimPrefix(strings.TrimSpace(parts[0]), "'")
	field = strings.TrimSuffix(field, "'")
	return field != "" && fields[field] == ""
}

// KubeconfigServer 提取 kubeconfig YAML 的 API server 地址（current-context
// 指向的 cluster 优先，回退首个 cluster；含 scheme）。解析失败返回 ""。
func KubeconfigServer(kubeconfigYAML string) string {
	var cfg struct {
		CurrentContext string `yaml:"current-context"`
		Contexts       []struct {
			Name    string `yaml:"name"`
			Context struct {
				Cluster string `yaml:"cluster"`
			} `yaml:"context"`
		} `yaml:"contexts"`
		Clusters []struct {
			Name    string `yaml:"name"`
			Cluster struct {
				Server string `yaml:"server"`
			} `yaml:"cluster"`
		} `yaml:"clusters"`
	}
	if err := yaml.Unmarshal([]byte(kubeconfigYAML), &cfg); err != nil {
		return ""
	}
	target := ""
	for _, c := range cfg.Contexts {
		if c.Name == cfg.CurrentContext {
			target = c.Context.Cluster
			break
		}
	}
	if target == "" && len(cfg.Clusters) > 0 {
		target = cfg.Clusters[0].Name
	}
	for _, c := range cfg.Clusters {
		if c.Name == target {
			return c.Cluster.Server
		}
	}
	if len(cfg.Clusters) > 0 {
		return cfg.Clusters[0].Cluster.Server
	}
	return ""
}
