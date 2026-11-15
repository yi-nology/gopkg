package credstage

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// RenderDatasourcesYAML 组合 datasources server 的声明 YAML：仅输出填写了地址
// 的源段；token 缺省省略该行（匿名访问）。全部源为空时 fail-loud（声明面
// 如实：至少需要一个数据源地址）。
func RenderDatasourcesYAML(name string, f map[string]string, stagingDir string) (string, error) {
	_ = stagingDir // 文件落点由 FileSpec 声明；渲染器只产出内容
	type source struct {
		URL   string `yaml:"url"`
		Token string `yaml:"token,omitempty"`
	}
	cfg := struct {
		Datasources struct {
			Prometheus   *source `yaml:"prometheus,omitempty"`
			Alertmanager *source `yaml:"alertmanager,omitempty"`
			Nightingale  *source `yaml:"nightingale,omitempty"`
			Loki         *source `yaml:"loki,omitempty"`
			Elastic      *source `yaml:"elastic,omitempty"`
			N8n          *source `yaml:"n8n,omitempty"`
		} `yaml:"datasources"`
	}{}
	if u := strings.TrimSpace(f["prometheus_url"]); u != "" {
		cfg.Datasources.Prometheus = &source{URL: u, Token: f["prometheus_token"]}
	}
	if u := strings.TrimSpace(f["alertmanager_url"]); u != "" {
		cfg.Datasources.Alertmanager = &source{URL: u}
	}
	if u := strings.TrimSpace(f["nightingale_url"]); u != "" {
		cfg.Datasources.Nightingale = &source{URL: u, Token: f["nightingale_token"]}
	}
	if u := strings.TrimSpace(f["loki_url"]); u != "" {
		cfg.Datasources.Loki = &source{URL: u, Token: f["loki_token"]}
	}
	if u := strings.TrimSpace(f["es_url"]); u != "" {
		cfg.Datasources.Elastic = &source{URL: u, Token: f["es_token"]}
	}
	if u := strings.TrimSpace(f["n8n_url"]); u != "" {
		cfg.Datasources.N8n = &source{URL: u, Token: f["n8n_api_key"]}
	}
	if cfg.Datasources.Prometheus == nil && cfg.Datasources.Alertmanager == nil &&
		cfg.Datasources.Nightingale == nil && cfg.Datasources.Loki == nil &&
		cfg.Datasources.Elastic == nil && cfg.Datasources.N8n == nil {
		return "", fmt.Errorf("实例 %s 至少需要一个数据源地址", name)
	}
	out, err := yaml.Marshal(&cfg)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
