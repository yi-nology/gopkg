package stager

import (
	"encoding/json"
	"strconv"
	"strings"
)

// KubeconfigServer 提取 kubeconfig 的 API server 地址（含 scheme）：
// current-context 指向的 cluster 优先，解析不到则回退首个 cluster。
// 解析失败返回空串（调用方按「无 server」处理，不因坏配置炸整条链路）。
//
// 支持 JSON 形态与常见块式 YAML 子集（clusters/contexts 列表 + 嵌套
// cluster/server）；不是完整 YAML 解析器：块标量、锚点、内联 flow mapping
// 不在覆盖面。
func KubeconfigServer(kubeconfig string) string {
	trimmed := strings.TrimSpace(kubeconfig)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, "{") {
		return kubeconfigServerJSON([]byte(trimmed))
	}
	return kubeconfigServerYAML(trimmed)
}

func kubeconfigServerJSON(data []byte) string {
	var cfg struct {
		CurrentContext string `json:"current-context"`
		Contexts       []struct {
			Name    string `json:"name"`
			Context struct {
				Cluster string `json:"cluster"`
			} `json:"context"`
		} `json:"contexts"`
		Clusters []struct {
			Name    string `json:"name"`
			Cluster struct {
				Server string `json:"server"`
			} `json:"cluster"`
		} `json:"clusters"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return ""
	}
	contextCluster := func(name string) string {
		for _, c := range cfg.Contexts {
			if c.Name == name {
				return c.Context.Cluster
			}
		}
		return ""
	}
	target := contextCluster(cfg.CurrentContext)
	if target == "" && len(cfg.Clusters) > 0 {
		target = cfg.Clusters[0].Name
	}
	for _, c := range cfg.Clusters {
		if c.Name == target && c.Cluster.Server != "" {
			return c.Cluster.Server
		}
	}
	for _, c := range cfg.Clusters {
		if c.Cluster.Server != "" {
			return c.Cluster.Server
		}
	}
	return ""
}

// kubeconfigItem 一个列表项的首值集合（name/cluster/server 等）。
type kubeconfigItem map[string]string

func kubeconfigServerYAML(text string) string {
	current := ""
	contexts := []kubeconfigItem{}
	clusters := []kubeconfigItem{}

	section := ""
	var items *[]kubeconfigItem
	var cur kubeconfigItem
	itemIndent := -1
	flush := func() {
		if cur != nil {
			*items = append(*items, cur)
			cur = nil
		}
	}

	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, "\r")
		line = stripYAMLComment(line)
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed == "---" {
			continue
		}
		indent := countIndent(line)

		// 顶层键（列表项 "- ..." 在缩进 0 时也走下面的列表分支）。
		if indent == 0 && !strings.HasPrefix(trimmed, "-") {
			key, val, ok := splitYAMLKV(trimmed)
			if !ok {
				continue
			}
			switch key {
			case "contexts":
				flush()
				section, items, itemIndent = "contexts", &contexts, -1
			case "clusters":
				flush()
				section, items, itemIndent = "clusters", &clusters, -1
			case "current-context":
				flush()
				section = ""
				current = parseYAMLScalar(val)
			default:
				flush()
				section = ""
			}
			continue
		}
		if section == "" || items == nil {
			continue
		}
		// 列表项起始。
		if strings.HasPrefix(trimmed, "-") && (trimmed == "-" || strings.HasPrefix(trimmed, "- ")) {
			if cur == nil || itemIndent == -1 || indent <= itemIndent {
				flush()
				itemIndent = indent
				cur = kubeconfigItem{}
				rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
				if rest != "" {
					if k, v, ok := splitYAMLKV(rest); ok {
						setKubeItem(cur, k, parseYAMLScalar(v))
					}
				}
			}
			continue
		}
		if cur != nil {
			if k, v, ok := splitYAMLKV(trimmed); ok {
				setKubeItem(cur, k, parseYAMLScalar(v))
			}
		}
	}
	flush()

	clusterOf := func(ctxName string) string {
		for _, c := range contexts {
			if c["name"] == ctxName {
				return c["cluster"]
			}
		}
		return ""
	}
	target := clusterOf(current)
	if target == "" && len(clusters) > 0 {
		target = clusters[0]["name"]
	}
	for _, c := range clusters {
		if c["name"] == target && c["server"] != "" {
			return c["server"]
		}
	}
	for _, c := range clusters {
		if c["server"] != "" {
			return c["server"]
		}
	}
	return ""
}

// setKubeItem 只在键尚未有非空值时写入（嵌套 cluster: 空值不会覆盖
// cluster: c1 这类实际值）。
func setKubeItem(item kubeconfigItem, key, val string) {
	if existing, ok := item[key]; ok && existing != "" && val == "" {
		return
	}
	if val != "" || item[key] == "" {
		item[key] = val
	}
}

// countIndent 前导空格数（tab 记 1，仅用于相对缩进比较）。
func countIndent(line string) int {
	n := 0
	for _, r := range line {
		if r != ' ' && r != '\t' {
			break
		}
		n++
	}
	return n
}

// stripYAMLComment 去行尾注释：仅引号外且 '#' 在行首/前面是空白的形态
// （URL 里的 #fragment 保留）。
func stripYAMLComment(line string) string {
	inSingle, inDouble := false, false
	for i, r := range line {
		switch r {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
				return strings.TrimRight(line[:i], " \t")
			}
		}
	}
	return line
}

// splitYAMLKV 按首个引号外的 ":" 切 key/value。
func splitYAMLKV(s string) (key, val string, ok bool) {
	inSingle, inDouble := false, false
	for i, r := range s {
		switch r {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case ':':
			if !inSingle && !inDouble {
				return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:]), true
			}
		}
	}
	return "", "", false
}

// parseYAMLScalar 去引号/反转义简单标量；块标量（|/>）返回空串。
func parseYAMLScalar(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "|" || s == ">" || s == "|-" || s == ">-" {
		return ""
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		if unquoted, err := strconv.Unquote(s); err == nil {
			return unquoted
		}
		return strings.Trim(s, `"`)
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
	}
	return s
}
