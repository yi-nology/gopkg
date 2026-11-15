package credstage

import (
	"fmt"
	"strings"
)

// RenderSSHHost 生成单个 OpenSSH Host 块。私钥/via 缺省时省略对应行；
// address/username 缺失 fail-loud（渲染器配置错误）。
func RenderSSHHost(name string, f map[string]string, stagingDir string) (string, error) {
	address, user := strings.TrimSpace(f["address"]), strings.TrimSpace(f["username"])
	if address == "" || user == "" {
		return "", fmt.Errorf("实例 %s 缺 address/username", name)
	}
	port := strings.TrimSpace(f["port"])
	if port == "" {
		port = "22"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Host %s\n", name)
	fmt.Fprintf(&b, "  HostName %s\n  Port %s\n  User %s\n", address, port, user)
	if key := strings.TrimSpace(f["private_key"]); key != "" {
		fmt.Fprintf(&b, "  IdentityFile %s/keys/%s.pem\n  IdentitiesOnly yes\n", stagingDir, name)
	}
	b.WriteString("  StrictHostKeyChecking accept-new\n")
	if via := strings.TrimSpace(f["via"]); via != "" {
		fmt.Fprintf(&b, "  ProxyJump %s\n", via)
	}
	return b.String(), nil
}
