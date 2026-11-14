package gitlab

import (
	"fmt"
	"net/url"

	gitlab "gitlab.com/gitlab-org/api/client-go"

	onlinegit "github.com/yi-nology/gopkg/biz/online-git"
)

func init() {
	onlinegit.RegisterProvider(onlinegit.PlatformGitLab, func(cfg *onlinegit.ProviderConfig) (onlinegit.GitProvider, error) {
		return NewProvider(cfg)
	})
}

// Provider GitLab 平台实现
type Provider struct {
	client    *gitlab.Client
	owner     string
	repo      string
	projectID string // owner/repo 格式
}

// NewProvider 创建 GitLab Provider
func NewProvider(cfg *onlinegit.ProviderConfig) (*Provider, error) {
	var client *gitlab.Client
	var err error

	// 受治理客户端：补上此前完全缺失的超时，并把 TLS 策略收进同一构造
	// （原来只在 InsecureSkipTLS 时才换 Transport，正常路径是零超时裸 client）。
	httpClient, err := onlinegit.APIHTTPClient("online-git/gitlab", cfg.InsecureSkipTLS)
	if err != nil {
		return nil, fmt.Errorf("create gitlab http client: %w", err)
	}

	opts := []gitlab.ClientOptionFunc{
		gitlab.WithHTTPClient(httpClient),
	}

	// 支持私有化部署
	if cfg.BaseURL != "" && cfg.BaseURL != "https://gitlab.com" {
		parsedURL, parseErr := url.Parse(cfg.BaseURL)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid base URL: %w", parseErr)
		}
		opts = append(opts, gitlab.WithBaseURL(parsedURL.String()))
	}

	client, err = gitlab.NewClient(cfg.Token, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create GitLab client: %w", err)
	}

	return &Provider{
		client:    client,
		owner:     cfg.Owner,
		repo:      cfg.Repo,
		projectID: cfg.Owner + "/" + cfg.Repo,
	}, nil
}

func (p *Provider) GetPlatform() onlinegit.Platform {
	return onlinegit.PlatformGitLab
}
