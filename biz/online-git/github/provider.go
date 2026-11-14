package github

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/go-github/v56/github"
	"golang.org/x/oauth2"

	onlinegit "github.com/yi-nology/gopkg/biz/online-git"
)

func init() {
	onlinegit.RegisterProvider(onlinegit.PlatformGitHub, func(cfg *onlinegit.ProviderConfig) (onlinegit.GitProvider, error) {
		return NewProvider(cfg)
	})
}

// Provider GitHub 平台实现
type Provider struct {
	client *github.Client
	owner  string
	repo   string
}

// NewProvider 创建 GitHub Provider
func NewProvider(cfg *onlinegit.ProviderConfig) (*Provider, error) {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: cfg.Token},
	)

	// 受治理传输层垫在 oauth2.Transport 之下：补上此前完全缺失的超时，
	// TLS 策略收进同一构造（原来是零超时的裸 http.Transport）。
	base, err := onlinegit.APIRoundTripper("online-git/github", cfg.InsecureSkipTLS)
	if err != nil {
		return nil, fmt.Errorf("create github http transport: %w", err)
	}

	tc := &http.Client{
		Transport: &oauth2.Transport{
			Source: ts,
			Base:   base,
		},
		Timeout: onlinegit.APITimeout,
	}

	client := github.NewClient(tc)

	// 支持 GitHub Enterprise
	if cfg.BaseURL != "" && cfg.BaseURL != "https://api.github.com" {
		var err error
		parsedURL, err := url.Parse(cfg.BaseURL)
		if err != nil {
			return nil, fmt.Errorf("invalid base URL: %w", err)
		}
		// 确保 URL 以 / 结尾
		if !strings.HasSuffix(parsedURL.Path, "/") {
			parsedURL.Path += "/"
		}
		client.BaseURL = parsedURL
	}

	return &Provider{
		client: client,
		owner:  cfg.Owner,
		repo:   cfg.Repo,
	}, nil
}

func (p *Provider) GetPlatform() onlinegit.Platform {
	return onlinegit.PlatformGitHub
}
