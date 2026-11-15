package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// 哨兵错误（errors.Is 判定，消费方不要匹配错误文本）。
var (
	// ErrOidcDisabled 三要素（Issuer/ClientID/ClientSecret）任一为空，功能关闭。
	ErrOidcDisabled = errors.New("oidc: 未配置（issuer/client_id/client_secret 任一为空，功能关闭）")
	// ErrStateInvalid state 不存在、已消费或超过 FlowTTL。
	ErrStateInvalid = errors.New("oidc: state 无效或已过期")
	// ErrDiscovery 发现文档拉取/解析/端点校验失败。
	ErrDiscovery = errors.New("oidc: 发现文档不可用")
	// ErrJWKS JWKS 拉取/解析失败或找不到 kid。
	ErrJWKS = errors.New("oidc: JWKS 不可用")
	// ErrTokenEndpoint token 端点请求失败或响应非法。
	ErrTokenEndpoint = errors.New("oidc: token 端点请求失败")
	// ErrIDToken id_token 形态/签名/claims 校验失败。
	ErrIDToken = errors.New("oidc: id_token 校验失败")
)

const (
	// discoveryTTL 发现文档进程内缓存时长。
	discoveryTTL = 10 * time.Minute
	// jwksTTL JWKS 进程内缓存时长。
	jwksTTL = time.Hour
	// defaultFlowTTL flow state 缺省有效期（授权页停留上限）。
	defaultFlowTTL = 10 * time.Minute
	// maxResponseBytes 发现/JWKS/token 响应体上限（1 MiB）。
	maxResponseBytes = 1 << 20
	// verifierBytes PKCE verifier 随机字节数（hex 64 字符，落在 RFC 7636 的 43-128 内）。
	verifierBytes = 32
	// stateNonceBytes state/nonce 随机字节数（hex 32 字符）。
	stateNonceBytes = 16
)

// OidcConfig IdP 往来配置。Issuer 必须是发现文档中的精确 issuer（不去尾斜杠
// 比较）；三个要素任一为空 = 关闭。Scopes 空时用 OIDC 最小集
// openid/profile/email。HTTPClient 空时用 10s 超时的默认客户端。FlowTTL
// <=0 用 10 分钟；Now 空用 time.Now（仅测试/时钟注入）。
type OidcConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	Scopes       []string
	HTTPClient   *http.Client
	FlowTTL      time.Duration
	Now          func() time.Time
}

// Enabled 三要素齐才启用（任一空=关闭，零行为）。
func (c OidcConfig) Enabled() bool {
	return c.Issuer != "" && c.ClientID != "" && c.ClientSecret != ""
}

// scopes 生效 scopes：宿主注入优先，空则 OIDC 语义最小集。
func (c OidcConfig) scopes() []string {
	if len(c.Scopes) > 0 {
		return c.Scopes
	}
	return []string{"openid", "profile", "email"}
}

// discoveryDoc 发现文档子集（消费的四个字段）。
type discoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// flow 一次登录流转的服务端态（state → nonce/PKCE/宿主关联值）。
type flow struct {
	Nonce     string
	Verifier  string
	Binding   string
	CreatedAt time.Time
}

// OidcClient IdP 往来客户端（并发安全；发现文档/JWKS 进程内缓存；flow state
// 进程内单次消费）。
type OidcClient struct {
	cfg     OidcConfig
	http    *http.Client
	now     func() time.Time
	flowTTL time.Duration

	// cacheMu 保护 discover/JWKS 缓存（网络请求不持锁）。
	cacheMu sync.Mutex
	disco   *discoveryDoc
	discoAt time.Time
	keys    map[string]*rsa.PublicKey
	keysAt  time.Time

	// flowMu 保护 flow state map（惰性 GC 在 BeginLogin 内做）。
	flowMu sync.Mutex
	flows  map[string]flow
}

// NewOidcClient 构造；不拨网（首次 Begin/Complete/Verify 惰性发现）。
func NewOidcClient(cfg OidcConfig) *OidcClient {
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	ttl := cfg.FlowTTL
	if ttl <= 0 {
		ttl = defaultFlowTTL
	}
	return &OidcClient{
		cfg:     cfg,
		http:    httpClient,
		now:     now,
		flowTTL: ttl,
		keys:    map[string]*rsa.PublicKey{},
		flows:   map[string]flow{},
	}
}

// Enabled 透传配置开关（handler 404 与登录页渲染判据）。
func (c *OidcClient) Enabled() bool { return c.cfg.Enabled() }

// randomHex 密码学随机 hex。
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oidc: 系统熵源故障: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// pkceChallenge S256 challenge = base64url(sha256(verifier))，无填充。
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// validEndpoint 发现文档端点必须是绝对 http(s) URL（拒绝相对路径与空 host）。
func validEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// discover 拉取+缓存发现文档（issuer 精确匹配校验——发现文档伪造/混包防线）。
func (c *OidcClient) discover(ctx context.Context) (*discoveryDoc, error) {
	c.cacheMu.Lock()
	if c.disco != nil && c.now().Sub(c.discoAt) < discoveryTTL {
		doc := c.disco
		c.cacheMu.Unlock()
		return doc, nil
	}
	c.cacheMu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimSuffix(c.cfg.Issuer, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, fmt.Errorf("%w: 构造请求: %v", ErrDiscovery, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDiscovery, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: 响应 %d", ErrDiscovery, resp.StatusCode)
	}
	var doc discoveryDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("%w: 解析: %v", ErrDiscovery, err)
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" || doc.JWKSURI == "" {
		return nil, fmt.Errorf("%w: 缺必要端点（authorization/token/jwks）", ErrDiscovery)
	}
	if !validEndpoint(doc.AuthorizationEndpoint) || !validEndpoint(doc.TokenEndpoint) || !validEndpoint(doc.JWKSURI) {
		return nil, fmt.Errorf("%w: 端点不是绝对 http(s) URL", ErrDiscovery)
	}
	if doc.Issuer != "" && doc.Issuer != c.cfg.Issuer {
		return nil, fmt.Errorf("%w: issuer 不匹配: %q", ErrDiscovery, doc.Issuer)
	}

	c.cacheMu.Lock()
	c.disco = &doc
	c.discoAt = c.now()
	c.cacheMu.Unlock()
	return &doc, nil
}

// BeginLogin 发起登录：生成 state/nonce/PKCE 并落流转态，返回 IdP 授权页 URL。
// redirectURI 由调用方按请求 scheme+host 传入；binding 是不透明关联值（如匿名
// 期会话 id），存服务端流转态，不经 IdP URL 外泄，CompleteLogin 原样返回。
func (c *OidcClient) BeginLogin(ctx context.Context, redirectURI, binding string) (string, error) {
	if !c.cfg.Enabled() {
		return "", ErrOidcDisabled
	}
	doc, err := c.discover(ctx)
	if err != nil {
		return "", err
	}
	verifier, err := randomHex(verifierBytes)
	if err != nil {
		return "", err
	}
	state, err := randomHex(stateNonceBytes)
	if err != nil {
		return "", err
	}
	nonce, err := randomHex(stateNonceBytes)
	if err != nil {
		return "", err
	}
	challenge := pkceChallenge(verifier)

	now := c.now()
	c.flowMu.Lock()
	c.gcLocked(now)
	c.flows[state] = flow{Nonce: nonce, Verifier: verifier, Binding: binding, CreatedAt: now}
	c.flowMu.Unlock()

	u, err := url.Parse(doc.AuthorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("%w: authorization_endpoint 非法: %v", ErrDiscovery, err)
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", c.cfg.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", strings.Join(c.cfg.scopes(), " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// tokenResponse token 端点成功响应中本包消费的字段。
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	IDToken      string `json:"id_token"`
}

// LoginResult 回调收口结果：已验证的 ID token + token 端点其余字段 + 流转态里
// 的宿主关联值。账号映射（username/groups→本地账号）由宿主基于 Claims 完成。
type LoginResult struct {
	// Subject ID token 的 sub（已验证非空）。
	Subject string
	// Binding BeginLogin 时宿主传入的不透明关联值。
	Binding string
	// Claims ID token 完整 claims（数值为 json.Number）。
	Claims map[string]any
	// IDToken 解析后的标准字段视图。
	IDToken *IDToken
	// AccessToken/TokenType/RefreshToken/ExpiresIn 来自 token 端点。
	AccessToken  string
	TokenType    string
	RefreshToken string
	ExpiresIn    int64
}

// CompleteLogin 回调收口：state 对账（单次+TTL，防重放）→ code 换 token
// （PKCE verifier + 机密客户端凭据，client_secret_post）→ ID token
// RS256/JWKS 验签（iss/aud/exp/sub + nonce 对账）→ LoginResult。
func (c *OidcClient) CompleteLogin(ctx context.Context, code, state, redirectURI string) (*LoginResult, error) {
	if !c.cfg.Enabled() {
		return nil, ErrOidcDisabled
	}

	// 单次消费：先摘流转态再判 TTL——重放同一 state 直接落空。
	c.flowMu.Lock()
	f, ok := c.flows[state]
	if ok {
		delete(c.flows, state)
	}
	c.flowMu.Unlock()
	if !ok || c.now().Sub(f.CreatedAt) > c.flowTTL {
		return nil, ErrStateInvalid
	}

	doc, err := c.discover(ctx)
	if err != nil {
		return nil, err
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {c.cfg.ClientID},
		"client_secret": {c.cfg.ClientSecret},
		"code_verifier": {f.Verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, doc.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: 构造请求: %v", ErrTokenEndpoint, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenEndpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: 读响应: %v", ErrTokenEndpoint, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: 状态 %d: %.200s", ErrTokenEndpoint, resp.StatusCode, body)
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("%w: 响应解析: %v", ErrTokenEndpoint, err)
	}
	if tr.IDToken == "" {
		return nil, fmt.Errorf("%w: token 响应缺 id_token", ErrIDToken)
	}
	idt, err := c.VerifyIDToken(ctx, tr.IDToken, f.Nonce)
	if err != nil {
		return nil, err
	}
	return &LoginResult{
		Subject:      idt.Subject,
		Binding:      f.Binding,
		Claims:       idt.Claims,
		IDToken:      idt,
		AccessToken:  tr.AccessToken,
		TokenType:    tr.TokenType,
		RefreshToken: tr.RefreshToken,
		ExpiresIn:    tr.ExpiresIn,
	}, nil
}

// gcLocked 清过期流转态（调用方持锁；惰性 GC 免后台协程）。
func (c *OidcClient) gcLocked(now time.Time) {
	for k, f := range c.flows {
		if now.Sub(f.CreatedAt) > c.flowTTL {
			delete(c.flows, k)
		}
	}
}
