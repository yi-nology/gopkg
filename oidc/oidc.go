package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 三要素任一为空即整体关闭（治理口径见包文档）。
var (
	// ErrDisabled OIDC 未配置（issuer/client_id/client_secret 缺一）。
	ErrDisabled = errors.New("oidc: 三要素（issuer/client_id/client_secret）未配置，OIDC 关闭")
	// ErrFlowInvalid state 不存在、已消费或已超过 FlowTTL。
	ErrFlowInvalid = errors.New("oidc: flow state 无效或已过期")
	// ErrProvider IdP 发现文档/JWKS/token 端点交互失败。
	ErrProvider = errors.New("oidc: IdP 端点交互失败")
	// ErrStateStore flow state 存储（StateStore）交互失败——与 state 不存在/
	// 已过期（ErrFlowInvalid）区分，宿主可据此判基础设施故障而非登录失败。
	ErrStateStore = errors.New("oidc: flow state 存储交互失败")
	// ErrIDToken id_token 形态、签名或声明校验失败。
	ErrIDToken = errors.New("oidc: id_token 校验失败")
	// ErrUnknownKey JWKS 刷新后仍无 token 头部声明的 kid。
	ErrUnknownKey = errors.New("oidc: JWKS 无匹配 kid")
)

// 默认缓存/流转时效。
const (
	DefaultFlowTTL      = 10 * time.Minute
	DefaultDiscoveryTTL = 10 * time.Minute
	DefaultJWKSTTL      = time.Hour
	defaultHTTPTimeout  = 10 * time.Second
)

// Config OIDC 客户端配置。Issuer/ClientID/ClientSecret 是启停三要素
// （任一空 = 整体关闭）。Scopes 缺省 openid profile email；UsernameClaim
// 缺省 preferred_username。HTTPClient/Now 是宿主测试与代理注入点，零值
// 分别落 10s 超时与 time.Now。StateStore 是 flow state 存储注入点，nil =
// 进程内 MemoryStateStore（单机行为不变）。
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string

	Scopes        []string
	UsernameClaim string

	HTTPClient *http.Client

	FlowTTL time.Duration
	// StateStore flow state 跨副本载体；nil = 进程内 MemoryStateStore。
	// 多副本无粘性会话时由宿主注入共享实现（DB/Redis）——Take 必须是原子
	// 单次消费（DB: DELETE ... RETURNING / Redis: GETDEL）。
	StateStore   StateStore
	DiscoveryTTL time.Duration
	JWKSTTL      time.Duration
	Now          func() time.Time
}

// Enabled 三要素齐才启用（任一空=关闭，零网络行为）。
func (c Config) Enabled() bool {
	return c.Issuer != "" && c.ClientID != "" && c.ClientSecret != ""
}

func (c Config) scopes() []string {
	if len(c.Scopes) > 0 {
		return c.Scopes
	}
	return []string{"openid", "profile", "email"} // OIDC 语义最小集
}

func (c Config) usernameClaim() string {
	if c.UsernameClaim != "" {
		return c.UsernameClaim
	}
	return "preferred_username"
}

// discoveryDoc OIDC 发现文档子集（.well-known/openid-configuration）。
type discoveryDoc struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	Issuer                string `json:"issuer"`
}

// Flow 一次登录流转的服务端态快照（StateStore 的存储单元）：state → nonce/
// PKCE verifier/宿主收编锚点/创建时刻。字段全部导出，宿主可原样序列化到
// DB/Redis。Verifier 是 PKCE 机密，存储侧应限权/加密。
type Flow struct {
	Nonce     string    `json:"nonce"`
	Verifier  string    `json:"verifier"`
	Anchor    string    `json:"anchor,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// StateStore flow state 跨副本载体（Config.StateStore 注入点）。
//
// Save 写入本次 flow；ttl 交给实现方做过期策略。Take 必须是原子单次消费：
// 同一 state 无论并发还是重复调用，只有一次返回 ok=true，其余返回
// (Flow{}, false, nil)（DB: DELETE ... RETURNING；Redis: GETDEL）。
//
// Take 返回 error 表示存储故障——Client 包装 ErrStateStore；ok=false 且
// error=nil 才表示 state 不存在/已过期——Client 返回 ErrFlowInvalid。
type StateStore interface {
	Save(ctx context.Context, state string, f Flow, ttl time.Duration) error
	Take(ctx context.Context, state string) (Flow, bool, error)
}

// MemoryStateStore 进程内 StateStore 实现（并发安全、零值可用）。TTL 在
// Save 时落过期时刻（零值用墙钟；Client 的 nil 默认实现复用自身 Now，
// 保持旧行为），Take/Save 惰性剔除。Client 侧仍会用 Flow.CreatedAt 复核
// FlowTTL——本实现的过期只是内存回收，不是唯一防线。
type MemoryStateStore struct {
	mu      sync.Mutex
	entries map[string]memoryState
	now     func() time.Time // nil = time.Now（Client 默认注入自身时钟）
}

// memoryState 进程内条目（flow + 过期时刻）。
type memoryState struct {
	flow      Flow
	expiresAt time.Time
}

// NewMemoryStateStore 构造进程内 StateStore。多个 Client 共享同一实例即可
// 跨客户端消费；跨进程共享仍需宿主实现 StateStore（DB/Redis）。
func NewMemoryStateStore() *MemoryStateStore { return &MemoryStateStore{} }

// clockNow 取过期判定时钟（零值落 time.Now）。
func (m *MemoryStateStore) clockNow() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

// Save 实现 StateStore（惰性 GC 过期条目，免后台协程）。
func (m *MemoryStateStore) Save(_ context.Context, state string, f Flow, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clockNow()
	if m.entries == nil {
		m.entries = make(map[string]memoryState)
	}
	for k, e := range m.entries {
		if now.After(e.expiresAt) {
			delete(m.entries, k)
		}
	}
	m.entries[state] = memoryState{flow: f, expiresAt: now.Add(ttl)}
	return nil
}

// Take 实现 StateStore：删除并返回（原子单次消费，过期条目同样删除）。
func (m *MemoryStateStore) Take(_ context.Context, state string) (Flow, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[state]
	if !ok {
		return Flow{}, false, nil
	}
	delete(m.entries, state)
	if m.clockNow().After(e.expiresAt) {
		return Flow{}, false, nil
	}
	return e.flow, true, nil
}

// Client IdP 往来客户端（并发安全；discovery/JWKS 进程内缓存）。
type Client struct {
	cfg   Config
	http  *http.Client
	now   func() time.Time
	store StateStore

	mu      sync.Mutex
	disco   *discoveryDoc
	discoAt time.Time
	keys    map[string]*rsa.PublicKey
	keysAt  time.Time
}

// New 构造客户端；不拨网（首次 BeginLogin/CompleteLogin 惰性发现）。
func New(cfg Config) *Client {
	if cfg.FlowTTL <= 0 {
		cfg.FlowTTL = DefaultFlowTTL
	}
	if cfg.DiscoveryTTL <= 0 {
		cfg.DiscoveryTTL = DefaultDiscoveryTTL
	}
	if cfg.JWKSTTL <= 0 {
		cfg.JWKSTTL = DefaultJWKSTTL
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: defaultHTTPTimeout}
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	store := cfg.StateStore
	if store == nil {
		// 默认内存实现复用 Client 时钟，保证 StateStore=nil 与旧行为一致
		// （含宿主注入 Now 的测试/回放场景）。
		store = &MemoryStateStore{now: nowFn}
	}
	return &Client{
		cfg:   cfg,
		http:  hc,
		now:   nowFn,
		store: store,
		keys:  map[string]*rsa.PublicKey{},
	}
}

// Enabled 透传配置开关（handler 404 与登录页渲染判据）。
func (c *Client) Enabled() bool { return c.cfg.Enabled() }

// BeginLogin 发起登录：生成 state/nonce/PKCE 并落流转态，返回 IdP 授权页
// URL。redirectURI 由调用方按请求 scheme+host 传入（反向代理须透传 Host）；
// anchor 是宿主的会话收编锚点（如匿名 browser_id），只存服务端流转态，
// 不经 IdP URL 外泄。
func (c *Client) BeginLogin(ctx context.Context, redirectURI, anchor string) (string, error) {
	if !c.cfg.Enabled() {
		return "", ErrDisabled
	}
	doc, err := c.discover(ctx)
	if err != nil {
		return "", err
	}
	verifier, err := randomHex(32) // 64 hex 字符，PKCE 43-128 合规
	if err != nil {
		return "", err
	}
	state, err := randomHex(16)
	if err != nil {
		return "", err
	}
	nonce, err := randomHex(16)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	f := Flow{Nonce: nonce, Verifier: verifier, Anchor: anchor, CreatedAt: c.now()}
	if err := c.store.Save(ctx, state, f, c.cfg.FlowTTL); err != nil {
		return "", fmt.Errorf("%w: flow state 保存失败: %w", ErrStateStore, err)
	}

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {c.cfg.ClientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {strings.Join(c.cfg.scopes(), " ")},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	return doc.AuthorizationEndpoint + "?" + q.Encode(), nil
}

// Result CompleteLogin 的登录结果。Username 按 UsernameClaim → email →
// sub 的顺序回退；Claims 是完整 id_token 载荷，供宿主读取自定义声明。
type Result struct {
	Subject  string
	Username string
	Anchor   string
	Groups   []string
	Claims   map[string]any
}

// CompleteLogin 回调收口：state 对账（单次+TTL，防重放）→ code 换 token
// （PKCE verifier + 机密客户端凭据）→ ID token RS256/JWKS 验签
// （iss/aud/exp/nonce）→ 登录结果。
func (c *Client) CompleteLogin(ctx context.Context, code, state, redirectURI string) (*Result, error) {
	if !c.cfg.Enabled() {
		return nil, ErrDisabled
	}
	f, ok, err := c.store.Take(ctx, state)
	if err != nil {
		// Store 故障与 state 不存在/过期（ErrFlowInvalid）分开，宿主可判 5xx。
		return nil, fmt.Errorf("%w: flow state 读取失败: %w", ErrStateStore, err)
	}
	// 单次消费由 Store.Take 保证；此处再用 CreatedAt 复核 TTL，防御 Store
	// 过期策略失效（多副本共享后端的常见坑）。
	if !ok || c.now().Sub(f.CreatedAt) > c.cfg.FlowTTL {
		return nil, ErrFlowInvalid
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
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: token 端点请求失败: %v", ErrProvider, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 500))
		return nil, fmt.Errorf("%w: token 端点响应 %d: %.200s", ErrProvider, resp.StatusCode, body)
	}
	var tokResp struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tokResp); err != nil || tokResp.IDToken == "" {
		return nil, fmt.Errorf("%w: token 响应缺 id_token", ErrProvider)
	}
	claims, err := c.parseIDToken(ctx, tokResp.IDToken, f.Nonce)
	if err != nil {
		return nil, err
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, fmt.Errorf("%w: 缺 sub", ErrIDToken)
	}
	username, _ := claims[c.cfg.usernameClaim()].(string)
	if username == "" {
		username, _ = claims["email"].(string)
	}
	if username == "" {
		username = sub // IdP 不发账号 claim 时以 sub 兜底
	}
	var groups []string
	if raw, ok := claims["groups"].([]any); ok {
		for _, g := range raw {
			if gs, ok := g.(string); ok && gs != "" {
				groups = append(groups, gs)
			}
		}
	}
	return &Result{
		Subject:  sub,
		Username: username,
		Anchor:   f.Anchor,
		Groups:   groups,
		Claims:   claims,
	}, nil
}

// discover 拉取+缓存发现文档（issuer 精确匹配校验——发现文档伪造/混包防线）。
func (c *Client) discover(ctx context.Context) (*discoveryDoc, error) {
	c.mu.Lock()
	if c.disco != nil && c.now().Sub(c.discoAt) < c.cfg.DiscoveryTTL {
		doc := c.disco
		c.mu.Unlock()
		return doc, nil
	}
	c.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimSuffix(c.cfg.Issuer, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: 发现文档拉取失败: %v", ErrProvider, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: 发现文档响应 %d", ErrProvider, resp.StatusCode)
	}
	var doc discoveryDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("%w: 发现文档解析失败: %v", ErrProvider, err)
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" || doc.JWKSURI == "" {
		return nil, fmt.Errorf("%w: 发现文档缺必要端点（authorization/token/jwks）", ErrProvider)
	}
	if doc.Issuer != c.cfg.Issuer {
		return nil, fmt.Errorf("%w: 发现文档 issuer 不匹配: %q", ErrProvider, doc.Issuer)
	}
	c.mu.Lock()
	c.disco, c.discoAt = &doc, c.now()
	c.mu.Unlock()
	return &doc, nil
}

// publicKey 取验签公钥（kid→RSA，JWKS TTL 缓存）。缓存没有该 kid 时强制
// 刷新一次（IdP 轮换容忍）；刷新后仍无则返回 ErrUnknownKey——只刷新一次，
// 不对未知 kid 反复拉取。
func (c *Client) publicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	if c.keys != nil && c.now().Sub(c.keysAt) < c.cfg.JWKSTTL {
		if k := c.keys[kid]; k != nil {
			c.mu.Unlock()
			return k, nil
		}
	}
	c.mu.Unlock()
	return c.fetchJWKS(ctx, kid)
}

// fetchJWKS 拉取并替换 JWKS 缓存，再按 kid 查找。
func (c *Client) fetchJWKS(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	doc, err := c.discover(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, doc.JWKSURI, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: JWKS 拉取失败: %v", ErrProvider, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: JWKS 响应 %d", ErrProvider, resp.StatusCode)
	}
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return nil, fmt.Errorf("%w: JWKS 解析失败: %v", ErrProvider, err)
	}
	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kty != "RSA" || k.N == "" || k.E == "" {
			continue
		}
		n, err1 := base64.RawURLEncoding.DecodeString(k.N)
		e, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil || len(n) == 0 || len(e) == 0 || len(e) > 4 {
			continue
		}
		exp := 0
		for _, b := range e {
			exp = exp<<8 | int(b)
		}
		if exp < 3 || exp%2 == 0 { // RSA 公钥指数须为奇数且 > 1
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exp}
	}
	c.mu.Lock()
	c.keys, c.keysAt = keys, c.now()
	key := c.keys[kid]
	c.mu.Unlock()
	if key == nil {
		return nil, fmt.Errorf("%w: %q", ErrUnknownKey, kid)
	}
	return key, nil
}

// parseIDToken JWKS 验签 + 标准校验：RS256 强制、iss 精确、aud 含
// client_id、exp/nbf 时钟、nonce 对账（重放/混淆防线）。
func (c *Client) parseIDToken(ctx context.Context, raw, nonce string) (map[string]any, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, fmt.Errorf("%w: 三段式形态非法", ErrIDToken)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &hdr); err != nil {
		return nil, fmt.Errorf("%w: 头部解析失败: %v", ErrIDToken, err)
	}
	if hdr.Alg != "RS256" {
		return nil, fmt.Errorf("%w: alg=%q（仅接受 RS256）", ErrIDToken, hdr.Alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: 签名段解码失败", ErrIDToken)
	}
	key, err := c.publicKey(ctx, hdr.Kid)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		return nil, fmt.Errorf("%w: RS256 签名不匹配", ErrIDToken)
	}
	claims := map[string]any{}
	if err := decodeSegment(parts[1], &claims); err != nil {
		return nil, fmt.Errorf("%w: 载荷解析失败: %v", ErrIDToken, err)
	}
	if iss, _ := claims["iss"].(string); iss != c.cfg.Issuer {
		return nil, fmt.Errorf("%w: iss 不匹配: %q", ErrIDToken, iss)
	}
	if !audienceContains(claims["aud"], c.cfg.ClientID) {
		return nil, fmt.Errorf("%w: aud 不含 client_id", ErrIDToken)
	}
	exp, ok := numericDate(claims["exp"])
	if !ok {
		return nil, fmt.Errorf("%w: 缺 exp", ErrIDToken)
	}
	if !c.now().Before(exp) {
		return nil, fmt.Errorf("%w: id_token 已过期", ErrIDToken)
	}
	if nbfRaw, present := claims["nbf"]; present {
		nbf, ok := numericDate(nbfRaw)
		if !ok {
			return nil, fmt.Errorf("%w: nbf 形态非法", ErrIDToken)
		}
		if c.now().Before(nbf) {
			return nil, fmt.Errorf("%w: id_token 尚未生效（nbf）", ErrIDToken)
		}
	}
	if n, _ := claims["nonce"].(string); n != nonce {
		return nil, fmt.Errorf("%w: nonce 不匹配", ErrIDToken)
	}
	return claims, nil
}

// audienceContains aud 支持单值字符串与数组两形态（OIDC 允许）。
func audienceContains(v any, clientID string) bool {
	switch aud := v.(type) {
	case string:
		return aud == clientID
	case []any:
		for _, a := range aud {
			if s, _ := a.(string); s == clientID {
				return true
			}
		}
	case []string:
		for _, a := range aud {
			if a == clientID {
				return true
			}
		}
	}
	return false
}

// numericDate 解 NumericDate（JSON number；字符串形态宽松兼容）。
func numericDate(v any) (time.Time, bool) {
	switch n := v.(type) {
	case float64:
		return time.Unix(int64(n), 0), true
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return time.Time{}, false
		}
		return time.Unix(i, 0), true
	case string:
		i, err := strconv.ParseInt(n, 10, 64)
		if err != nil {
			return time.Time{}, false
		}
		return time.Unix(i, 0), true
	}
	return time.Time{}, false
}

// decodeSegment base64url（无填充）段 → JSON。
func decodeSegment(seg string, out any) error {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

// randomHex 密码学随机 hex。
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oidc: 系统熵源故障: %w", err)
	}
	return hex.EncodeToString(b), nil
}
