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
	// ErrStateStore 注入 StateStore 形态下的载体读写失败（gopkg#29）——
	// 区别于 ErrFlowInvalid：前者是基础设施故障（可重试/告警），后者是
	// 「state 不存在/已消费/已过期」的正常业务否决。
	ErrStateStore = errors.New("oidc: flow state 载体读写失败")
	// ErrProvider IdP 发现文档/JWKS/token 端点交互失败。
	ErrProvider = errors.New("oidc: IdP 端点交互失败")
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

// StateStore 跨副本 flow state 载体（gopkg#29）：无粘性负载均衡下，登录
// 回调可能落到与 BeginLogin 不同的副本——进程内 map 必现 ErrFlowInvalid
// （拓扑决定的失败概率，不是偶发网络问题）。注入同一载体（DB/Redis/任意
// 共享存储）后回调落任何副本都能对账。
//
// 实现方契约：
//   - Take 必须原子单次消费（DB: DELETE ... RETURNING / Redis: GETDEL）——
//     重放同一 state 第二次 Take 落空（防重放语义由载体兜底）；
//   - Save 的 ttl 建议按载体原生过期实现（Client 侧恒以 CreatedAt+FlowTTL
//     复核，Store 过期策略失效也不致放行陈旧 state）；
//   - 「state 不存在」返回 (Flow{}, false, nil) → Client 判 ErrFlowInvalid；
//     载体读写故障返回 error → Client 包装 ErrStateStore，二者可区分。
type StateStore interface {
	Save(ctx context.Context, state string, f Flow, ttl time.Duration) error
	Take(ctx context.Context, state string) (Flow, bool, error)
}

// MemoryStateStore StateStore 的进程内导出实现（gopkg#29 可选便利）：多
// Client/测试共享同一份流转态（如网关与回调 handler 各持一个 Client）。
// 零值可用；惰性 GC 免后台协程；Take 原子单次消费；过期键在 Save/Take 时
// 顺带清扫。多副本部署请用 DB/Redis 等真共享载体实现 StateStore——本实现
// 只共享进程内。
type MemoryStateStore struct {
	mu    sync.Mutex
	flows map[string]memoryFlow
}

// memoryFlow 带载体侧过期的流转态条目（ttl 到期即视为不存在）。
type memoryFlow struct {
	f         Flow
	expiresAt time.Time
}

// Save 实现 StateStore（ttl 到期后条目不再可见；Client 侧另有 CreatedAt
// 复核，双保险）。
func (s *MemoryStateStore) Save(_ context.Context, state string, f Flow, ttl time.Duration) error {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.flows == nil {
		s.flows = make(map[string]memoryFlow)
	}
	s.gcLocked(now)
	s.flows[state] = memoryFlow{f: f, expiresAt: now.Add(ttl)}
	return nil
}

// Take 实现 StateStore：命中即删（原子单次消费，重放落空）；过期条目按
// 不存在返回。
func (s *MemoryStateStore) Take(_ context.Context, state string) (Flow, bool, error) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.flows[state]
	if ok {
		delete(s.flows, state)
	}
	s.gcLocked(now)
	if !ok || now.After(e.expiresAt) {
		return Flow{}, false, nil
	}
	return e.f, true, nil
}

// gcLocked 清过期条目（调用方持锁）。
func (s *MemoryStateStore) gcLocked(now time.Time) {
	for k, e := range s.flows {
		if now.After(e.expiresAt) {
			delete(s.flows, k)
		}
	}
}

// Config OIDC 客户端配置。Issuer/ClientID/ClientSecret 是启停三要素
// （任一空 = 整体关闭）。Scopes 缺省 openid profile email；UsernameClaim
// 缺省 preferred_username。HTTPClient/Now 是宿主测试与代理注入点，零值
// 分别落 10s 超时与 time.Now。
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string

	Scopes        []string
	UsernameClaim string

	HTTPClient *http.Client

	FlowTTL      time.Duration
	DiscoveryTTL time.Duration
	JWKSTTL      time.Duration
	Now          func() time.Time

	// StateStore 跨副本 flow state 载体（gopkg#29）。nil = 进程内 map
	// （缺省：单机/粘性代理形态零行为变化，逐字与历史一致）。无粘性的
	// 多副本部署让所有副本共享同一载体实现（见 StateStore 契约）。
	StateStore StateStore
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

// Flow 一次登录流转的服务端态（state → nonce/PKCE/宿主收编锚点）。注入
// StateStore 时经载体跨副本传递（gopkg#29）——导出面：宿主实现 Store 必须
// 存得下它；CreatedAt 由 Client 侧恒复核 TTL（防御 Store 过期策略失效）。
type Flow struct {
	Nonce     string
	Verifier  string
	Anchor    string
	CreatedAt time.Time
}

// Client IdP 往来客户端（并发安全；discovery/JWKS 进程内缓存）。
type Client struct {
	cfg  Config
	http *http.Client
	now  func() time.Time

	mu      sync.Mutex
	disco   *discoveryDoc
	discoAt time.Time
	keys    map[string]*rsa.PublicKey
	keysAt  time.Time
	flows   map[string]Flow // StateStore==nil 时的进程内流转态（缺省形态）
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
	return &Client{
		cfg:   cfg,
		http:  hc,
		now:   nowFn,
		keys:  map[string]*rsa.PublicKey{},
		flows: map[string]Flow{},
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
	if c.cfg.StateStore != nil {
		// 跨副本载体形态（gopkg#29）：写入失败按基础设施故障上抛
		// （ErrStateStore），不得静默降级为进程内 map——那会让回调落到
		// 本副本才能成功，拓扑决定的必现概率又回来了。
		if err := c.cfg.StateStore.Save(ctx, state, f, c.cfg.FlowTTL); err != nil {
			return "", fmt.Errorf("%w: flow state 写入失败: %v", ErrStateStore, err)
		}
	} else {
		c.mu.Lock()
		c.gcLocked()
		c.flows[state] = f
		c.mu.Unlock()
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

// CompleteLogin 回调收口：state 对账（单次+TTL，防重放；注入 StateStore 时
// 经载体跨副本取回，读故障包装 ErrStateStore 与「state 不存在」可区分，
// gopkg#29）→ code 换 token（PKCE verifier + 机密客户端凭据）→ ID token
// RS256/JWKS 验签（iss/aud/exp/nonce）→ 登录结果。
func (c *Client) CompleteLogin(ctx context.Context, code, state, redirectURI string) (*Result, error) {
	if !c.cfg.Enabled() {
		return nil, ErrDisabled
	}
	var f Flow
	var ok bool
	if c.cfg.StateStore != nil {
		var err error
		f, ok, err = c.cfg.StateStore.Take(ctx, state)
		if err != nil {
			// 载体读写故障 ≠ state 无效：基础设施可重试/告警，业务否决不混入。
			return nil, fmt.Errorf("%w: flow state 读取失败: %v", ErrStateStore, err)
		}
	} else {
		c.mu.Lock()
		f, ok = c.flows[state]
		if ok {
			delete(c.flows, state) // 单次消费：重放同一 state 直接落空
		}
		c.mu.Unlock()
	}
	if !ok || c.now().Sub(f.CreatedAt) > c.cfg.FlowTTL {
		// CreatedAt 复核恒做（gopkg#29）：Store 过期策略失效也不放行陈旧 state。
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

// gcLocked 清过期流转态（调用方持锁；惰性 GC 免后台协程）。
func (c *Client) gcLocked() {
	now := c.now()
	for k, f := range c.flows {
		if now.Sub(f.CreatedAt) > c.cfg.FlowTTL {
			delete(c.flows, k)
		}
	}
}
