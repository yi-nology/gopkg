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
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── 共享测试密钥与工具 ────────────────────────────────────────────────

var (
	testKeysOnce sync.Once
	testKey1     *rsa.PrivateKey
	testKey2     *rsa.PrivateKey
)

// sharedKey 取共享 RSA 密钥（keygen 慢，整个包只生成一次；测试 panic 即失败）。
func sharedKey(t *testing.T, second bool) *rsa.PrivateKey {
	t.Helper()
	testKeysOnce.Do(func() {
		var err error
		testKey1, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic("生成测试 RSA 密钥失败: " + err.Error())
		}
		testKey2, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic("生成测试 RSA 密钥失败: " + err.Error())
		}
	})
	if second {
		return testKey2
	}
	return testKey1
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// signJWT 用测试私钥签一张标准 RS256 JWT。
func signJWT(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return signSegments(t, key, string(header), string(payload))
}

// signSegments 对给定 header/payload JSON 文本签名（构造畸形 payload 用）。
func signSegments(t *testing.T, key *rsa.PrivateKey, headerJSON, payloadJSON string) string {
	t.Helper()
	signing := b64([]byte(headerJSON)) + "." + b64([]byte(payloadJSON))
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("签名: %v", err)
	}
	return signing + "." + b64(sig)
}

// validClaims 一张可过验签的 ID token claims（iss/aud/sub/exp/iat/nonce）。
func validClaims(issuer, nonce string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":   issuer,
		"sub":   "user-1",
		"aud":   "client-1",
		"exp":   now.Add(5 * time.Minute).Unix(),
		"iat":   now.Unix(),
		"nonce": nonce,
	}
}

// ── 假 IdP ───────────────────────────────────────────────────────────

type fakeIDP struct {
	t   *testing.T
	srv *httptest.Server

	mu               sync.Mutex
	keys             map[string]*rsa.PrivateKey
	discoveryFetches int
	jwksFetches      int
	tokenCalls       int
	lastTokenForm    url.Values
	tokenStatus      int
	tokenBody        []byte
	discoveryStatus  int
	discoveryBody    []byte
	jwksStatus       int
	jwksBody         []byte
}

func newFakeIDP(t *testing.T, keys map[string]*rsa.PrivateKey) *fakeIDP {
	t.Helper()
	f := &fakeIDP{t: t, keys: keys}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", f.handleDiscovery)
	mux.HandleFunc("/jwks", f.handleJWKS)
	mux.HandleFunc("/token", f.handleToken)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIDP) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	f.discoveryFetches++
	status, body := f.discoveryStatus, f.discoveryBody
	f.mu.Unlock()
	if status != 0 && status != http.StatusOK {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if body != nil {
		_, _ = w.Write(body)
		return
	}
	doc := map[string]string{
		"issuer":                 f.srv.URL,
		"authorization_endpoint": f.srv.URL + "/authorize",
		"token_endpoint":         f.srv.URL + "/token",
		"jwks_uri":               f.srv.URL + "/jwks",
	}
	_ = json.NewEncoder(w).Encode(doc)
}

func (f *fakeIDP) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	f.jwksFetches++
	status, body := f.jwksStatus, f.jwksBody
	keys := make(map[string]*rsa.PrivateKey, len(f.keys))
	for kid, key := range f.keys {
		keys[kid] = key
	}
	f.mu.Unlock()
	if status != 0 && status != http.StatusOK {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if body != nil {
		_, _ = w.Write(body)
		return
	}
	type jwk struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		N   string `json:"n"`
		E   string `json:"e"`
	}
	out := struct {
		Keys []jwk `json:"keys"`
	}{}
	for kid, key := range keys {
		out.Keys = append(out.Keys, jwk{
			Kty: "RSA",
			Kid: kid,
			N:   b64(key.N.Bytes()),
			E:   b64(big.NewInt(int64(key.E)).Bytes()),
		})
	}
	_ = json.NewEncoder(w).Encode(out)
}

func (f *fakeIDP) handleToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	f.tokenCalls++
	f.lastTokenForm = r.PostForm
	status, body := f.tokenStatus, f.tokenBody
	f.mu.Unlock()
	if status != 0 && status != http.StatusOK {
		w.WriteHeader(status)
		_, _ = w.Write(body)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

func (f *fakeIDP) setToken(tr tokenResponse) {
	body, err := json.Marshal(tr)
	if err != nil {
		f.t.Fatalf("marshal token response: %v", err)
	}
	f.mu.Lock()
	f.tokenBody = body
	f.mu.Unlock()
}

func (f *fakeIDP) setKeys(keys map[string]*rsa.PrivateKey) {
	f.mu.Lock()
	f.keys = keys
	f.mu.Unlock()
}

func (f *fakeIDP) fetchCounts() (discovery, jwks, token int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.discoveryFetches, f.jwksFetches, f.tokenCalls
}

func (f *fakeIDP) newClient(t *testing.T, mod func(*OidcConfig)) *OidcClient {
	t.Helper()
	cfg := OidcConfig{
		Issuer:       f.srv.URL,
		ClientID:     "client-1",
		ClientSecret: "secret-1",
	}
	if mod != nil {
		mod(&cfg)
	}
	return NewOidcClient(cfg)
}

// begin 发起登录并拆出 state/nonce/challenge。
func begin(t *testing.T, c *OidcClient, binding string) (authURL *url.URL, state, nonce string) {
	t.Helper()
	raw, err := c.BeginLogin(context.Background(), "https://app.example/cb", binding)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("授权 URL 非法: %v", err)
	}
	q := u.Query()
	return u, q.Get("state"), q.Get("nonce")
}

// ── 配置关闭 ────────────────────────────────────────────────────────

func TestDisabledConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  OidcConfig
	}{
		{"全空", OidcConfig{}},
		{"缺 client_id/client_secret", OidcConfig{Issuer: "https://idp"}},
		{"缺 client_secret", OidcConfig{Issuer: "https://idp", ClientID: "c"}},
		{"缺 issuer", OidcConfig{ClientID: "c", ClientSecret: "s"}},
	}
	for _, c := range cases {
		if c.cfg.Enabled() {
			t.Fatalf("%s: 三要素不齐不应 Enabled", c.name)
		}
		client := NewOidcClient(c.cfg)
		if client.Enabled() {
			t.Fatalf("%s: client 不应 Enabled", c.name)
		}
		if _, err := client.BeginLogin(context.Background(), "https://app/cb", ""); !errors.Is(err, ErrOidcDisabled) {
			t.Fatalf("%s: BeginLogin 应 ErrOidcDisabled，got %v", c.name, err)
		}
		if _, err := client.CompleteLogin(context.Background(), "code", "state", "https://app/cb"); !errors.Is(err, ErrOidcDisabled) {
			t.Fatalf("%s: CompleteLogin 应 ErrOidcDisabled，got %v", c.name, err)
		}
		if _, err := client.VerifyIDToken(context.Background(), "a.b.c", ""); !errors.Is(err, ErrOidcDisabled) {
			t.Fatalf("%s: VerifyIDToken 应 ErrOidcDisabled，got %v", c.name, err)
		}
	}
	full := OidcConfig{Issuer: "https://idp", ClientID: "c", ClientSecret: "s"}
	if !full.Enabled() {
		t.Fatal("三要素齐应 Enabled")
	}
}

// ── BeginLogin ──────────────────────────────────────────────────────

func TestBeginLogin(t *testing.T) {
	f := newFakeIDP(t, map[string]*rsa.PrivateKey{"kid-1": sharedKey(t, false)})
	client := f.newClient(t, nil)

	u, state, nonce := begin(t, client, "sess-anon-42")
	if u.Scheme != "http" || u.Host == "" || u.Path != "/authorize" {
		t.Fatalf("授权 URL 形态异常: %s", u)
	}
	q := u.Query()
	checks := map[string]string{
		"response_type":         "code",
		"client_id":             "client-1",
		"redirect_uri":          "https://app.example/cb",
		"scope":                 "openid profile email",
		"state":                 state,
		"nonce":                 nonce,
		"code_challenge_method": "S256",
	}
	for k, want := range checks {
		if got := q.Get(k); got != want {
			t.Errorf("%s=%q want %q", k, got, want)
		}
	}
	if len(state) != stateNonceBytes*2 {
		t.Errorf("state 长度=%d want %d hex", len(state), stateNonceBytes*2)
	}
	if _, err := hex.DecodeString(state); err != nil {
		t.Errorf("state 应为 hex: %v", err)
	}
	if len(nonce) != stateNonceBytes*2 {
		t.Errorf("nonce 长度=%d want %d hex", len(nonce), stateNonceBytes*2)
	}
	challenge := q.Get("code_challenge")
	if len(challenge) != 43 {
		t.Errorf("S256 challenge 应为 43 字符 base64url，got %d", len(challenge))
	}
	if strings.ContainsAny(challenge, "=+/") {
		t.Errorf("challenge 应为无填充 base64url: %q", challenge)
	}
	// binding 只落服务端流转态，不得出现在 IdP URL。
	if strings.Contains(u.RawQuery, "sess-anon-42") {
		t.Fatal("binding 不应外泄到授权 URL")
	}

	u2, state2, nonce2 := begin(t, client, "sess-anon-43")
	if state2 == state || nonce2 == nonce {
		t.Fatal("两次登录的 state/nonce 应不同")
	}
	if u2.Query().Get("code_challenge") == challenge {
		t.Fatal("两次登录的 PKCE challenge 应不同")
	}

	// 发现文档进程内缓存：两次 Begin 只拉一次。
	if got, _, _ := f.fetchCounts(); got != 1 {
		t.Fatalf("发现文档应缓存（1 次），got %d", got)
	}
	// Begin 不应请求 token/JWKS。
	if _, jwks, token := f.fetchCounts(); jwks != 0 || token != 0 {
		t.Fatalf("Begin 不应请求 JWKS/token: jwks=%d token=%d", jwks, token)
	}
}

func TestBeginLoginMergesEndpointQuery(t *testing.T) {
	f := newFakeIDP(t, map[string]*rsa.PrivateKey{"kid-1": sharedKey(t, false)})
	body, err := json.Marshal(map[string]string{
		"issuer":                 f.srv.URL,
		"authorization_endpoint": f.srv.URL + "/authorize?tenant=acme&x=1",
		"token_endpoint":         f.srv.URL + "/token",
		"jwks_uri":               f.srv.URL + "/jwks",
	})
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.discoveryBody = body
	f.mu.Unlock()

	client := f.newClient(t, nil)
	u, _, _ := begin(t, client, "")
	q := u.Query()
	if q.Get("tenant") != "acme" || q.Get("x") != "1" {
		t.Fatalf("端点既有 query 应保留: %s", u.RawQuery)
	}
	if q.Get("response_type") != "code" {
		t.Fatal("OIDC 参数应合并进既有 query")
	}
}

// ── CompleteLogin ───────────────────────────────────────────────────

func TestCompleteLoginHappyPath(t *testing.T) {
	key := sharedKey(t, false)
	f := newFakeIDP(t, map[string]*rsa.PrivateKey{"kid-1": key})
	client := f.newClient(t, nil)

	u, state, nonce := begin(t, client, "sess-anon-42")
	claims := validClaims(f.srv.URL, nonce)
	claims["groups"] = []string{"sre", "oncall"}
	token := signJWT(t, key, "kid-1", claims)
	f.setToken(tokenResponse{
		AccessToken:  "access-1",
		TokenType:    "Bearer",
		RefreshToken: "refresh-1",
		ExpiresIn:    3600,
		IDToken:      token,
	})

	res, err := client.CompleteLogin(context.Background(), "code-1", state, "https://app.example/cb")
	if err != nil {
		t.Fatalf("CompleteLogin: %v", err)
	}
	if res.Subject != "user-1" || res.Binding != "sess-anon-42" {
		t.Fatalf("sub/binding 不符: %+v", res)
	}
	if res.AccessToken != "access-1" || res.TokenType != "Bearer" || res.RefreshToken != "refresh-1" || res.ExpiresIn != 3600 {
		t.Fatalf("token 字段不符: %+v", res)
	}
	if res.IDToken == nil || res.IDToken.Nonce != nonce || res.IDToken.Issuer != f.srv.URL {
		t.Fatalf("IDToken 字段不符: %+v", res.IDToken)
	}
	groups, ok := res.Claims["groups"].([]any)
	if !ok || len(groups) != 2 || groups[0] != "sre" {
		t.Fatalf("groups claim 解出失真: %#v", res.Claims["groups"])
	}

	// token 端点 form 必须带 PKCE verifier 与机密客户端凭据，且 verifier 与
	// 授权 URL 的 S256 challenge 对得上。
	f.mu.Lock()
	form := f.lastTokenForm
	f.mu.Unlock()
	if form.Get("grant_type") != "authorization_code" || form.Get("code") != "code-1" ||
		form.Get("redirect_uri") != "https://app.example/cb" || form.Get("client_id") != "client-1" ||
		form.Get("client_secret") != "secret-1" {
		t.Fatalf("token form 字段不符: %v", form)
	}
	verifier := form.Get("code_verifier")
	if verifier == "" {
		t.Fatal("token form 缺 code_verifier")
	}
	if got, want := pkceChallenge(verifier), u.Query().Get("code_challenge"); got != want {
		t.Fatalf("verifier/challenge 不匹配: got %s want %s", got, want)
	}

	// state 一次性：重放同一 state 直接落空，且不再打 token 端点。
	if _, err := client.CompleteLogin(context.Background(), "code-2", state, "https://app.example/cb"); !errors.Is(err, ErrStateInvalid) {
		t.Fatalf("state 重放应 ErrStateInvalid，got %v", err)
	}
	if _, _, tokenCalls := f.fetchCounts(); tokenCalls != 1 {
		t.Fatalf("重放不应再请求 token 端点: %d", tokenCalls)
	}
}

func TestCompleteLoginUnknownState(t *testing.T) {
	f := newFakeIDP(t, map[string]*rsa.PrivateKey{"kid-1": sharedKey(t, false)})
	client := f.newClient(t, nil)
	if _, err := client.CompleteLogin(context.Background(), "code", "never-issued", "https://app.example/cb"); !errors.Is(err, ErrStateInvalid) {
		t.Fatalf("未知 state 应 ErrStateInvalid，got %v", err)
	}
}

func TestCompleteLoginFlowExpiry(t *testing.T) {
	f := newFakeIDP(t, map[string]*rsa.PrivateKey{"kid-1": sharedKey(t, false)})
	now := time.Now()
	client := f.newClient(t, func(c *OidcConfig) {
		c.FlowTTL = time.Minute
		c.Now = func() time.Time { return now }
	})
	_, state, _ := begin(t, client, "")
	now = now.Add(2 * time.Minute) // 超过 TTL

	if _, err := client.CompleteLogin(context.Background(), "code", state, "https://app.example/cb"); !errors.Is(err, ErrStateInvalid) {
		t.Fatalf("过期 flow 应 ErrStateInvalid，got %v", err)
	}
	if _, _, tokenCalls := f.fetchCounts(); tokenCalls != 0 {
		t.Fatalf("过期 flow 不应请求 token 端点: %d", tokenCalls)
	}
}

func TestCompleteLoginConsumesStateOnFailure(t *testing.T) {
	f := newFakeIDP(t, map[string]*rsa.PrivateKey{"kid-1": sharedKey(t, false)})
	client := f.newClient(t, nil)
	_, state, nonce := begin(t, client, "")
	// 先给一个 nonce 不符的 token：Complete 失败，但 state 已一次性消费。
	f.setToken(tokenResponse{IDToken: signJWT(t, sharedKey(t, false), "kid-1", validClaims(f.srv.URL, "wrong-"+nonce))})
	if _, err := client.CompleteLogin(context.Background(), "code", state, "https://app.example/cb"); !errors.Is(err, ErrIDToken) {
		t.Fatalf("nonce 不符应 ErrIDToken，got %v", err)
	}
	// 再用正确 token 重试同一 state：必须落空（不能借失败重放）。
	f.setToken(tokenResponse{IDToken: signJWT(t, sharedKey(t, false), "kid-1", validClaims(f.srv.URL, nonce))})
	if _, err := client.CompleteLogin(context.Background(), "code", state, "https://app.example/cb"); !errors.Is(err, ErrStateInvalid) {
		t.Fatalf("失败后 state 也应已消费，got %v", err)
	}
}

func TestCompleteLoginTokenEndpointErrors(t *testing.T) {
	key := sharedKey(t, false)
	cases := []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"非 200", http.StatusInternalServerError, `{"error":"server_error"}`, ErrTokenEndpoint},
		{"响应非 JSON", http.StatusOK, `not-json`, ErrTokenEndpoint},
		{"缺 id_token", http.StatusOK, `{"access_token":"a"}`, ErrIDToken},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeIDP(t, map[string]*rsa.PrivateKey{"kid-1": key})
			client := f.newClient(t, nil)
			_, state, _ := begin(t, client, "")
			f.mu.Lock()
			if c.status != http.StatusOK {
				f.tokenStatus = c.status
			}
			f.tokenBody = []byte(c.body)
			f.mu.Unlock()
			if _, err := client.CompleteLogin(context.Background(), "code", state, "https://app.example/cb"); !errors.Is(err, c.want) {
				t.Fatalf("应 %v，got %v", c.want, err)
			}
		})
	}
}

// ── 发现文档失败面 ──────────────────────────────────────────────────

func TestDiscoveryFailures(t *testing.T) {
	key := sharedKey(t, false)
	cases := []struct {
		name   string
		status int
		body   func(f *fakeIDP) []byte
	}{
		{"HTTP 500", http.StatusInternalServerError, nil},
		{"非 JSON", 0, func(*fakeIDP) []byte { return []byte("{") }},
		{"缺端点", 0, func(*fakeIDP) []byte { return []byte(`{"issuer":"x"}`) }},
		{"相对端点", 0, func(f *fakeIDP) []byte {
			b, _ := json.Marshal(map[string]string{
				"issuer":                 f.srv.URL,
				"authorization_endpoint": "/authorize",
				"token_endpoint":         f.srv.URL + "/token",
				"jwks_uri":               f.srv.URL + "/jwks",
			})
			return b
		}},
		{"issuer 不匹配", 0, func(f *fakeIDP) []byte {
			b, _ := json.Marshal(map[string]string{
				"issuer":                 "https://evil.example",
				"authorization_endpoint": f.srv.URL + "/authorize",
				"token_endpoint":         f.srv.URL + "/token",
				"jwks_uri":               f.srv.URL + "/jwks",
			})
			return b
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeIDP(t, map[string]*rsa.PrivateKey{"kid-1": key})
			client := f.newClient(t, nil)
			f.mu.Lock()
			f.discoveryStatus = c.status
			if c.body != nil {
				f.discoveryBody = c.body(f)
			}
			f.mu.Unlock()
			if _, err := client.BeginLogin(context.Background(), "https://app/cb", ""); !errors.Is(err, ErrDiscovery) {
				t.Fatalf("应 ErrDiscovery，got %v", err)
			}
		})
	}
}

// ── ID token 验签 ───────────────────────────────────────────────────

func TestVerifyIDTokenValidForms(t *testing.T) {
	key := sharedKey(t, false)
	f := newFakeIDP(t, map[string]*rsa.PrivateKey{"kid-1": key})
	client := f.newClient(t, nil)

	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"aud 字符串", nil},
		{"aud 数组含 client_id", func(c map[string]any) { c["aud"] = []string{"other", "client-1"} }},
		{"aud 数组含非字符串元素", func(c map[string]any) { c["aud"] = []any{"client-1", 42} }},
		{"nbf/iat 过去", func(c map[string]any) {
			now := time.Now().Add(-time.Minute).Unix()
			c["nbf"] = now
			c["iat"] = now
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			claims := validClaims(f.srv.URL, "nonce-1")
			if c.mutate != nil {
				c.mutate(claims)
			}
			idt, err := client.VerifyIDToken(context.Background(), signJWT(t, key, "kid-1", claims), "nonce-1")
			if err != nil {
				t.Fatalf("VerifyIDToken: %v", err)
			}
			if idt.Subject != "user-1" || idt.Issuer != f.srv.URL {
				t.Fatalf("字段不符: %+v", idt)
			}
			if !containsString(idt.Audience, "client-1") {
				t.Fatalf("aud 解出失真: %v", idt.Audience)
			}
		})
	}

	// 不要求 nonce 的入口：token 无 nonce、期望为空 → 通过。
	claims := validClaims(f.srv.URL, "")
	delete(claims, "nonce")
	if _, err := client.VerifyIDToken(context.Background(), signJWT(t, key, "kid-1", claims), ""); err != nil {
		t.Fatalf("空 nonce 双方一致应通过: %v", err)
	}
}

func TestVerifyIDTokenFailures(t *testing.T) {
	key := sharedKey(t, false)
	otherKey := sharedKey(t, true)
	f := newFakeIDP(t, map[string]*rsa.PrivateKey{"kid-1": key})
	client := f.newClient(t, nil)

	base := func(mutate func(map[string]any)) string {
		claims := validClaims(f.srv.URL, "nonce-1")
		if mutate != nil {
			mutate(claims)
		}
		return signJWT(t, key, "kid-1", claims)
	}
	cases := []struct {
		name  string
		token string
		nonce string
		want  error
	}{
		{"iss 不匹配", base(func(c map[string]any) { c["iss"] = "https://evil.example" }), "nonce-1", ErrIDToken},
		{"aud 字符串不匹配", base(func(c map[string]any) { c["aud"] = "other-client" }), "nonce-1", ErrIDToken},
		{"aud 数组不匹配", base(func(c map[string]any) { c["aud"] = []string{"a", "b"} }), "nonce-1", ErrIDToken},
		{"aud 缺失", base(func(c map[string]any) { delete(c, "aud") }), "nonce-1", ErrIDToken},
		{"aud 类型非法", base(func(c map[string]any) { c["aud"] = 42 }), "nonce-1", ErrIDToken},
		{"aud 空数组", base(func(c map[string]any) { c["aud"] = []string{} }), "nonce-1", ErrIDToken},
		{"nonce 不匹配", base(nil), "other-nonce", ErrIDToken},
		{"nonce 缺失", base(func(c map[string]any) { delete(c, "nonce") }), "nonce-1", ErrIDToken},
		{"exp 缺失", base(func(c map[string]any) { delete(c, "exp") }), "nonce-1", ErrIDToken},
		{"已过期", base(func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() }), "nonce-1", ErrIDToken},
		{"nbf 未生效", base(func(c map[string]any) { c["nbf"] = time.Now().Add(time.Hour).Unix() }), "nonce-1", ErrIDToken},
		{"iat 在未来", base(func(c map[string]any) { c["iat"] = time.Now().Add(time.Hour).Unix() }), "nonce-1", ErrIDToken},
		{"nbf 非数字", base(func(c map[string]any) { c["nbf"] = "soon" }), "nonce-1", ErrIDToken},
		{"iat 非数字", base(func(c map[string]any) { c["iat"] = "now" }), "nonce-1", ErrIDToken},
		{"sub 缺失", base(func(c map[string]any) { delete(c, "sub") }), "nonce-1", ErrIDToken},
		{"sub 为空", base(func(c map[string]any) { c["sub"] = "" }), "nonce-1", ErrIDToken},
		{"签名用错键", signJWT(t, otherKey, "kid-1", validClaims(f.srv.URL, "nonce-1")), "nonce-1", ErrIDToken},
		{"alg none", signJWTWithHeader(t, key, "none", "kid-1", validClaims(f.srv.URL, "nonce-1")), "nonce-1", ErrIDToken},
		{"alg HS256", signJWTWithHeader(t, key, "HS256", "kid-1", validClaims(f.srv.URL, "nonce-1")), "nonce-1", ErrIDToken},
		{"未知 kid", signJWT(t, otherKey, "kid-unknown", validClaims(f.srv.URL, "nonce-1")), "nonce-1", ErrJWKS},
		{"kid 缺失", signJWT(t, key, "", validClaims(f.srv.URL, "nonce-1")), "nonce-1", ErrJWKS},
		{"空 token", "", "", ErrIDToken},
		{"两段", "a.b", "", ErrIDToken},
		{"四段", "a.b.c.d", "", ErrIDToken},
		{"空段", ".b.c", "", ErrIDToken},
		{"header 非 base64", "!!!." + b64([]byte(`{"alg":"RS256"}`)) + "." + b64([]byte("x")), "", ErrIDToken},
		{"payload 非 base64", b64([]byte(`{"alg":"RS256","kid":"kid-1"}`)) + ".!!!." + b64([]byte("x")), "", ErrIDToken},
		{"签名非 base64", b64([]byte(`{"alg":"RS256","kid":"kid-1"}`)) + "." + b64([]byte(`{"iss":"x"}`)) + ".!!!", "", ErrIDToken},
		{"header 非 JSON", b64([]byte("not-json")) + "." + b64([]byte(`{}`)) + "." + b64([]byte("x")), "", ErrIDToken},
		{"签署 payload 非 JSON", signSegments(t, key, `{"alg":"RS256","kid":"kid-1"}`, "not-json"), "", ErrIDToken},
		{"签署 payload 是数组", signSegments(t, key, `{"alg":"RS256","kid":"kid-1"}`, `[]`), "", ErrIDToken},
		{"签署 payload 尾随 JSON", signSegments(t, key, `{"alg":"RS256","kid":"kid-1"}`, `{"iss":"x"} {}`), "", ErrIDToken},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := client.VerifyIDToken(context.Background(), c.token, c.nonce); !errors.Is(err, c.want) {
				t.Fatalf("应 %v，got %v", c.want, err)
			}
		})
	}
}

// signJWTWithHeader 用指定 alg 签（构造 alg 混淆攻击样本）。
func signJWTWithHeader(t *testing.T, key *rsa.PrivateKey, alg, kid string, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": alg, "typ": "JWT", "kid": kid})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return signSegments(t, key, string(header), string(payload))
}

func TestVerifyIDTokenExpBoundary(t *testing.T) {
	key := sharedKey(t, false)
	f := newFakeIDP(t, map[string]*rsa.PrivateKey{"kid-1": key})
	fixed := time.Now().Add(time.Minute).Truncate(time.Second)
	client := f.newClient(t, func(c *OidcConfig) {
		c.Now = func() time.Time { return fixed }
	})
	claims := validClaims(f.srv.URL, "nonce-1")
	claims["exp"] = fixed.Unix()
	claims["iat"] = fixed.Unix()
	if _, err := client.VerifyIDToken(context.Background(), signJWT(t, key, "kid-1", claims), "nonce-1"); err != nil {
		t.Fatalf("now == exp 应有效（含端点）: %v", err)
	}
	claims["exp"] = fixed.Unix() - 1
	if _, err := client.VerifyIDToken(context.Background(), signJWT(t, key, "kid-1", claims), "nonce-1"); !errors.Is(err, ErrIDToken) {
		t.Fatalf("now > exp 应 ErrIDToken，got %v", err)
	}
}

func TestJWKSCacheAndRotation(t *testing.T) {
	key1 := sharedKey(t, false)
	key2 := sharedKey(t, true)
	f := newFakeIDP(t, map[string]*rsa.PrivateKey{"kid-1": key1})
	client := f.newClient(t, nil)

	// 首次验签：JWKS 拉一次。
	if _, err := client.VerifyIDToken(context.Background(), signJWT(t, key1, "kid-1", validClaims(f.srv.URL, "n")), "n"); err != nil {
		t.Fatalf("首次验签: %v", err)
	}
	// 第二次同 kid：缓存命中，不再拉。
	if _, err := client.VerifyIDToken(context.Background(), signJWT(t, key1, "kid-1", validClaims(f.srv.URL, "n")), "n"); err != nil {
		t.Fatalf("缓存命中验签: %v", err)
	}
	if _, jwks, _ := f.fetchCounts(); jwks != 1 {
		t.Fatalf("JWKS 应缓存（1 次），got %d", jwks)
	}

	// IdP 轮换：JWKS 换 kid-2，旧缓存只有 kid-1 → 未知 kid 强刷一次即通过。
	f.setKeys(map[string]*rsa.PrivateKey{"kid-2": key2})
	if _, err := client.VerifyIDToken(context.Background(), signJWT(t, key2, "kid-2", validClaims(f.srv.URL, "n")), "n"); err != nil {
		t.Fatalf("未知 kid 应强刷 JWKS 后通过: %v", err)
	}
	if _, jwks, _ := f.fetchCounts(); jwks != 2 {
		t.Fatalf("未知 kid 应恰好强刷一次（总 2 次），got %d", jwks)
	}
}

func TestJWKSMalformed(t *testing.T) {
	key := sharedKey(t, false)
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"非 200", http.StatusBadGateway, ""},
		{"非 JSON", 0, "not-json"},
		{"无 RSA 键", 0, `{"keys":[{"kty":"EC","kid":"kid-1","n":"x","e":"AQAB"}]}`},
		{"n 非法", 0, `{"keys":[{"kty":"RSA","kid":"kid-1","n":"!!!","e":"AQAB"}]}`},
		{"e 非法", 0, `{"keys":[{"kty":"RSA","kid":"kid-1","n":"AQAB","e":"!!!"}]}`},
		{"e 为空", 0, `{"keys":[{"kty":"RSA","kid":"kid-1","n":"AQAB","e":""}]}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeIDP(t, map[string]*rsa.PrivateKey{"kid-1": key})
			client := f.newClient(t, nil)
			f.mu.Lock()
			f.jwksStatus = c.status
			if c.body != "" {
				f.jwksBody = []byte(c.body)
			}
			f.mu.Unlock()
			token := signJWT(t, key, "kid-1", validClaims(f.srv.URL, "n"))
			if _, err := client.VerifyIDToken(context.Background(), token, "n"); !errors.Is(err, ErrJWKS) {
				t.Fatalf("应 ErrJWKS，got %v", err)
			}
		})
	}
}
