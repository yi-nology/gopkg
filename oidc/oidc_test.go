package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// idp 最小 fake IdP：发现文档 + JWKS + token 端点。
type idp struct {
	t      *testing.T
	server *httptest.Server

	mu          sync.Mutex
	key         *rsa.PrivateKey
	kid         string
	alg         string
	jwks        map[string]*rsa.PublicKey
	claims      map[string]any
	discoStatus int
	tokenStatus int
	omitIDToken bool
	discoMutate func(*discoveryDoc)

	discoHits int
	jwksHits  int
	tokenHits int
	lastForm  url.Values
}

func newIDP(t *testing.T) *idp {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	i := &idp{
		t:      t,
		key:    key,
		kid:    "kid-1",
		alg:    "RS256",
		jwks:   map[string]*rsa.PublicKey{"kid-1": &key.PublicKey},
		claims: map[string]any{},
	}
	i.server = httptest.NewServer(http.HandlerFunc(i.handle))
	t.Cleanup(i.server.Close)
	i.claims = i.defaultClaims()
	return i
}

func (i *idp) defaultClaims() map[string]any {
	return map[string]any{
		"iss":                i.server.URL,
		"sub":                "user-1",
		"aud":                "client-1",
		"exp":                time.Now().Add(time.Hour).Unix(),
		"preferred_username": "alice",
		"email":              "alice@example.com",
		"groups":             []any{"team-a", "team-b"},
	}
}

func (i *idp) handle(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		i.handleDiscovery(w)
	case "/jwks":
		i.handleJWKS(w)
	case "/token":
		i.handleToken(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (i *idp) handleDiscovery(w http.ResponseWriter) {
	i.mu.Lock()
	i.discoHits++
	doc := discoveryDoc{
		AuthorizationEndpoint: i.server.URL + "/authorize",
		TokenEndpoint:         i.server.URL + "/token",
		JWKSURI:               i.server.URL + "/jwks",
		Issuer:                i.server.URL,
	}
	mutate := i.discoMutate
	status := i.discoStatus
	i.mu.Unlock()
	if mutate != nil {
		mutate(&doc)
	}
	if status != 0 {
		w.WriteHeader(status)
		return
	}
	_ = json.NewEncoder(w).Encode(doc)
}

func (i *idp) handleJWKS(w http.ResponseWriter) {
	i.mu.Lock()
	i.jwksHits++
	keys := make([]map[string]any, 0, len(i.jwks))
	for kid, pub := range i.jwks {
		e := big.NewInt(int64(pub.E)).Bytes()
		keys = append(keys, map[string]any{
			"kty": "RSA",
			"kid": kid,
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(e),
		})
	}
	i.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
}

func (i *idp) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	i.mu.Lock()
	i.tokenHits++
	i.lastForm = r.PostForm
	status := i.tokenStatus
	omit := i.omitIDToken
	key := i.key
	kid := i.kid
	alg := i.alg
	payload, err := json.Marshal(i.claims)
	i.mu.Unlock()
	if status != 0 {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"error":"server_error"}`))
		return
	}
	if omit {
		_, _ = w.Write([]byte(`{}`))
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tok, err := signToken(key, kid, alg, payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"id_token": tok, "token_type": "Bearer"})
}

func signToken(key *rsa.PrivateKey, kid, alg string, payload []byte) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": alg, "kid": kid, "typ": "JWT"})
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (i *idp) setNonce(nonce string) {
	i.mu.Lock()
	i.claims["nonce"] = nonce
	i.mu.Unlock()
}

func (i *idp) updateClaims(fn func(map[string]any)) {
	i.mu.Lock()
	fn(i.claims)
	i.mu.Unlock()
}

func (i *idp) counts() (disco, jwks, token int) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.discoHits, i.jwksHits, i.tokenHits
}

func (i *idp) form() url.Values {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.lastForm
}

func newTestClient(i *idp, mutate func(*Config)) *Client {
	cfg := Config{Issuer: i.server.URL, ClientID: "client-1", ClientSecret: "s3cret"}
	if mutate != nil {
		mutate(&cfg)
	}
	return New(cfg)
}

// begin 发起登录并解出 state/nonce（assert 授权 URL 的 PKCE 形状）。
func begin(t *testing.T, c *Client, anchor string) (authURL, state, nonce, challenge string) {
	t.Helper()
	authURL, err := c.BeginLogin(context.Background(), "https://app.example.com/callback", anchor)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse auth URL: %v", err)
	}
	q := u.Query()
	state, nonce, challenge = q.Get("state"), q.Get("nonce"), q.Get("code_challenge")
	if state == "" || nonce == "" || challenge == "" {
		t.Fatalf("授权 URL 缺 state/nonce/code_challenge: %s", authURL)
	}
	return authURL, state, nonce, challenge
}

func complete(c *Client, state string) (*Result, error) {
	return c.CompleteLogin(context.Background(), "auth-code-1", state, "https://app.example.com/callback")
}

func TestDisabledWhenAnyElementMissing(t *testing.T) {
	cases := map[string]Config{
		"all empty":             {},
		"missing client secret": {Issuer: "https://idp", ClientID: "c"},
		"missing client id":     {Issuer: "https://idp", ClientSecret: "s"},
		"missing issuer":        {ClientID: "c", ClientSecret: "s"},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			c := New(cfg)
			if c.Enabled() {
				t.Fatal("Enabled() = true, want false")
			}
			if _, err := c.BeginLogin(context.Background(), "https://app/cb", ""); !errors.Is(err, ErrDisabled) {
				t.Fatalf("BeginLogin err = %v, want ErrDisabled", err)
			}
			if _, err := complete(c, "state"); !errors.Is(err, ErrDisabled) {
				t.Fatalf("CompleteLogin err = %v, want ErrDisabled", err)
			}
		})
	}
}

func TestBeginLoginAuthorizationURLAndDiscoveryCache(t *testing.T) {
	i := newIDP(t)
	c := newTestClient(i, nil)
	authURL, state, nonce, challenge := begin(t, c, "browser-7")

	u, _ := url.Parse(authURL)
	q := u.Query()
	if got := q.Get("response_type"); got != "code" {
		t.Errorf("response_type = %q", got)
	}
	if got := q.Get("client_id"); got != "client-1" {
		t.Errorf("client_id = %q", got)
	}
	if got := q.Get("redirect_uri"); got != "https://app.example.com/callback" {
		t.Errorf("redirect_uri = %q", got)
	}
	if got := q.Get("scope"); got != "openid profile email" {
		t.Errorf("scope = %q", got)
	}
	if got := q.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q", got)
	}
	raw, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil || len(raw) != sha256.Size {
		t.Errorf("code_challenge 形态非法: %v len=%d", err, len(raw))
	}
	if len(state) != 32 || len(nonce) != 32 {
		t.Errorf("state/nonce 长度 = %d/%d, want 32/32", len(state), len(nonce))
	}

	// 第二次 BeginLogin：发现文档命中缓存。
	_, state2, _, _ := begin(t, c, "")
	if state2 == state {
		t.Error("两次 BeginLogin 的 state 相同")
	}
	if disco, _, _ := i.counts(); disco != 1 {
		t.Errorf("发现文档请求次数 = %d, want 1（缓存命中）", disco)
	}
}

func TestCompleteLoginSuccess(t *testing.T) {
	i := newIDP(t)
	c := newTestClient(i, nil)
	_, state, nonce, challenge := begin(t, c, "browser-7")
	i.setNonce(nonce)

	res, err := complete(c, state)
	if err != nil {
		t.Fatalf("CompleteLogin: %v", err)
	}
	if res.Subject != "user-1" || res.Username != "alice" || res.Anchor != "browser-7" {
		t.Errorf("result = %+v", res)
	}
	if len(res.Groups) != 2 || res.Groups[0] != "team-a" || res.Groups[1] != "team-b" {
		t.Errorf("groups = %v", res.Groups)
	}
	if res.Claims["email"] != "alice@example.com" {
		t.Errorf("claims.email = %v", res.Claims["email"])
	}

	form := i.form()
	if form.Get("grant_type") != "authorization_code" || form.Get("code") != "auth-code-1" ||
		form.Get("redirect_uri") != "https://app.example.com/callback" ||
		form.Get("client_id") != "client-1" || form.Get("client_secret") != "s3cret" {
		t.Errorf("token 请求表单 = %v", form)
	}
	verifier := form.Get("code_verifier")
	sum := sha256.Sum256([]byte(verifier))
	if got := base64.RawURLEncoding.EncodeToString(sum[:]); got != challenge {
		t.Errorf("code_verifier 与 challenge 不对应: %q != %q", got, challenge)
	}

	// state 单次消费：重放不得到达 token 端点。
	if _, err := complete(c, state); !errors.Is(err, ErrFlowInvalid) {
		t.Fatalf("replay err = %v, want ErrFlowInvalid", err)
	}
	if _, _, token := i.counts(); token != 1 {
		t.Errorf("token 端点请求次数 = %d, want 1", token)
	}
	if disco, jwks, _ := i.counts(); disco != 1 || jwks != 1 {
		t.Errorf("disco/jwks = %d/%d, want 1/1", disco, jwks)
	}
}

func TestCompleteLoginUnknownState(t *testing.T) {
	i := newIDP(t)
	c := newTestClient(i, nil)
	if _, err := complete(c, "never-issued"); !errors.Is(err, ErrFlowInvalid) {
		t.Fatalf("err = %v, want ErrFlowInvalid", err)
	}
	if disco, _, token := i.counts(); disco != 0 || token != 0 {
		t.Errorf("无效 state 不应触网: disco=%d token=%d", disco, token)
	}
}

func TestFlowTTL(t *testing.T) {
	i := newIDP(t)
	c := newTestClient(i, func(cfg *Config) { cfg.FlowTTL = 20 * time.Millisecond })
	_, state, nonce, _ := begin(t, c, "")
	i.setNonce(nonce)
	time.Sleep(40 * time.Millisecond)
	if _, err := complete(c, state); !errors.Is(err, ErrFlowInvalid) {
		t.Fatalf("err = %v, want ErrFlowInvalid", err)
	}
	if _, _, token := i.counts(); token != 0 {
		t.Errorf("过期 state 不应触达 token 端点: %d", token)
	}
}

func TestNonceMismatch(t *testing.T) {
	i := newIDP(t)
	c := newTestClient(i, nil)
	_, state, nonce, _ := begin(t, c, "")
	i.setNonce(nonce + "-other")
	if _, err := complete(c, state); !errors.Is(err, ErrIDToken) || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("err = %v, want ErrIDToken/nonce", err)
	}
}

func TestClaimValidation(t *testing.T) {
	tests := map[string]struct {
		mutate func(*idp)
		substr string
	}{
		"issuer mismatch": {func(i *idp) {
			i.updateClaims(func(m map[string]any) { m["iss"] = "https://evil.example.com" })
		}, "iss"},
		"audience mismatch": {func(i *idp) {
			i.updateClaims(func(m map[string]any) { m["aud"] = "other-client" })
		}, "aud"},
		"expired": {func(i *idp) {
			i.updateClaims(func(m map[string]any) { m["exp"] = time.Now().Add(-time.Minute).Unix() })
		}, "过期"},
		"not before": {func(i *idp) {
			i.updateClaims(func(m map[string]any) { m["nbf"] = time.Now().Add(time.Hour).Unix() })
		}, "nbf"},
		"missing exp": {func(i *idp) {
			i.updateClaims(func(m map[string]any) { delete(m, "exp") })
		}, "exp"},
		"missing sub": {func(i *idp) {
			i.updateClaims(func(m map[string]any) { delete(m, "sub") })
		}, "sub"},
		"missing nonce": {func(i *idp) {
			i.updateClaims(func(m map[string]any) { delete(m, "nonce") })
		}, "nonce"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			i := newIDP(t)
			c := newTestClient(i, nil)
			_, state, nonce, _ := begin(t, c, "")
			i.setNonce(nonce)
			tc.mutate(i)
			_, err := complete(c, state)
			if !errors.Is(err, ErrIDToken) {
				t.Fatalf("err = %v, want ErrIDToken", err)
			}
			if !strings.Contains(err.Error(), tc.substr) {
				t.Errorf("err = %v, want contains %q", err, tc.substr)
			}
		})
	}
}

func TestAudienceArrayAccepted(t *testing.T) {
	i := newIDP(t)
	c := newTestClient(i, nil)
	_, state, nonce, _ := begin(t, c, "")
	i.setNonce(nonce)
	i.updateClaims(func(m map[string]any) { m["aud"] = []any{"other-client", "client-1"} })
	if _, err := complete(c, state); err != nil {
		t.Fatalf("CompleteLogin: %v", err)
	}
}

func TestAlgNoneOrHMACRejected(t *testing.T) {
	for _, alg := range []string{"none", "HS256", "RS384"} {
		t.Run(alg, func(t *testing.T) {
			i := newIDP(t)
			c := newTestClient(i, nil)
			_, state, nonce, _ := begin(t, c, "")
			i.setNonce(nonce)
			i.mu.Lock()
			i.alg = alg
			i.mu.Unlock()
			if _, err := complete(c, state); !errors.Is(err, ErrIDToken) {
				t.Fatalf("err = %v, want ErrIDToken", err)
			}
		})
	}
}

func TestBadSignature(t *testing.T) {
	i := newIDP(t)
	c := newTestClient(i, nil)
	_, state, nonce, _ := begin(t, c, "")
	i.setNonce(nonce)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	i.mu.Lock()
	i.key = other // kid 仍指向原公钥：签名与 JWKS 公钥不匹配
	i.mu.Unlock()
	if _, err := complete(c, state); !errors.Is(err, ErrIDToken) {
		t.Fatalf("err = %v, want ErrIDToken", err)
	}
}

func TestUnknownKidForcesOneJWKSRefresh(t *testing.T) {
	i := newIDP(t)
	c := newTestClient(i, nil)

	// 第一次登录：建立 JWKS 缓存（kid-1）。
	_, state, nonce, _ := begin(t, c, "")
	i.setNonce(nonce)
	if _, err := complete(c, state); err != nil {
		t.Fatalf("first CompleteLogin: %v", err)
	}
	if _, jwks, _ := i.counts(); jwks != 1 {
		t.Fatalf("jwks hits = %d, want 1", jwks)
	}

	// IdP 轮换到 kid-2：缓存无 kid-2 → 强制刷新一次并成功。
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	i.mu.Lock()
	i.key, i.kid = key2, "kid-2"
	i.jwks = map[string]*rsa.PublicKey{"kid-2": &key2.PublicKey}
	i.mu.Unlock()
	_, state, nonce, _ = begin(t, c, "")
	i.setNonce(nonce)
	if _, err := complete(c, state); err != nil {
		t.Fatalf("rotated CompleteLogin: %v", err)
	}
	if _, jwks, _ := i.counts(); jwks != 2 {
		t.Errorf("jwks hits = %d, want 2（未知 kid 强刷一次）", jwks)
	}

	// 未知 kid 且刷新后仍不存在：只刷新一次，不反复拉取。
	i.mu.Lock()
	i.kid = "kid-missing"
	i.mu.Unlock()
	_, state, nonce, _ = begin(t, c, "")
	i.setNonce(nonce)
	if _, err := complete(c, state); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("err = %v, want ErrUnknownKey", err)
	}
	if _, jwks, _ := i.counts(); jwks != 3 {
		t.Errorf("jwks hits = %d, want 3（仅一次强制刷新）", jwks)
	}
}

func TestJWKSCacheWithinTTL(t *testing.T) {
	i := newIDP(t)
	c := newTestClient(i, nil)
	for n := 0; n < 3; n++ {
		_, state, nonce, _ := begin(t, c, "")
		i.setNonce(nonce)
		if _, err := complete(c, state); err != nil {
			t.Fatalf("CompleteLogin #%d: %v", n, err)
		}
	}
	if _, jwks, _ := i.counts(); jwks != 1 {
		t.Errorf("jwks hits = %d, want 1", jwks)
	}
}

func TestTokenEndpointFailures(t *testing.T) {
	tests := map[string]func(*idp){
		"status 500": func(i *idp) {
			i.mu.Lock()
			i.tokenStatus = http.StatusInternalServerError
			i.mu.Unlock()
		},
		"missing idtoken": func(i *idp) {
			i.mu.Lock()
			i.omitIDToken = true
			i.mu.Unlock()
		},
	}
	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			i := newIDP(t)
			c := newTestClient(i, nil)
			_, state, nonce, _ := begin(t, c, "")
			i.setNonce(nonce)
			setup(i)
			if _, err := complete(c, state); !errors.Is(err, ErrProvider) {
				t.Fatalf("err = %v, want ErrProvider", err)
			}
		})
	}
}

func TestDiscoveryValidation(t *testing.T) {
	tests := map[string]func(*idp){
		"issuer mismatch": func(i *idp) {
			i.mu.Lock()
			i.discoMutate = func(d *discoveryDoc) { d.Issuer = "https://evil.example.com" }
			i.mu.Unlock()
		},
		"missing jwks endpoint": func(i *idp) {
			i.mu.Lock()
			i.discoMutate = func(d *discoveryDoc) { d.JWKSURI = "" }
			i.mu.Unlock()
		},
		"missing token endpoint": func(i *idp) {
			i.mu.Lock()
			i.discoMutate = func(d *discoveryDoc) { d.TokenEndpoint = "" }
			i.mu.Unlock()
		},
		"non-200": func(i *idp) {
			i.mu.Lock()
			i.discoStatus = http.StatusBadGateway
			i.mu.Unlock()
		},
	}
	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			i := newIDP(t)
			c := newTestClient(i, nil)
			setup(i)
			if _, err := c.BeginLogin(context.Background(), "https://app/cb", ""); !errors.Is(err, ErrProvider) {
				t.Fatalf("err = %v, want ErrProvider", err)
			}
		})
	}
}

func TestUsernameFallback(t *testing.T) {
	t.Run("email fallback", func(t *testing.T) {
		i := newIDP(t)
		c := newTestClient(i, nil)
		_, state, nonce, _ := begin(t, c, "")
		i.setNonce(nonce)
		i.updateClaims(func(m map[string]any) { delete(m, "preferred_username") })
		res, err := complete(c, state)
		if err != nil {
			t.Fatal(err)
		}
		if res.Username != "alice@example.com" {
			t.Errorf("username = %q", res.Username)
		}
	})
	t.Run("sub fallback", func(t *testing.T) {
		i := newIDP(t)
		c := newTestClient(i, nil)
		_, state, nonce, _ := begin(t, c, "")
		i.setNonce(nonce)
		i.updateClaims(func(m map[string]any) {
			delete(m, "preferred_username")
			delete(m, "email")
		})
		res, err := complete(c, state)
		if err != nil {
			t.Fatal(err)
		}
		if res.Username != "user-1" {
			t.Errorf("username = %q", res.Username)
		}
	})
}

func TestCustomUsernameClaim(t *testing.T) {
	i := newIDP(t)
	c := newTestClient(i, func(cfg *Config) { cfg.UsernameClaim = "nickname" })
	_, state, nonce, _ := begin(t, c, "")
	i.setNonce(nonce)
	i.updateClaims(func(m map[string]any) { m["nickname"] = "alice-nick" })
	res, err := complete(c, state)
	if err != nil {
		t.Fatal(err)
	}
	if res.Username != "alice-nick" {
		t.Errorf("username = %q", res.Username)
	}
}

func TestGroupsTolerateNonStrings(t *testing.T) {
	i := newIDP(t)
	c := newTestClient(i, nil)
	_, state, nonce, _ := begin(t, c, "")
	i.setNonce(nonce)
	i.updateClaims(func(m map[string]any) { m["groups"] = []any{"g1", 7, "", "g2"} })
	res, err := complete(c, state)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Groups) != 2 || res.Groups[0] != "g1" || res.Groups[1] != "g2" {
		t.Errorf("groups = %v", res.Groups)
	}
}

func TestConcurrentStateConsumption(t *testing.T) {
	i := newIDP(t)
	c := newTestClient(i, nil)
	_, state, nonce, _ := begin(t, c, "")
	i.setNonce(nonce)

	const n = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	okCount := 0
	for k := 0; k < n; k++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := complete(c, state); err == nil {
				mu.Lock()
				okCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if okCount != 1 {
		t.Errorf("成功次数 = %d, want 1", okCount)
	}
	if _, _, token := i.counts(); token != 1 {
		t.Errorf("token 端点请求次数 = %d, want 1", token)
	}
}

func TestDiscoveryURLTrimTrailingSlash(t *testing.T) {
	i := newIDP(t)
	c := newTestClient(i, func(cfg *Config) { cfg.Issuer += "/" })
	// 发现文档 issuer 仍是无尾斜杠的 server URL，配置带斜杠时会精确不匹配。
	if _, err := c.BeginLogin(context.Background(), "https://app/cb", ""); !errors.Is(err, ErrProvider) {
		t.Fatalf("err = %v, want ErrProvider（issuer 精确匹配）", err)
	}
}

func TestNumericDateStringForm(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	for _, v := range []any{float64(exp), fmt.Sprintf("%d", exp)} {
		got, ok := numericDate(v)
		if !ok || got.Unix() != exp {
			t.Errorf("numericDate(%v) = %v, %v", v, got, ok)
		}
	}
	if _, ok := numericDate(true); ok {
		t.Error("bool 不应解为 NumericDate")
	}
}
