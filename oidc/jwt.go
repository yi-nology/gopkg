package oidc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// IDToken 验证通过的 ID token 标准字段视图（Claims 保留全部原始 claims）。
type IDToken struct {
	// Issuer iss（已与配置 Issuer 精确比对）。
	Issuer string
	// Subject sub（已验证非空）。
	Subject string
	// Audience aud 的全部字符串值（已验证包含 ClientID）。
	Audience []string
	// ExpiresAt exp（已校验存在且未过期）。
	ExpiresAt time.Time
	// IssuedAt iat（缺失为零值）。
	IssuedAt time.Time
	// NotBefore nbf（缺失为零值）。
	NotBefore time.Time
	// Nonce nonce（已与流转态对账；期望为空时要求 claim 也为空）。
	Nonce string
	// Claims 完整 claims；数值由 json.Decoder.UseNumber 解码为 json.Number。
	Claims map[string]any
	// Raw 原始紧凑 JWT 文本。
	Raw string
}

// jwksDoc JWKS 子集：只消费 RSA 公钥（kty/kid/n/e）。
type jwksDoc struct {
	Keys []struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

// VerifyIDToken 校验原始 ID token：RS256 强制（无算法协商面）→ JWKS 取键
// （未知 kid 强制刷新一次）→ RSA 签名 → iss 精确、aud 含 ClientID、exp 必填
// 且未过期、nbf/iat 可选校验、nonce 精确对账、sub 非空。
//
// nonce 为空表示调用方不要求 nonce（其他入口复用验签时）；登录主路径
// [OidcClient.CompleteLogin] 恒传流转态 nonce——期望为空而 token 携带 nonce
// 同样判失败（双向精确）。
func (c *OidcClient) VerifyIDToken(ctx context.Context, raw, nonce string) (*IDToken, error) {
	if !c.cfg.Enabled() {
		return nil, ErrOidcDisabled
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, fmt.Errorf("%w: JWT 形态非法（须三段非空）", ErrIDToken)
	}

	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header 不是合法 base64url", ErrIDToken)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerRaw, &hdr); err != nil {
		return nil, fmt.Errorf("%w: header 不是合法 JSON", ErrIDToken)
	}
	// 算法白名单先于一切密钥操作：none/HS256/ES256 等一律拒绝，杜绝
	// alg confusion（不存在「按 header 选算法」的面）。
	if hdr.Alg != "RS256" {
		return nil, fmt.Errorf("%w: alg=%q（仅支持 RS256）", ErrIDToken, hdr.Alg)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: 签名不是合法 base64url", ErrIDToken)
	}
	key, err := c.verifyKey(ctx, hdr.Kid)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		return nil, fmt.Errorf("%w: 签名不匹配", ErrIDToken)
	}

	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload 不是合法 base64url", ErrIDToken)
	}
	claims := map[string]any{}
	dec := json.NewDecoder(bytes.NewReader(payloadRaw))
	dec.UseNumber()
	if err := dec.Decode(&claims); err != nil {
		return nil, fmt.Errorf("%w: claims 不是合法 JSON 对象", ErrIDToken)
	}
	if err := ensureEOF(dec); err != nil {
		return nil, fmt.Errorf("%w: claims 尾随非法内容", ErrIDToken)
	}

	iss, _ := claims["iss"].(string)
	if iss != c.cfg.Issuer {
		return nil, fmt.Errorf("%w: iss 不匹配: %q", ErrIDToken, iss)
	}
	aud, ok := audienceOf(claims["aud"])
	if !ok || !containsString(aud, c.cfg.ClientID) {
		return nil, fmt.Errorf("%w: aud 不含 client_id", ErrIDToken)
	}
	n, _ := claims["nonce"].(string)
	if n != nonce {
		return nil, fmt.Errorf("%w: nonce 不匹配", ErrIDToken)
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, fmt.Errorf("%w: 缺 sub", ErrIDToken)
	}

	exp, ok := numericDate(claims["exp"])
	if !ok {
		return nil, fmt.Errorf("%w: 缺 exp 或不是数字", ErrIDToken)
	}
	now := c.now()
	if now.Unix() > exp {
		return nil, fmt.Errorf("%w: 已过期", ErrIDToken)
	}
	var iat, nbf time.Time
	if v, ok := claims["nbf"]; ok {
		nbfUnix, ok := numericDate(v)
		if !ok {
			return nil, fmt.Errorf("%w: nbf 不是数字", ErrIDToken)
		}
		if now.Unix() < nbfUnix {
			return nil, fmt.Errorf("%w: nbf 尚未生效", ErrIDToken)
		}
		nbf = time.Unix(nbfUnix, 0).UTC()
	}
	if v, ok := claims["iat"]; ok {
		iatUnix, ok := numericDate(v)
		if !ok {
			return nil, fmt.Errorf("%w: iat 不是数字", ErrIDToken)
		}
		if now.Unix() < iatUnix {
			return nil, fmt.Errorf("%w: iat 在未来", ErrIDToken)
		}
		iat = time.Unix(iatUnix, 0).UTC()
	}

	return &IDToken{
		Issuer:    iss,
		Subject:   sub,
		Audience:  aud,
		ExpiresAt: time.Unix(exp, 0).UTC(),
		IssuedAt:  iat,
		NotBefore: nbf,
		Nonce:     n,
		Claims:    claims,
		Raw:       raw,
	}, nil
}

// ensureEOF 确认 decoder 已消费完整个 JSON 文本（拒绝尾随 token）。
func ensureEOF(dec *json.Decoder) error {
	var extra any
	err := dec.Decode(&extra)
	if err == io.EOF {
		return nil
	}
	if err == nil {
		return fmt.Errorf("尾随 JSON 值")
	}
	return err
}

// audienceOf 解析 aud：允许字符串或字符串数组（OIDC 两种形态都合法），
// 跳过数组中的非字符串元素；没有任何字符串时失败。
func audienceOf(v any) ([]string, bool) {
	switch a := v.(type) {
	case string:
		if a == "" {
			return nil, false
		}
		return []string{a}, true
	case []any:
		out := make([]string, 0, len(a))
		for _, x := range a {
			if s, ok := x.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		if len(out) == 0 {
			return nil, false
		}
		return out, true
	default:
		return nil, false
	}
}

// numericDate 读取 NumericDate：接受 json.Number（UseNumber 解码）与 float64
// 兜底（构造侧直接传 map 时）。
func numericDate(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i, true
		}
		f, err := n.Float64()
		if err != nil {
			return 0, false
		}
		return int64(f), true
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	default:
		return 0, false
	}
}

// containsString 线性包含判定（aud 通常 1-3 项）。
func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// verifyKey 取验签公钥：缓存未命中/过期先按普通路径取；失败再强制刷新一次
// （IdP 轮换后旧缓存无新 kid 的容忍窗口）。
func (c *OidcClient) verifyKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	key, err := c.jwksKey(ctx, kid, false)
	if err == nil && key != nil {
		return key, nil
	}
	key, refreshErr := c.jwksKey(ctx, kid, true)
	if refreshErr != nil {
		return nil, refreshErr
	}
	if key == nil {
		return nil, fmt.Errorf("%w: 无 kid %q", ErrJWKS, kid)
	}
	return key, nil
}

// jwksKey 取验签公钥（kid→RSA；TTL 缓存；force=未知 kid 时强制刷新一次——
// IdP 密钥轮换）。非 RSA 键、非法 n/e 静默跳过（同一 JWKS 可混多算法）。
func (c *OidcClient) jwksKey(ctx context.Context, kid string, force bool) (*rsa.PublicKey, error) {
	c.cacheMu.Lock()
	if !force && !c.keysAt.IsZero() && c.now().Sub(c.keysAt) < jwksTTL {
		key := c.keys[kid]
		c.cacheMu.Unlock()
		if key != nil {
			return key, nil
		}
		return nil, fmt.Errorf("%w: 缓存无 kid %q", ErrJWKS, kid)
	}
	c.cacheMu.Unlock()

	doc, err := c.discover(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, doc.JWKSURI, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: 构造请求: %v", ErrJWKS, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJWKS, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: 响应 %d", ErrJWKS, resp.StatusCode)
	}
	var set jwksDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&set); err != nil {
		return nil, fmt.Errorf("%w: 解析: %v", ErrJWKS, err)
	}
	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, ok := rsaPublicKey(k.N, k.E)
		if !ok {
			continue
		}
		keys[k.Kid] = pub
	}
	c.cacheMu.Lock()
	c.keys = keys
	c.keysAt = c.now()
	c.cacheMu.Unlock()

	if key := keys[kid]; key != nil {
		return key, nil
	}
	return nil, fmt.Errorf("%w: 无 kid %q", ErrJWKS, kid)
}

// rsaPublicKey 由 JWK 的 n/e（base64url 大端无符号整数）构造 RSA 公钥。
// n 为空、e 为空/超过 4 字节/小于 3/偶数一律拒绝（畸形键不参与验签）。
func rsaPublicKey(nB64, eB64 string) (*rsa.PublicKey, bool) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil || len(nBytes) == 0 {
		return nil, false
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil || len(eBytes) == 0 || len(eBytes) > 4 {
		return nil, false
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	if e < 3 || e%2 == 0 {
		return nil, false
	}
	n := new(big.Int).SetBytes(nBytes)
	if n.Sign() <= 0 {
		return nil, false
	}
	return &rsa.PublicKey{N: n, E: e}, true
}
