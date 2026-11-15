// Package oidc 实现 OIDC authorization-code 登录客户端：发现文档、PKCE
// S256、code 交换、ID token 的 RS256/JWKS 验签、nonce 对账与 flow state
// TTL 管理。
//
// 本包只管「与 IdP 的往来」：账号映射、角色/会话签发、登录成功后的前端
// 跳转都是宿主产品决策，不在包内（bianque 的 UserSvc.LoginOidc 是这类
// 宿主的参照实现）。依赖仅标准库（crypto/rsa + encoding/json +
// net/http）：JWKS 解析与 RS256 验签不引入第三方 JWT 库——id_token 的
// 验签面只有「两段 base64url + RSA PKCS#1 v1.5/SHA-256」，自持实现比多
// 一条依赖链更可控，也避免把算法协商面（alg=none/HS* 降级）交给库默认
// 行为。
//
// # 治理口径
//
// Issuer/ClientID/ClientSecret 三要素任一为空 = 整体关闭：[Client.BeginLogin]
// 与 [Client.CompleteLogin] 均返回 [ErrDisabled]，零网络行为。这是产品治理
// 决策（未配置 SSO 的部署不暴露半开的登录面），不是可选项。
//
// # 安全判定（CompleteLogin）
//
//  1. state 单次消费 + FlowTTL：回调先删后验，重放同一 state 直接落空；
//  2. code 交换携带 PKCE verifier（S256 challenge 在 BeginLogin 生成，
//     verifier 32 字节熵）与 client_secret；
//  3. id_token 强制 alg=RS256（拒绝 none/HS* 降级），公钥按 kid 从 JWKS
//     取；缓存内无 kid 时强制刷新一次（IdP 密钥轮换容忍），刷新后仍无该
//     kid 即失败——不会无限拉取；
//  4. iss 精确等于配置 issuer、aud 含 client_id、nonce 与本次 flow 精确
//     对账、exp/nbf 以本包时钟判定；sub 必须非空（OIDC 的账号锚点）。
//
// 发现文档同样校验 issuer 精确匹配（伪造/混包防线），且 authorization/
// token/jwks 三个端点缺一即失败。发现文档与 JWKS 进程内缓存（默认
// 10min/1h）；flow state 缺省为进程内 map（默认 TTL 10min + BeginLogin 时
// 惰性 GC）——单机/粘性代理形态不受影响；无粘性负载均衡的多副本部署注入
// [Config.StateStore] 做跨副本共享（[StateStore] 实现方保证 Take 原子单次
// 消费，如 DB DELETE...RETURNING / Redis GETDEL；[MemoryStateStore] 是进程内
// 共享的可选便利实现），nil = 缺省 map，零行为变化。Client 侧恒以
// CreatedAt+FlowTTL 复核，载体过期策略失效不致放行陈旧 state。
//
// # 用法
//
//	c := oidc.New(oidc.Config{
//		Issuer:       "https://idp.example.com",
//		ClientID:     "console",
//		ClientSecret: "…",
//	})
//	if !c.Enabled() {
//		// 三要素未配齐：SSO 整体关闭
//	}
//	authURL, err := c.BeginLogin(ctx, redirectURI, browserID) // 302 到 IdP
//	// IdP 回调：
//	res, err := c.CompleteLogin(ctx, code, state, redirectURI)
//	// res.Subject / res.Username / res.Anchor / res.Groups / res.Claims
//	// 交给宿主的账号映射与签发面。
package oidc
