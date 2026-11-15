// Package oidc 提供 OIDC 登录客户端（authorization code + PKCE S256 +
// RS256/JWKS 验签）。与 JWT 中间件面解耦：本包只管「IdP 往来」——发现
// 文档、JWKS、code 交换、ID token 校验与 flow state 生命周期；账号映射、
// 本地签发、会话建立都留宿主。
//
// # 治理口径
//
// 三要素（Issuer/ClientID/ClientSecret）任一为空 = 整体关闭（零行为）：
// [OidcClient.Enabled] 为 false，[OidcClient.BeginLogin]/
// [OidcClient.CompleteLogin]/[OidcClient.VerifyIDToken] 一律返回
// [ErrOidcDisabled]，不拨网、不生成 state。
//
// # 零第三方依赖的取舍
//
// 本仓是零依赖模块（go.mod 只有 module + go 指令），因此没有引入 JWT 库，
// 而是手写最小 JOSE 解析：只支持 **RS256**（RSASSA-PKCS1-v1_5 + SHA-256），
// 显式拒绝 none/HS256/ES256 等一切其他 alg——不存在算法协商面，也就没有
// alg confusion 的降级路径。JWE、嵌套 JWT、JWKS 的 x5c 链、多算法轮换不在
// 支持面内；需要这些能力时应在宿主边界另行适配，而不是放宽本包校验。
//
// # 登录流
//
//  1. [OidcClient.BeginLogin] 惰性拉取发现文档（.well-known/openid-configuration，
//     issuer 精确匹配），生成 state/nonce/PKCE verifier，把流转态留在进程内
//     map（TTL 默认 10 分钟 + 惰性 GC），返回 IdP 授权页 URL（S256 challenge）。
//     redirect_uri 由调用方按请求现场推导，binding 是不透明关联值（例如匿名
//     会话 id），不经 IdP URL 外泄。
//  2. [OidcClient.CompleteLogin] 按 state **一次性消费**流转态（重放直接落空），
//     用 code + verifier + 机密客户端凭据（client_secret_post）换 token，再验
//     ID token：RS256 强制、iss 精确、aud 含 client_id、exp 必须存在且未过期、
//     nbf/iat 可选校验、nonce 精确对账、sub 非空。JWKS 未知 kid 会**强制刷新
//     一次**（IdP 密钥轮换容忍），仍未知则失败。
//  3. [OidcClient.VerifyIDToken] 是 2 的验签面单出口，也可供其他入口复用。
//
// # 缓存与单副本边界
//
// 发现文档缓存 10 分钟、JWKS 缓存 1 小时（均进程内）；JWKS 未知 kid 时绕过
// 缓存强刷一次。flow state 是**进程内**的：多副本部署时回调必须落回同一副本
// （粘性代理）或由宿主外置共享 state；本包不提供跨副本 flow 存储。
//
// # 端点与策略注入
//
// issuer/client 凭据/scopes 由宿主注入；发现文档给授权/token/JWKS 端点。
// HTTPClient 可由宿主替换（代理、mTLS、测试），默认 10s 超时；`Now` 与
// `FlowTTL` 仅用于时钟注入与测试。ID token 的 claims 以 map 形式返回，
// username/groups 等业务映射由宿主按自己的词表解释。
package oidc
