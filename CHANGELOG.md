# Changelog

## [0.5.0] - 2026-11-05

### 新增：登录端点（把访问令牌换成身份 + 角色）

验证方（X）之前只有「接收推送」和「本地校验 token」两件事，**没有面向操作者的登录入口**：
宿主只能在每个请求里自己比对 Bearer，界面上就只能“先发个真请求试试”，失败再按状态码猜原因。

- `Peer::login(token, required_roles) -> Result<Login, LoginError>`：校验令牌 + **本宿主的
  角色闸门**；`Login` 给出 `{credential_id, subject, roles, audience, expires_at}`（秒）；
- `login_router(peer, required_roles)`：一个现成的 `POST /login`，令牌放 body
  `{"token":"…"}` 或 `Authorization: Bearer …`（两边都给时 body 优先）；
- 错误码是**对外契约**：401 `credential_missing` / `credential_invalid`、
  403 `role_required`、503 `credential_store_unavailable`；
- 口径与推送侧一致：不区分“不认识 / 过期 / 撤销 / audience 不符”（避免变成令牌枚举接口，
  具体原因只进日志）；摘要表读不了是 503 而不是 401（别让人白去重新登录）。

宿主需要显式挂它（`nest`/`merge` 到自己的路径），`router()` 的行为不变。

用例 32 → 36（成功路径、角色不足、缺失/无效、HTTP 契约）。

> 依赖新增 `log`（库里用 `log` 记账，落到哪由宿主决定）。

## [0.4.1] - 2026-11-05

### 修复

- **注册客户端不再跟随重定向**（`redirect(Policy::none())`）：一次性券写在
  `/enroll/{券}/…` 的 URL 里，跟一个 302 就等于把券交给了重定向目标 ——
  入口少/多一个斜杠、`http→https` 都会发生。3xx 现在报 `cred_redirected`，
  并提示去检查入口地址，而不是含糊地报成“cred 拒绝”让人去查券。
- 初始化页成功文案区分两种情形：首次接入无需重启（`serve_when_ready` 自己起监听）；
  **运行中**删掉材料后重新注册则必须重启，否则跑的是启动时加载的旧证书。

用例 31 → 32。

## [0.4.0] - 2026-11-05

### 新增：信任锚、入口证书指纹、材料齐备即起监听（P1）

P0 让对端自己报地址；P1 要回答的是“我报给的到底是谁”。三件事一个主题：
**别让“注册成功”变成一句无从核对的话。**

- `InitConfig` 新增 `ca_file`：入口自签时的**信任锚**（PEM）。与 `insecure_tls` 互斥，
  缺文件 / 同时配都在**加载期**拒 —— 不再留给运行期一个安静的坑。
- 调 cred 的客户端开 `tls_info`：`/__init` 的成功响应里多一个
  `cred_certificate_sha256`（注册时实际观察到的入口证书指纹）。没有信任锚的部署
  （`insecure_tls = true`）必须把它和 `openssl s_client … -fingerprint -sha256` 对一遍：
  否则“注册成功”只说明连到了**某个人**。
- `serve_when_ready(peer, listen, files)`：三件材料齐了就自己起 mTLS，
  **首次注册后不需要重启进程**。材料没齐时不先绑端口 —— 绑上只会让对端看到一个永远
  握不上手的端口，比拒绝连接更难排查。响应里的 `restart_required` 随之变成 `false`。

### 变更（跟行为有关的硬约束）

- `publish_endpoint` 必须能取出主机名：`https://:18802/…` 这种未渲染的占位符现在
  **拒启动**。证书 SAN 与 cred 拨号地址都来自它，占位符能签出证书、注册也“成功”，
  坏在 cred 那侧握手。
- 初始化页手填的 `host` 必须等于 `publish_endpoint` 的主机名（`host_mismatch`），
  不再允许两者分叉。
- 「连不上 cred」的错误带完整 source 链；证书不被信任时直接说该配 `ca_file`
  还是确知跳过（`invalid peer certificate: UnknownIssuer` 原来只埋在链里）。

### 测试

26 → 31：真 TLS stub（CA 签的入口证书）验「配了锚就验过」「没锚被拒且提示 ca_file」
「响应里的指纹与叶子证书 DER 对得上」，以及 `serve_when_ready` 材料出现前不监听、
出现后自己起来。

> 升级注意：`InitConfig` / `Config` 是公开结构体，本次新增了字段。用构造器的不受影响；
> 用结构体字面量构造的需要补 `ca_file` —— 这是 0.3 → 0.4 的原因。

## [0.3.0] - 2026-11-05

### 新增：自注册与初始化（未初始化时只暴露 `/__init`）

收数地址是**对端的部署事实**（端口映射、反代、DNS），cred 那边抄不对，命令行参数又不可信。
现在由服务自己在首次启动时报上来，但必须同时具备两个**独立**的授权：

- `[init].setup_code` 保护**本服务**：否则谁都能把它指向自己的 cred 中心、再给自己签 token；
- 一次性券（`wot_…`，cred 页面签发）保护 **cred**：否则谁都能注册成认证系统。

API：

- `Config` 新增 `publish_endpoint` / `init(InitConfig)` / `identity(IdentityFiles)`；
- `InitState` + `init_state(config)` + `init_router(peer)`：
  `GET /__init`（JSON / 自包含 HTML）、`POST /__init`（一次提交完成注册）；
- POST 顺序：常数时间校验 setup code → `GET <cred>/enroll/<券>/bundle` →
  本机生成密钥与 CSR → `POST <cred>/enroll/<券>/certificate` →
  校验 SAN 与私钥配对 → **原子落盘**；任何一步失败都不落材料；
- `examples/init_demo.rs`：最小宿主（未初始化跑初始化页，初始化后跑 mTLS 推送监听）。

三处刻意的硬约束：

- **配置期就拒**：空 setup code、开了 init 却没 identity 路径、或没 publish endpoint；
- **并发只允许一次**：闸门挂在 `Peer` 上，两个提交不会各换一张证书；
- **不热加载**：写完材料提示重启，由宿主重新起 mTLS 监听。

> 升级注意：`Config` 是公开结构体，本次新增了字段。用 `Config::new(...)` + 构造器的不受影响；
> 用结构体字面量构造的需要补字段 —— 这是 0.2 → 0.3 的原因。

## [0.2.0] - 2026-11-03

### Added（授权记录验签）

- `Config` 新增 `require_signature` / `issuer_public_keys`，以及构造器
  `require_signature(bool)` / `issuer_public_key(bytes)` / `issuer_public_key_hex(text)`。
  开启后 `register` 缺签名或验不过返回 `400 credential_signature_invalid`；
  从磁盘加载时验不过的记录直接丢弃。
- `GET /healthz` 新增 `rejected_on_load`（启动时因签名不合格/malformed 被丢弃的条数）。
- `Peer::rejected_on_load()`，调用方应写进启动日志。
- 配置校验：`require_signature = true` 但没有公钥、`max_ttl <= 0`、`clock_skew_seconds < 0`
  都在启动期拒绝（fail-closed）。

### Changed

- 依赖 `wist-auth` **0.3**（签名契约）。
- `revoke` 请求体新增可选 `revoked_at` / `signature`：`require_signature` 时两者必填；
  旧版 cred 只发 `revision` 时仍可用（但开了验签会被拒）。
- **升级顺序**：先升所有验证方（本版，`require_signature = false`），再升 `wist-cred`，
  最后打开 `require_signature`。原因：0.1 的 `RevokeRequest` 是 `deny_unknown_fields`，
  新版 cred 发的新字段会被旧验证方拒掉。

### Changed（仓内）

- 示例 `peer-service` 移出本仓：它现在是一个**独立 crate**（`wist-cred-stack/dev/peer-example/`），
  依赖走 crates.io 上已发布的 `wist-cred-peer` —— 这样示例演示的就是下游真实的接入形态，
  而不是“库里自己跑自己”。

## [0.1.0] - 2026-11-03

首个版本：把「验证方（X）接入 `wist-cred`」的实现抽成库，并给一个能直接跑起来的示例服务。

### 新增

- `Peer`：验证方运行时 —— 摘要表、裁剪策略（角色 / 有效期 / 资源）、本地校验。
  只存 `sha256` 摘要，撤销后重启不会复活。
- `Peer::router`：`POST <base>`（register）、`POST <base>/{id}/revoke`、`GET /healthz`
  三个口，挂进任意 axum 服务即可；路由本身不认识 TLS，只认 `Extension<PeerIdentity>`。
- `serve` / `serve_router`：起一个双向认证的 HTTPS —— 客户端证书必须链到给定 CA，
  握手期就拒掉不认识的来者；应用层再按 `allowed_issuers` 做身份白名单。
- 示例 `peer-service`：一条命令起真实服务，打印要填回 `wist-cred` 的收数地址；
  带 `--verify-endpoint` 时额外挂 `POST /verify`，方便联调时直接拿 token 试。
