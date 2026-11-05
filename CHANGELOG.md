# Changelog

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
