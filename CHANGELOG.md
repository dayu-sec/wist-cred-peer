# Changelog

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
