# wist-cred-peer

验证方（X）接入 [`wist-cred`](https://github.com/dayu-sec/wist-cred) 的**可复用运行时**。

一个服务要能被 cred 发凭据，需要三件事：握手期双向认证、接收 `register`/`revoke`、
维护自己的摘要表。这三件事在平台里已经有一套成熟口径（`wist-center` ↔ `wist-gwlinkd`、
`wist-ingest-ctrl`），本 crate 把它们抽成库，避免每个服务各写一遍。

## 它管什么

| 能力 | 实现 |
|---|---|
| 双向认证（客户端证书由 CA-I 签，握手期验链） | `serve` / `serve_router` |
| 接收 `register` / `revoke`（授权数据） | `Peer::router` |
| 自己的状态（摘要表、角色/有效期/资源裁剪） | `Peer` + `wist-auth::credential` |
| 应用层信任（只收白名单签发方） | `Config::allow_issuer` |

## 两种接法

**1. 独立起服务**（旁路部署、示例）

```rust
use wist_cred_peer::{Config, Peer, TlsFiles};

let peer = Peer::open(Config::new("wist-ingest", "state/credentials.json").allow_issuer("wist-cred"))?;
wist_cred_peer::serve(peer, "127.0.0.1:19443".parse()?, TlsFiles {
    cert: "/etc/wist/wist-ingest/server.crt".into(),
    key: "/etc/wist/wist-ingest/server.key".into(),
    client_ca: "/etc/wist/wist-ingest/client-ca.pem".into(),
}).await?;
```

**2. 挂进已有服务**（服务自己终止 TLS）

把 `Peer::router()` merge 进去，并在请求上注入 `Extension<wist_pki::PeerIdentity>`
（握手层拿到的客户端身份）。路由本身不认识 TLS。

## 示例：一个真的能跑的服务

不在本仓 —— 它作为一个**独立 crate** 放着，依赖走 crates.io 上已发布的 `wist-cred-peer`，
这才是下游真实的接入形态：

```
wist-cred-stack/dev/peer-example/     # 依赖 wist-cred-peer = "0.1"
```

```sh
cd wist-cred-stack
./dev/svc.sh start peer      # 建系统 → 跑接入命令拿证书 → 起 mTLS 服务（:19455）
./dev/svc.sh peer-check      # 签发 → 推送 → 本地验证 → 撤销 → 再验证
```

它演示的正是本 crate 的全部职责：收 register/revoke、自己的摘要表、双向认证、心跳。

## 契约

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `<base_path>` | `register`：收一条摘要（`revision` 单调，低版本拒） |
| `POST` | `<base_path>/{credential_id}/revoke` | 撤销，幂等；开验签时带 `revoked_at` + `signature` |
| `GET` | `/healthz` | 心跳（cred 每 30s 探一次；含 `rejected_on_load`） |

`base_path` 默认 `/api/v1/internal/credentials`，与 cred 推送地址的尾部一致。

约定：

- 客户端证书由 CA-I 签，握手期验链；应用层只做**身份白名单**（`allowed_issuers`）。
- `audience` 必须等于本服务的名字，否则拒（防跨服务重放）。
- C 提议的角色 / 有效期 / 资源由本服务裁剪（D9），不是照单全收。
- 只存 `sha256` 摘要，明文永不落盘；撤销后重启不会复活。
- **授权记录签名（0.2+）**：`Config::require_signature(true).issuer_public_key_hex("<hex>")`。
  开启后 `register` 拒收无签名 / 验不过的记录，从磁盘加载时丢掉验不过的记录
  （`Peer::rejected_on_load()` 应当写进启动日志）—— 改角色 / 延长有效期 / 清撤销标记
  都会被发现。

## 版本

`version.txt` 是权威版本；`Cargo.toml` 必须与它一致（release 流水线会校验）。
