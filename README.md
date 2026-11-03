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

```sh
cargo run --example peer-service -- \
  --listen 127.0.0.1:19443 \
  --dir /etc/wist/wist-ingest \        # cred 的一次性接入命令落的材料
  --store ./state/credentials.json \
  --audience wist-ingest \
  --issuer wist-cred \
  --known-roles read,investigation:run \
  --verify-endpoint                    # 仅联调：多挂一个 POST /verify
```

起来之后把它打印的地址填回 cred 的收数地址即可。`--verify-endpoint` 那个路由
**只用于联调**，生产别开（凭据的判定应该发生在业务请求里，不是让对端服务代验）。

## 契约

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `<base_path>` | `register`：收一条摘要（`revision` 单调，低版本拒） |
| `POST` | `<base_path>/{credential_id}/revoke` | 撤销，幂等 |
| `GET` | `/healthz` | 心跳（cred 每 30s 探一次） |

`base_path` 默认 `/api/v1/internal/credentials`，与 cred 推送地址的尾部一致。

约定：

- 客户端证书由 CA-I 签，握手期验链；应用层只做**身份白名单**（`allowed_issuers`）。
- `audience` 必须等于本服务的名字，否则拒（防跨服务重放）。
- C 提议的角色 / 有效期 / 资源由本服务裁剪（D9），不是照单全收。
- 只存 `sha256` 摘要，明文永不落盘；撤销后重启不会复活。

## 版本

`version.txt` 是权威版本；`Cargo.toml` 必须与它一致（release 流水线会校验）。
