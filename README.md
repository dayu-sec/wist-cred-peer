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

## 自注册与初始化（P0）

服务第一次启动时**没有任何材料**，无法起 mTLS 推送监听。`init` 模块把这套流程收在库里：

| 状态 | 判据 | 行为 |
|---|---|---|
| `uninitialized` | 没有 `server.crt` / `key` / `client-ca.pem` | 挂 `init_router(peer)`，它提供 `GET/POST /__init` |
| `initialized` | 三件齐全 | `/__init` → `409`；宿主照常起 `serve(...)` |

两条**互相独立**的授权，缺一条都能被打穿：

- `[init].setup_code` 保护**本服务**：否则谁都能把它指向自己的 cred 中心、再给自己签 token；
- 一次性券（`wot_…`，cred 页面签发）保护 **cred**：否则谁都能注册成认证系统。

```rust
use wist_cred_peer::{Config, IdentityFiles, InitConfig};

let config = Config::new("wist-console", "/var/lib/wist-console/credentials.json")
    // 收数地址来自部署配置（栈按端口映射渲染），不由命令行参数给。
    .publish_endpoint("https://console.internal:18802/api/v1/internal/credentials")
    .identity(IdentityFiles {
        cert: "/cred/server.crt".into(),
        key: "/cred/server.key".into(),
        client_ca: "/cred/client-ca.pem".into(),
    })
    .init(InitConfig {
        setup_code: std::env::var("CRED_PEER_SETUP_CODE")?,
        cred_url: None,          // 预置后页面上不再让操作者输
        insecure_tls: false,     // 自签入口的首次注册才打开（P1 换 ca_file）
    });
```

`POST /__init` 一次做完：常数时间校验 setup code → `GET <cred>/enroll/<券>/bundle` →
本机生成密钥与 CSR → `POST <cred>/enroll/<券>/certificate` → 校验 SAN 与密钥配对 →
原子落盘。**任何一步失败都不落材料**（不给自己造一个“半初始化”的现场）。

P0 **不热加载**：写完材料后提示重启，由宿主重新起 mTLS 监听。

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
