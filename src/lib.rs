//! 验证方（X）接入 `wist-cred` 的**可复用运行时**。
//!
//! 一个 X 要能被 cred 发凭据，需要三件事，本 crate 把它们收在一起：
//!
//! | 能力 | 谁提供 |
//! |---|---|
//! | 握手期双向认证（客户端证书由 CA-I 签） | [`serve`] + `wist-pki` |
//! | 接收 `register` / `revoke`（授权数据） | [`Peer::router`] |
//! | 自己的状态（摘要表、裁剪策略、有效期） | [`Peer`] + `wist-auth::credential` |
//!
//! ## 两种接法
//!
//! **独立起服务**（示例、旁路部署）：
//!
//! ```no_run
//! use std::net::SocketAddr;
//! use wist_cred_peer::{Config, Peer, TlsFiles};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let peer = Peer::open(Config::new("wist-ingest", "state/credentials.json").allow_issuer("wist-cred"))?;
//! wist_cred_peer::serve(
//!     peer,
//!     "127.0.0.1:19443".parse::<SocketAddr>()?,
//!     TlsFiles {
//!         cert: "/etc/wist/wist-ingest/server.crt".into(),
//!         key: "/etc/wist/wist-ingest/server.key".into(),
//!         client_ca: "/etc/wist/wist-ingest/client-ca.pem".into(),
//!     },
//! )
//! .await?;
//! # Ok(())
//! # }
//! ```
//!
//! **挂进已有服务**（服务自己终止 TLS）：把 [`Peer::router`] `merge` 进去，并在请求上
//! 注入 `Extension<wist_pki::PeerIdentity>`（握手层拿到的客户端身份）。路由本身不认识
//! TLS，只认这个扩展。
//!
//! ## 边界的口径
//!
//! - 握手不过就到不了这里；过了之后**只认已验证的身份**，不读请求里的自述字段。
//! - `audience` 必须等于本服务的名字，否则拒（防跨服务重放）。
//! - `revision` 单调：低 revision 的 `register` 被拒，撤销后无法复活。
//! - C 提议的角色 / 有效期 / 资源由本服务**裁剪**（D9），不是照单全收。

mod api;
mod config;
mod error;
mod init;
mod peer;
mod serve;

pub use config::{Config, IdentityFiles, InitConfig};
pub use error::{Error, Result};
pub use init::{InitState, router as init_router, state as init_state};
pub use peer::Peer;
pub use serve::{TlsFiles, serve, serve_router, serve_when_ready};

/// 契约里默认的接收路径（`register` = `POST <base>`，`revoke` = `POST <base>/{id}/revoke`）。
pub const DEFAULT_BASE_PATH: &str = "/api/v1/internal/credentials";
