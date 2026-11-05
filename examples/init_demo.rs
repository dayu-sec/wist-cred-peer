//! 自注册的最小宿主（P0 验证用，不随产品发布）。
//!
//! 两种形态，按**材料是否齐全**自己切：
//!
//! - 未初始化：在 `WIST_PEER_HTTP` 上暴露 `/__init`（初始化页）与 `/healthz`；
//!   提交成功后写材料、提示重启。
//! - 已初始化：在 `[publish].endpoint` 的端口上起 **mTLS 推送监听**（`wist_cred_peer::serve`），
//!   cred 的心跳与推送都打到这里。
//!
//! 用法（在 cred 页面签一张券之后）：
//!
//! ```sh
//! WIST_PEER_AUDIENCE=wist-demo \
//! WIST_PEER_STATE=/tmp/wist-demo \
//! WIST_PEER_ENDPOINT=https://127.0.0.1:19499/api/v1/internal/credentials \
//! WIST_PEER_SETUP_CODE=crp_demo_setup \
//! WIST_PEER_CRED_URL=https://127.0.0.1:4444 \
//! cargo run --example init_demo
//! ```
//!
//! 然后：
//!
//! ```sh
//! curl -s -X POST http://127.0.0.1:18900/__init \
//!   -H 'content-type: application/json' \
//!   -d '{"setup_code":"crp_demo_setup","ticket":"wot_…"}'
//! ```

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;
use wist_cred_peer::{Config, IdentityFiles, InitConfig, InitState, Peer, TlsFiles};

fn env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let audience = env("WIST_PEER_AUDIENCE").unwrap_or_else(|| "wist-demo".to_string());
    let state_dir: PathBuf = env("WIST_PEER_STATE")
        .unwrap_or_else(|| "/tmp/wist-cred-peer-demo".to_string())
        .into();
    std::fs::create_dir_all(&state_dir)?;

    let endpoint = env("WIST_PEER_ENDPOINT")
        .ok_or("WIST_PEER_ENDPOINT is required (the address cred dials)")?;
    let setup_code = env("WIST_PEER_SETUP_CODE").ok_or("WIST_PEER_SETUP_CODE is required")?;
    let roles: Vec<String> = env("WIST_PEER_ROLES")
        .unwrap_or_else(|| "read".to_string())
        .split(',')
        .map(|role| role.trim().to_string())
        .filter(|role| !role.is_empty())
        .collect();
    let http_addr: SocketAddr = env("WIST_PEER_HTTP")
        .unwrap_or_else(|| "127.0.0.1:18900".to_string())
        .parse()?;

    let identity = IdentityFiles {
        cert: state_dir.join("server.crt"),
        key: state_dir.join("server.key"),
        client_ca: state_dir.join("client-ca.pem"),
    };

    let mut config = Config::new(audience.clone(), state_dir.join("credentials.json"))
        .publish_endpoint(endpoint.clone())
        .identity(identity.clone())
        .init(InitConfig {
            setup_code,
            cred_url: env("WIST_PEER_CRED_URL"),
            insecure_tls: env("WIST_PEER_INSECURE_TLS").as_deref() != Some("0"),
        })
        .allow_issuer("wist-cred")
        .known_roles(roles);

    // 已初始化时把签发方公钥也装上（与 cred.toml 的 require_signature 同口径）。
    if let Ok(pub_hex) = std::fs::read_to_string(state_dir.join("issuer-signing.pub")) {
        config = config
            .require_signature(true)
            .issuer_public_key_hex(pub_hex.trim())?;
    }

    let peer = Peer::open(config)?;

    if wist_cred_peer::init_state(peer.config()) == InitState::Initialized {
        let addr = listen_addr_for(&endpoint)?;
        println!("已初始化：在 {addr} 上起 mTLS 推送监听（{endpoint}）");
        return wist_cred_peer::serve(
            peer,
            addr,
            TlsFiles {
                cert: identity.cert,
                key: identity.key,
                client_ca: identity.client_ca,
            },
        )
        .await
        .map_err(Into::into);
    }

    let for_health = peer.clone();
    let app = wist_cred_peer::init_router(peer).route(
        "/healthz",
        get(move || {
            let peer: Arc<Peer> = for_health.clone();
            async move {
                Json(json!({
                    "status": "uninitialized",
                    "audience": peer.config().audience,
                    "endpoint": peer.config().publish_endpoint,
                }))
            }
        }),
    );

    println!("未初始化：初始化页 http://{http_addr}/__init");
    let listener = tokio::net::TcpListener::bind(http_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// 从 `<publish>.endpoint` 取端口，绑在 `0.0.0.0`（demo 里不做地址推导）。
fn listen_addr_for(endpoint: &str) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let rest = endpoint
        .strip_prefix("https://")
        .ok_or("endpoint must be https://")?;
    let authority: String = rest
        .chars()
        .take_while(|character| !matches!(character, '/' | '?' | '#'))
        .collect();
    let port = authority
        .rsplit_once(':')
        .map(|(_, port)| port)
        .ok_or("endpoint must carry an explicit port")?;
    Ok(format!("0.0.0.0:{port}").parse()?)
}

// 让 `Router` 的类型推导有落点（axum 0.8 需要显式标注过 state 形态）。
#[allow(dead_code)]
fn _assert_router(_: Router) {}
