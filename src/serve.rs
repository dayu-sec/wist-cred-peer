//! 起一个**双向认证**的 HTTPS 服务：握手期就把「来的是不是 cred」判掉。
//!
//! 与 `wist-center` ↔ `wist-gwlinkd`、`wist-ingest-ctrl` 的接入口同一形态：
//!
//! | 方向 | 谁证明谁 | 手段 |
//! |---|---|---|
//! | cred → 本服务 | 客户端证书（CA-I 签） | `WebPkiClientVerifier` |
//! | 本服务 → cred | 服务器证书（CA-S 签） | cred 侧的信任锚 |
//!
//! 握手不过就到不了应用层；过了之后只认**已验证的身份**，不读请求里的自述字段。

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use tokio_rustls::TlsAcceptor;
use wist_pki::PeerIdentity;

use crate::error::{Error, Result};
use crate::peer::Peer;

/// 证书材料（通常由 cred 的一次性接入命令落在本机）。
#[derive(Debug, Clone)]
pub struct TlsFiles {
    /// 本服务的服务器证书（CA-S 按本机 CSR 签出）。
    pub cert: PathBuf,
    /// 只在本机的私钥。
    pub key: PathBuf,
    /// 客户端信任锚（CA-I 公开证书）：cred 出示的证书要链到它。
    pub client_ca: PathBuf,
}

/// 起服务，直到进程退出。
///
/// `peer` 是共享状态；路由与摘要表都在里面，多个连接并发处理。
pub async fn serve(peer: Arc<Peer>, listen: SocketAddr, files: TlsFiles) -> Result<()> {
    let client_ca_pem = std::fs::read_to_string(&files.client_ca).map_err(|err| {
        Error::Serve(format!(
            "read client CA {}: {err}",
            files.client_ca.display()
        ))
    })?;
    // 严格模式：**必须**出示客户端证书（`allow_unauthenticated = false`）。
    let config = wist_pki::tls::server_config_mtls(&files.cert, &files.key, &client_ca_pem, false)
        .map_err(Error::Serve)?;

    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|err| Error::Serve(format!("bind {listen}: {err}")))?;
    serve_listener(peer.router(), listener, config).await
}

/// 用同一套 mTLS 握手服务一个**自定义路由**。
///
/// 用在两个场景：示例要额外挂 `/verify`；或者你已经有一个 `Router`，只想借这里的
/// 接入层（客户端证书验链 + 身份注入）。`config` 由 `wist_pki::tls::server_config_mtls` 生成。
pub async fn serve_router(
    app: Router,
    listen: SocketAddr,
    config: rustls::ServerConfig,
) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|err| Error::Serve(format!("bind {listen}: {err}")))?;
    serve_listener(app, listener, config).await
}

/// 等身份材料齐备再起 mTLS 监听（首次注册后**不需要重启**）。
///
/// 初始化页是原子写盘（先 `.<name>.tmp` 再 rename），所以三件都在就是真的完整。
/// 没就绪时**不绑端口**：没有服务器证书就绑上，只会让对端看到一个永远握不上手
/// 的端口（比拒绝连接更难排查）。
pub async fn serve_when_ready(peer: Arc<Peer>, listen: SocketAddr, files: TlsFiles) -> Result<()> {
    if !ready(&files) {
        eprintln!(
            "waiting for identity materials before starting mTLS on {listen}: {} / {} / {}",
            files.cert.display(),
            files.key.display(),
            files.client_ca.display()
        );
    }
    while !ready(&files) {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    eprintln!("identity materials are in place; starting mTLS on {listen}");
    serve(peer, listen, files).await
}

fn ready(files: &TlsFiles) -> bool {
    files.cert.is_file() && files.key.is_file() && files.client_ca.is_file()
}

async fn serve_listener(
    app: Router,
    listener: tokio::net::TcpListener,
    config: rustls::ServerConfig,
) -> Result<()> {
    let acceptor = TlsAcceptor::from(Arc::new(config));

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                // 瞬时错误（EMFILE / ECONNABORTED）不能把整个服务带下来。
                eprintln!("accept failed: {err}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            let stream = match acceptor.accept(stream).await {
                Ok(stream) => stream,
                Err(err) => {
                    // 证书过期、链不对、没出示客户端证书，都会在握手期被拒。
                    eprintln!("tls handshake failed from {peer_addr}: {err}");
                    return;
                }
            };

            let identity = wist_pki::tls::peer_leaf_certificate_der(stream.get_ref().1)
                .and_then(|der| PeerIdentity::from_certificate_der(&der).ok());

            let io = hyper_util::rt::TokioIo::new(stream);
            let service = hyper::service::service_fn(
                move |mut request: hyper::Request<hyper::body::Incoming>| {
                    let app = app.clone();
                    let identity = identity.clone();
                    async move {
                        if let Some(identity) = identity {
                            request.extensions_mut().insert(identity);
                        }
                        tower::ServiceExt::oneshot(app, request).await
                    }
                },
            );

            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                eprintln!("http connection error from {peer_addr}: {err}");
            }
        });
    }
}
