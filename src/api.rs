//! HTTP 面：接收 cred 推来的 `register` / `revoke`，外加一个健康检查。
//!
//! 路由本身**不认识 TLS**：它只读请求上的 `Extension<PeerIdentity>`（握手层注入的身份）。
//! 这样既能独立起服务（[`crate::serve`]），也能挂进已有的 axum 服务。

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use wist_auth::credential::{CredentialEntry, CredentialError};
use wist_pki::PeerIdentity;

use crate::peer::{AuthDenial, Peer};

/// 撤销请求体。
///
/// - `revision`：比本地记录小就算过期（D12）；
/// - `revoked_at`：签发方给的撤销时间；缺省时用本机时间（兼容旧版 cred）；
/// - `signature`：签发方对“已撤销的那条记录”的签名（`require_signature` 时必填）。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeRequest {
    pub revision: u64,
    #[serde(default)]
    pub revoked_at: Option<i64>,
    #[serde(default)]
    pub signature: Option<String>,
}

/// 联调用的校验请求体。**生产不要挂这个路由**（见 [`Peer::router_with_verify`]）。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyRequest {
    pub token: String,
}

pub(crate) fn router(peer: Arc<Peer>, with_verify_endpoint: bool) -> Router {
    let base = peer.config().base_path.clone();
    let mut app = Router::new()
        .route(&base, post(register))
        .route(&format!("{base}/{{credential_id}}/revoke"), post(revoke))
        .route("/healthz", get(healthz));
    if with_verify_endpoint {
        app = app.route("/verify", post(verify));
    }
    app.with_state(peer)
}

/// `POST <base>`：收一条摘要。
async fn register(
    State(peer): State<Arc<Peer>>,
    identity: Option<Extension<PeerIdentity>>,
    Json(entry): Json<CredentialEntry>,
) -> Response {
    if let Err(denial) = peer.authorize(identity.as_ref().map(|Extension(id)| id)) {
        return denial.into_response();
    }
    if entry.audience != peer.config().audience {
        return api_error(
            StatusCode::BAD_REQUEST,
            "audience_mismatch",
            format!(
                "this service is {:?}, the credential targets {:?}",
                peer.config().audience,
                entry.audience
            ),
        );
    }

    match peer.store().register(entry) {
        Ok(effective) => (
            StatusCode::OK,
            Json(json!({ "accepted": true, "effective": effective })),
        )
            .into_response(),
        Err(error) => credential_error(error),
    }
}

/// `POST <base>/{credential_id}/revoke`：撤销。幂等；`revision` 不前进会被拒。
async fn revoke(
    State(peer): State<Arc<Peer>>,
    identity: Option<Extension<PeerIdentity>>,
    Path(credential_id): Path<String>,
    Json(body): Json<RevokeRequest>,
) -> Response {
    if let Err(denial) = peer.authorize(identity.as_ref().map(|Extension(id)| id)) {
        return denial.into_response();
    }

    let revoked_at = body.revoked_at.unwrap_or_else(now_secs);
    match peer
        .store()
        .revoke(&credential_id, body.revision, revoked_at, body.signature)
    {
        Ok(Some(updated)) => (
            StatusCode::OK,
            Json(json!({
                "credential_id": updated.credential_id,
                "revoked_at": updated.revoked_at,
                "revision": updated.revision,
            })),
        )
            .into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "credential_not_found",
            "no such credential in this store",
        ),
        Err(error) => credential_error(error),
    }
}

/// `GET /healthz`：cred 的心跳探这里（不是 `/`，避免和业务首页混在一起）。
async fn healthz(State(peer): State<Arc<Peer>>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "audience": peer.config().audience,
        "registered": peer.registered(),
        "rejected_on_load": peer.rejected_on_load(),
    }))
}

/// `POST /verify`：**联调用**。把 token 交给本服务判一次，返回同样的 `VerifiedCredential`。
async fn verify(State(peer): State<Arc<Peer>>, Json(body): Json<VerifyRequest>) -> Response {
    match peer.verify(&body.token) {
        Ok(credential) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "credential": {
                    "credential_id": credential.credential_id,
                    "subject": credential.subject,
                    "audience": credential.audience,
                    "roles": credential.roles,
                    "resources": credential.resources,
                    "expires_at": credential.expires_at,
                }
            })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "ok": false,
                "code": error.code(),
                "message": error.to_string(),
            })),
        )
            .into_response(),
    }
}

fn credential_error(error: CredentialError) -> Response {
    let status = StatusCode::from_u16(error.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    api_error(status, error.code(), error.to_string())
}

fn api_error(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    (
        status,
        Json(json!({ "error": { "code": code, "message": message.into() } })),
    )
        .into_response()
}

impl IntoResponse for AuthDenial {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::UNAUTHORIZED);
        api_error(status, self.code, self.message)
    }
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use serde_json::json;
    use tower::ServiceExt;

    use super::*;
    use crate::Config;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0);
            let path = std::env::temp_dir().join(format!(
                "wist-cred-peer-{tag}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("temp dir");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const TOKEN: &str = "wcr_peer_test_token";

    fn peer(dir: &TempDir) -> Arc<Peer> {
        let config = Config::new("wist-ingest", dir.0.join("credentials.json"))
            .allow_issuer("wist-cred")
            .known_roles(["read", "investigation:run"])
            .max_ttl("read", 86_400);
        Peer::open(config).expect("open peer")
    }

    fn identity(id: &str) -> PeerIdentity {
        PeerIdentity {
            id: id.to_string(),
            uri: None,
            cn: Some(id.to_string()),
            fingerprint_sha256: "00".repeat(32),
            serial_hex: "01".to_string(),
            not_before: "2026-01-01T00:00:00Z".to_string(),
            not_after: "2027-01-01T00:00:00Z".to_string(),
        }
    }

    fn entry(revision: u64) -> CredentialEntry {
        let now = now_secs();
        CredentialEntry {
            credential_id: "cred_1".to_string(),
            digest: format!("sha256:{}", wist_auth::sha256_hex(TOKEN)),
            subject: "ci-nightly".to_string(),
            roles: vec!["read".to_string(), "unknown:role".to_string()],
            resources: Default::default(),
            audience: "wist-ingest".to_string(),
            issued_at: now,
            expires_at: now + 3_600,
            revision,
            revoked_at: None,
            signature: None,
        }
    }

    async fn post(
        app: Router,
        uri: &str,
        identity: Option<PeerIdentity>,
        body: Value,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        if let Some(identity) = identity {
            request.extensions_mut().insert(identity);
        }
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, value)
    }

    #[tokio::test]
    async fn register_requires_a_client_certificate() {
        let dir = TempDir::new("no-cert");
        let app = peer(&dir).router_with_verify();
        let (status, body) = post(app, "/api/v1/internal/credentials", None, json!(entry(1))).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body["error"]["code"], "client_certificate_required");
    }

    #[tokio::test]
    async fn register_rejects_an_unlisted_issuer() {
        let dir = TempDir::new("bad-issuer");
        let app = peer(&dir).router_with_verify();
        let (status, body) = post(
            app,
            "/api/v1/internal/credentials",
            Some(identity("someone-else")),
            json!(entry(1)),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"]["code"], "issuer_not_allowed");
    }

    #[tokio::test]
    async fn register_rejects_another_audience() {
        // 防跨服务重放：给别的服务用的凭据，这里不收。
        let dir = TempDir::new("audience");
        let app = peer(&dir).router_with_verify();
        let mut body = entry(1);
        body.audience = "wist-center".to_string();
        let (status, rejected) = post(
            app,
            "/api/v1/internal/credentials",
            Some(identity("wist-cred")),
            json!(body),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{rejected}");
        assert_eq!(rejected["error"]["code"], "audience_mismatch");
    }

    #[tokio::test]
    async fn register_then_verify_then_revoke() {
        let dir = TempDir::new("closed-loop");
        let peer = peer(&dir);
        let app = peer.router_with_verify();

        let (status, accepted) = post(
            app.clone(),
            "/api/v1/internal/credentials",
            Some(identity("wist-cred")),
            json!(entry(1)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{accepted}");
        assert_eq!(accepted["accepted"], true);
        // 不认识的角色被裁掉（D9），不是照单全收。
        assert_eq!(accepted["effective"]["roles"], json!(["read"]));

        let (status, verified) =
            post(app.clone(), "/verify", None, json!({ "token": TOKEN })).await;
        assert_eq!(status, StatusCode::OK, "{verified}");
        assert_eq!(verified["credential"]["subject"], "ci-nightly");

        let (status, revoked) = post(
            app.clone(),
            "/api/v1/internal/credentials/cred_1/revoke",
            Some(identity("wist-cred")),
            json!({ "revision": 2 }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{revoked}");
        assert_eq!(revoked["revision"], 2);

        let (status, rejected) = post(app, "/verify", None, json!({ "token": TOKEN })).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{rejected}");
        assert_eq!(rejected["code"], "token_revoked");
    }

    #[tokio::test]
    async fn a_stale_revision_cannot_revive_a_revoked_credential() {
        let dir = TempDir::new("stale");
        let peer = peer(&dir);
        let app = peer.router_with_verify();
        post(
            app.clone(),
            "/api/v1/internal/credentials",
            Some(identity("wist-cred")),
            json!(entry(1)),
        )
        .await;
        post(
            app.clone(),
            "/api/v1/internal/credentials/cred_1/revoke",
            Some(identity("wist-cred")),
            json!({ "revision": 2 }),
        )
        .await;

        // 迟到的 register（revision 1）不许把撤销覆盖回去。
        let (status, rejected) = post(
            app.clone(),
            "/api/v1/internal/credentials",
            Some(identity("wist-cred")),
            json!(entry(1)),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{rejected}");
        assert_eq!(rejected["error"]["code"], "credential_revision_stale");

        let (status, body) = post(app, "/verify", None, json!({ "token": TOKEN })).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body["code"], "token_revoked");
    }

    #[tokio::test]
    async fn healthz_reports_state_without_auth() {
        // 心跳是 mTLS 的，但路由本身不做应用层鉴权：握手层已经保证了来者是谁。
        let dir = TempDir::new("health");
        let app = peer(&dir).router();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["status"], "ok");
        assert_eq!(body["audience"], "wist-ingest");
        assert_eq!(body["registered"], 0);
        assert_eq!(body["rejected_on_load"], 0);
    }

    // ── 签名（Ed25519）：授权内容被改过就拒收 ───────────────────────────

    use ring::rand::SystemRandom;
    use ring::signature::Ed25519KeyPair;
    use wist_auth::signing::{public_key_from_pkcs8, sign};

    fn keypair() -> (Vec<u8>, Vec<u8>) {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("keypair");
        let public = public_key_from_pkcs8(pkcs8.as_ref()).expect("public");
        (pkcs8.as_ref().to_vec(), public)
    }

    fn signed_peer(dir: &TempDir, public: Vec<u8>) -> Arc<Peer> {
        let config = Config::new("wist-ingest", dir.0.join("credentials.json"))
            .allow_issuer("wist-cred")
            .known_roles(["read", "investigation:run"])
            .require_signature(true)
            .issuer_public_key(public);
        Peer::open(config).expect("open signed peer")
    }

    fn signed_entry(revision: u64, private_key: &[u8]) -> CredentialEntry {
        let mut entry = entry(revision);
        entry.signature = Some(sign(&entry, private_key).expect("sign"));
        entry
    }

    #[test]
    fn requiring_signatures_without_a_public_key_fails_closed() {
        let dir = TempDir::new("sig-nokey");
        let config =
            Config::new("wist-ingest", dir.0.join("credentials.json")).require_signature(true);
        let err = Peer::open(config).err().expect("must reject");
        assert!(
            err.to_string().contains("issuer_public_key"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn invalid_ttl_or_negative_skew_is_rejected() {
        let dir = TempDir::new("badcfg");
        let zero_ttl = Config::new("wist-ingest", dir.0.join("a.json")).max_ttl("read", 0);
        assert!(Peer::open(zero_ttl).is_err());

        let mut negative_skew = Config::new("wist-ingest", dir.0.join("b.json"));
        negative_skew.clock_skew_seconds = -1;
        assert!(Peer::open(negative_skew).is_err());
    }

    #[tokio::test]
    async fn unsigned_register_is_rejected_when_signature_is_required() {
        let dir = TempDir::new("sig-missing");
        let (_, public) = keypair();
        let app = signed_peer(&dir, public).router_with_verify();
        let (status, body) = post(
            app,
            "/api/v1/internal/credentials",
            Some(identity("wist-cred")),
            json!(entry(1)),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"]["code"], "credential_signature_invalid");
    }

    #[tokio::test]
    async fn signed_register_is_accepted_and_revoke_needs_a_signature_too() {
        let dir = TempDir::new("sig-ok");
        let (private, public) = keypair();
        let app = signed_peer(&dir, public).router_with_verify();

        let (status, body) = post(
            app.clone(),
            "/api/v1/internal/credentials",
            Some(identity("wist-cred")),
            json!(signed_entry(1, &private)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        // 撤销没带签名：拒。
        let (status, body) = post(
            app.clone(),
            "/api/v1/internal/credentials/cred_1/revoke",
            Some(identity("wist-cred")),
            json!({ "revision": 2 }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"]["code"], "credential_signature_invalid");

        // 对“已撤销”的记录重新签名：通过。
        let mut revoked = signed_entry(2, &private);
        revoked.revoked_at = Some(now_secs());
        revoked.signature = Some(sign(&revoked, &private).expect("sign"));
        let (status, body) = post(
            app,
            "/api/v1/internal/credentials/cred_1/revoke",
            Some(identity("wist-cred")),
            json!({
                "revision": 2,
                "revoked_at": revoked.revoked_at,
                "signature": revoked.signature,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["revision"], 2);
    }
}
