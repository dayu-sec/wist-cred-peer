//! 登录：把一条访问令牌换成「你是谁、能做什么」。
//!
//! 与 [`crate::Peer::router`] 的区别很重要：
//!
//! | | 谁在用 | 认证方式 | 输入 |
//! |---|---|---|---|
//! | `router()` | cred 推摘要 | mTLS 客户端证书 | 授权记录 |
//! | `login_router()` | **浏览器 / 操作者** | 访问令牌 | 一条 `wcr_…` |
//!
//! 后者之前是缺的：宿主（console / center / ingest）各自在「每个请求都带 Bearer」里
//! 校验令牌，却没有人能把一次校验的结果——身份与角色——交回给界面。于是前端只能
//! 「先发一个真请求试试」，失败了再猜原因。
//!
//! 这里给一个稳定的契约（错误码是**对外契约**，不要改）：
//!
//! | 状态 | code | 含义 |
//! |---|---|---|
//! | 200 | — | `{subject, roles, audience, expires_at, credential_id}` |
//! | 401 | `credential_missing` | 没带令牌 |
//! | 401 | `credential_invalid` | 不认识 / 过期 / 撤销 / audience 不符（**不区分原因**，避免变成令牌枚举接口） |
//! | 403 | `role_required` | 令牌有效，但没给这个宿主要的角色 |
//! | 503 | `credential_store_unavailable` | 摘要表读不了：服务端故障，不是「你的令牌不对」 |

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::Peer;

/// 登录成功的身份视图。**只放界面需要的东西**：不带资源裁剪结果（那是业务决定）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Login {
    pub credential_id: String,
    pub subject: String,
    pub roles: Vec<String>,
    pub audience: String,
    /// Unix 秒。界面自己决定到点之后怎么提示。
    pub expires_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginError {
    /// 没带令牌。
    Missing,
    /// 不认识 / 过期 / 撤销 / audience 不符。
    Invalid,
    /// 令牌有效，但角色不够。
    RoleRequired,
    /// 摘要表读不了（服务端故障）。
    StoreUnavailable,
}

impl LoginError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Missing => "credential_missing",
            Self::Invalid => "credential_invalid",
            Self::RoleRequired => "role_required",
            Self::StoreUnavailable => "credential_store_unavailable",
        }
    }
}

impl Peer {
    /// 校验一条访问令牌，并做**本宿主**的角色闸门。
    ///
    /// `required_roles` 是宿主自己的决定（比如 console 要 `read`）；为空表示只看令牌有效性。
    pub fn login(
        &self,
        token: Option<&str>,
        required_roles: &[String],
    ) -> std::result::Result<Login, LoginError> {
        let token = token.map(str::trim).filter(|value| !value.is_empty());
        let Some(token) = token else {
            return Err(LoginError::Missing);
        };
        let credential = match self.verify(token) {
            Ok(credential) => credential,
            Err(err) => {
                // 摘要表读失败不是「令牌不对」：不能让所有人去重新登录。
                if matches!(err, wist_auth::credential::CredentialError::Store(_)) {
                    log::error!("event=PeerLoginStore code={} {err:?}", err.code());
                    return Err(LoginError::StoreUnavailable);
                }
                // 对外不区分原因（不做令牌枚举接口），日志里留 code 便于排查。
                log::debug!("event=PeerLoginRejected code={}", err.code());
                return Err(LoginError::Invalid);
            }
        };
        if !required_roles.is_empty()
            && !credential
                .roles
                .iter()
                .any(|role| required_roles.iter().any(|required| required == role))
        {
            log::warn!(
                "event=PeerLoginForbidden subject={} credential_id={} roles={:?} required={:?}",
                credential.subject,
                credential.credential_id,
                credential.roles,
                required_roles,
            );
            return Err(LoginError::RoleRequired);
        }
        Ok(Login {
            credential_id: credential.credential_id,
            subject: credential.subject,
            roles: credential.roles,
            audience: credential.audience,
            expires_at: credential.expires_at,
        })
    }
}

/// 挂一个登录端点（`POST <base>`）。宿主自己决定挂在哪（console 是 `/api/login`）。
///
/// 令牌可以放在 JSON body 的 `{"token": "…"}`，也可以放在 `Authorization: Bearer …`；
/// 两边都给时 **body 优先**（表单式登录是主路径，头是“已经拿着令牌，只想确认它是谁”）。
pub fn router(peer: Arc<Peer>, required_roles: Vec<String>) -> Router {
    Router::new()
        .route("/login", post(login))
        .with_state(Arc::new(LoginContext {
            peer,
            required_roles,
        }))
}

struct LoginContext {
    peer: Arc<Peer>,
    required_roles: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct LoginRequest {
    #[serde(default)]
    token: Option<String>,
}

async fn login(
    State(context): State<Arc<LoginContext>>,
    headers: HeaderMap,
    body: Option<Json<LoginRequest>>,
) -> Response {
    let from_body = body
        .as_ref()
        .and_then(|Json(request)| request.token.clone());
    let token = from_body.or_else(|| {
        headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .map(str::to_string)
    });

    match context
        .peer
        .login(token.as_deref(), &context.required_roles)
    {
        Ok(login) => Json(json!({
            "credential_id": login.credential_id,
            "subject": login.subject,
            "roles": login.roles,
            "audience": login.audience,
            "expires_at": login.expires_at,
        }))
        .into_response(),
        Err(error) => {
            let status = match error {
                LoginError::Missing | LoginError::Invalid => StatusCode::UNAUTHORIZED,
                LoginError::RoleRequired => StatusCode::FORBIDDEN,
                LoginError::StoreUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            };
            (
                status,
                Json(json!({
                    "error": {
                        "code": error.code(),
                        "message": match error {
                            LoginError::Missing => "missing access token",
                            LoginError::Invalid => "access token is not valid here",
                            LoginError::RoleRequired => {
                                "access token is valid but does not grant access to this service"
                            }
                            LoginError::StoreUnavailable => {
                                "credential store is unavailable; this is a server-side problem"
                            }
                        },
                    }
                })),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn peer(dir: &std::path::Path) -> Arc<Peer> {
        let config = crate::Config::new("wist-console", dir.join("credentials.json"))
            .known_roles(["read", "admin"])
            .allow_issuer("wist-cred");
        Peer::open(config).expect("peer")
    }

    async fn call(app: Router, body: Option<serde_json::Value>) -> (StatusCode, serde_json::Value) {
        let mut builder = axum::http::Request::builder().method("POST").uri("/login");
        // 没有 body 时**不能**带 `content-type: application/json`：`Json` 提取器看到它就
        // 要求一个合法 JSON，空的会是 400（真实场景是“只带 Bearer 头”的那种）。
        if body.is_some() {
            builder = builder.header("content-type", "application/json");
        }
        let request = builder
            .body(Body::from(
                body.map(|value| value.to_string()).unwrap_or_default(),
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    #[test]
    fn a_missing_token_is_missing_not_invalid() {
        let dir = std::env::temp_dir().join(format!("peer-login-{}", std::process::id()));
        let peer = peer(&dir);
        assert_eq!(peer.login(None, &[]), Err(LoginError::Missing));
        assert_eq!(peer.login(Some("   "), &[]), Err(LoginError::Missing));
        assert_eq!(peer.login(Some("wcr_nope"), &[]), Err(LoginError::Invalid));
    }

    const TOKEN: &str = "wcr_login_test_token";

    /// 走一次真实的推送入口，把一条授权记录放进摘要表。
    ///
    /// 不直接构造 store：登录端点的前提就是“凭证是 **register 进来**的”，
    /// 绕开它测出来的东西不一定是现场的形状。
    async fn register(peer: &Arc<Peer>, roles: &[&str]) {
        use axum::http::Request;
        use tower::ServiceExt;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs() as i64)
            .unwrap_or(0);
        let entry = wist_auth::credential::CredentialEntry {
            credential_id: "cred_login".to_string(),
            digest: format!("sha256:{}", wist_auth::sha256_hex(TOKEN)),
            subject: "ops-zhangsan".to_string(),
            roles: roles.iter().map(|role| role.to_string()).collect(),
            resources: Default::default(),
            audience: "wist-console".to_string(),
            issued_at: now,
            expires_at: now + 3_600,
            revision: 1,
            revoked_at: None,
            signature: None,
        };
        let identity = wist_pki::PeerIdentity {
            id: "wist-cred".to_string(),
            uri: None,
            cn: Some("wist-cred".to_string()),
            fingerprint_sha256: "00".repeat(32),
            serial_hex: "01".to_string(),
            not_before: "2026-01-01T00:00:00Z".to_string(),
            not_after: "2027-01-01T00:00:00Z".to_string(),
        };
        let mut request = Request::builder()
            .method("POST")
            .uri(crate::DEFAULT_BASE_PATH)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&entry).expect("json")))
            .expect("request");
        request.extensions_mut().insert(identity);
        let response = peer.router().oneshot(request).await.expect("register");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_registered_token_logs_in_with_its_identity() {
        let dir = std::env::temp_dir().join(format!("peer-login-ok-{}", std::process::id()));
        let peer = peer(&dir);
        register(&peer, &["read"]).await;

        let login = peer
            .login(Some(TOKEN), &["read".to_string()])
            .expect("login");
        assert_eq!(login.subject, "ops-zhangsan");
        assert_eq!(login.roles, vec!["read".to_string()]);
        assert_eq!(login.audience, "wist-console");
        assert_eq!(login.credential_id, "cred_login");
        assert!(login.expires_at > 0, "expires_at 是 Unix 秒，不是毫秒");

        // 空 `required_roles` = 只看令牌有效性，不看角色。
        assert!(peer.login(Some(TOKEN), &[]).is_ok());
    }

    #[tokio::test]
    async fn a_valid_token_without_the_required_role_is_forbidden() {
        let dir = std::env::temp_dir().join(format!("peer-login-role-{}", std::process::id()));
        let peer = peer(&dir);
        register(&peer, &["read"]).await;

        assert_eq!(
            peer.login(Some(TOKEN), &["admin".to_string()]),
            Err(LoginError::RoleRequired),
            "令牌有效但角色不够 → 403，不是 401"
        );
    }

    #[tokio::test]
    async fn the_endpoint_reports_the_stable_contract() {
        let dir = std::env::temp_dir().join(format!("peer-login-http-{}", std::process::id()));
        let app = router(peer(&dir), vec!["read".to_string()]);

        let (status, body) = call(app.clone(), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body["error"]["code"], "credential_missing");

        let (status, body) = call(app, Some(json!({ "token": "wcr_nope" }))).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body["error"]["code"], "credential_invalid");
    }
}
