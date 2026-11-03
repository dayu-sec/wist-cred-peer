//! 验证方的**自身状态**：摘要表 + 裁剪策略 + 「这个调用方是不是 cred」。

use std::sync::Arc;

use wist_auth::credential::{CredentialError, CredentialStore, StoreParams, VerifiedCredential};
use wist_pki::PeerIdentity;

use crate::config::Config;
use crate::error::{Error, Result};

/// 一个验证方（X）的运行时。
///
/// 它是**进程内的单例**：`Peer::open` 之后用 `Arc<Peer>` 共享，摘要表自带读写锁，
/// 多个请求并发登记/校验是安全的。
pub struct Peer {
    config: Arc<Config>,
    store: CredentialStore,
}

impl Peer {
    /// 打开（或新建）摘要表。
    ///
    /// 落盘文件只存 `sha256` 摘要；重启后照常可用，不需要 cred 重推。
    pub fn open(config: Config) -> Result<Arc<Self>> {
        if config.audience.trim().is_empty() {
            return Err(Error::Config("audience must not be empty".into()));
        }
        if config.base_path.trim().is_empty() || !config.base_path.starts_with('/') {
            return Err(Error::Config(
                "base_path must be an absolute path such as /api/v1/internal/credentials".into(),
            ));
        }
        if config.allowed_issuers.is_empty() {
            // 不拦启动：本地调试可能先起服务再补配置。但推不进来，日志里会看到 403。
        }

        let params = StoreParams {
            known_roles: config.known_roles.clone(),
            max_ttl_by_role: config.max_ttl_by_role.clone(),
            visible_resources: config.visible_resources.clone(),
            clock_skew_seconds: config.clock_skew_seconds,
        };
        let store = CredentialStore::open(config.store_path.clone(), params)
            .map_err(|err| Error::Store(err.to_string()))?;

        Ok(Arc::new(Self {
            config: Arc::new(config),
            store,
        }))
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// 当前登记了几条（给健康检查 / 运维看）。
    pub fn registered(&self) -> usize {
        self.store.entries().len()
    }

    /// axum 路由：`POST {base}`、`POST {base}/{id}/revoke`、`GET /healthz`。
    ///
    /// 挂进已有服务时，记得在请求上注入 `Extension<PeerIdentity>`。
    pub fn router(self: &Arc<Self>) -> axum::Router {
        crate::api::router(self.clone(), false)
    }

    /// 多一个 `POST /verify`（`{token}` → 判定结果）。**只给示例/联调用**：
    /// 生产里 token 不应该交给对端服务做「额外」校验。
    pub fn router_with_verify(self: &Arc<Self>) -> axum::Router {
        crate::api::router(self.clone(), true)
    }

    pub(crate) fn store(&self) -> &CredentialStore {
        &self.store
    }

    /// 本地校验一条 token。`audience` 用本服务的名字，不需要调用方再传。
    pub fn verify(&self, token: &str) -> std::result::Result<VerifiedCredential, CredentialError> {
        self.store.verify(token, &self.config.audience)
    }

    /// 应用层信任：握手期已由 CA-I 验过链，这里只做**身份白名单**。
    ///
    /// 返回 `Err(code)` 时调用方直接映射成 401/403。
    pub(crate) fn authorize(
        &self,
        identity: Option<&PeerIdentity>,
    ) -> std::result::Result<(), AuthDenial> {
        let Some(identity) = identity else {
            return Err(AuthDenial {
                status: 401,
                code: "client_certificate_required",
                message: "this endpoint requires mutual TLS: present a client certificate",
            });
        };
        if !self
            .config
            .allowed_issuers
            .iter()
            .any(|allowed| allowed == &identity.id)
        {
            return Err(AuthDenial {
                status: 403,
                code: "issuer_not_allowed",
                message: "the client certificate is not an allowed credential issuer",
            });
        }
        Ok(())
    }
}

/// 拒绝原因（对外只给稳定的 code，不泄露白名单内容）。
pub(crate) struct AuthDenial {
    pub status: u16,
    pub code: &'static str,
    pub message: &'static str,
}
