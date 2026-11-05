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
    /// 初始化闸门：**跟着进程（Peer）走**，不跟着 router 走 ——
    /// 同一个 Peer 可能被构建出多个 router（测试、多端口挂载），而"只允许初始化一次"
    /// 是进程级不变量。
    init_gate: tokio::sync::Mutex<()>,
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
        if config.require_signature && config.issuer_public_keys.is_empty() {
            return Err(Error::Config(
                "require_signature = true needs at least one issuer_public_key".into(),
            ));
        }
        if config.clock_skew_seconds < 0 {
            return Err(Error::Config(
                "clock_skew_seconds must not be negative".into(),
            ));
        }
        // 自注册的三件前提必须是**配置期**成立的：
        // 否则要么什么人都能初始化（空 setup code），要么初始化必然失败（缺落点/缺地址）。
        if let Some(init) = &config.init {
            if init.setup_code.trim().is_empty() {
                return Err(Error::Config(
                    "init.setup_code must not be empty: an empty code lets anyone point this \
                     service at their own cred center"
                        .into(),
                ));
            }
            if config.identity.is_none() {
                return Err(Error::Config(
                    "init is enabled but identity paths are missing (nothing to write the \
                     registration materials to)"
                        .into(),
                ));
            }
            if config
                .publish_endpoint
                .as_deref()
                .map(str::trim)
                .unwrap_or("")
                .is_empty()
            {
                return Err(Error::Config(
                    "init is enabled but publish_endpoint is missing: the peer must report the \
                     address cred will dial, and that value comes from the deployment config"
                        .into(),
                ));
            }
            // 空地址上面已经拒了；这里拒「渲染了但没主机名」的占位符（`https://:18802/…`）。
            // 这种地址在初始化页上不会自己暴露：能签出一张签给 `""` 的证书、
            // 也能“注册成功”，到 cred 拨号时才发现握手不过。
            if let Some(endpoint) = config.publish_endpoint.as_deref()
                && crate::init::host_of(endpoint.trim()).is_none()
            {
                return Err(Error::Config(format!(
                    "publish_endpoint {:?} has no usable host: cred dials this address and the \
                     certificate SAN is taken from it, so a placeholder is not acceptable",
                    endpoint.trim()
                )));
            }
            if init.insecure_tls && init.ca_file.is_some() {
                return Err(Error::Config(
                    "init.ca_file and init.insecure_tls are mutually exclusive: pick a trust anchor \
                     or knowingly skip verification, not both"
                        .into(),
                ));
            }
            if let Some(ca_file) = &init.ca_file
                && !ca_file.is_file()
            {
                return Err(Error::Config(format!(
                    "init.ca_file {} does not exist",
                    ca_file.display()
                )));
            }
        }
        // 上限 <= 0 会让凭据一登记就过期；这是配置错，不是运行时问题。
        if let Some((role, seconds)) = config
            .max_ttl_by_role
            .iter()
            .find(|(_, seconds)| **seconds <= 0)
        {
            return Err(Error::Config(format!(
                "max_ttl for role {role:?} must be > 0, got {seconds}"
            )));
        }

        let params = StoreParams {
            known_roles: config.known_roles.clone(),
            max_ttl_by_role: config.max_ttl_by_role.clone(),
            visible_resources: config.visible_resources.clone(),
            clock_skew_seconds: config.clock_skew_seconds,
            require_signature: config.require_signature,
            issuer_public_keys: config.issuer_public_keys.clone(),
        };
        let store = CredentialStore::open(config.store_path.clone(), params)
            .map_err(|err| Error::Store(err.to_string()))?;

        Ok(Arc::new(Self {
            config: Arc::new(config),
            init_gate: tokio::sync::Mutex::new(()),
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

    /// 启动加载时因签名不合格被丢弃的条数（运维应当关注：非 0 意味着磁盘被改过）。
    pub fn rejected_on_load(&self) -> usize {
        self.store.rejected_on_load()
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

    /// 初始化闸门（见字段注释）。
    pub(crate) fn init_gate(&self) -> &tokio::sync::Mutex<()> {
        &self.init_gate
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
