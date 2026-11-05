//! 接入配置：本服务叫什么、信任哪个签发方、能验什么。

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::DEFAULT_BASE_PATH;

/// 一个验证方（X）的接入配置。
///
/// 全部是**本服务自己的决定**，不是 cred 传过来的：cred 只能提议，这里是上限。
#[derive(Debug, Clone)]
pub struct Config {
    /// 本服务的名字，也就是 cred 侧的认证系统名；凭据的 `audience` 必须等于它。
    pub audience: String,
    /// 摘要表落盘位置（只存 sha256）。父目录不存在会自动建。
    pub store_path: PathBuf,
    /// 接收路径前缀。默认 [`DEFAULT_BASE_PATH`]，与 cred 的 `[push]` 地址尾部一致。
    pub base_path: String,
    /// 允许的签发方身份（客户端证书的 `id`，通常就是 `wist-cred`）。**空 = 拒绝一切**。
    pub allowed_issuers: Vec<String>,
    /// 本服务认识的角色。不在其中的角色会被丢掉；**空 = 全部丢掉**（fail-closed）。
    pub known_roles: Vec<String>,
    /// 角色 → 有效期上限（秒）。命中多条取最小。
    pub max_ttl_by_role: BTreeMap<String, i64>,
    /// 本服务可见的资源。`None` = 不裁剪（留给业务层判）；`Some` = 取交集。
    pub visible_resources: Option<BTreeMap<String, Vec<String>>>,
    /// 时钟偏移（秒），默认 60。
    pub clock_skew_seconds: i64,
    /// 是否要求每条授权记录都带签发方签名。
    ///
    /// - `register`：缺签名 / 验不过 → 拒收；
    /// - 从磁盘加载：验不过的记录直接丢弃。
    pub require_signature: bool,
    /// 信任的签发方 Ed25519 公钥（裸 32 字节）。空 = 一把都不信（fail-closed）。
    pub issuer_public_keys: Vec<Vec<u8>>,
    /// 本服务在 cred 眼里的收数地址（部署事实）。
    ///
    /// 由**部署配置**渲染（如栈里的 `CREDENTIALS_BIND_IP/HOST_PORT`），不由命令行参数给。
    pub publish_endpoint: Option<String>,
    /// 未初始化时接受的注册配置；`None` = 本服务不支持自注册（不挂 `/__init`）。
    pub init: Option<InitConfig>,
    /// 注册产物落点。`None` = 不参与初始化流程。
    pub identity: Option<IdentityFiles>,
}

/// 自注册（初始化页）的配置。
#[derive(Debug, Clone)]
pub struct InitConfig {
    /// 初始化页必须提交的这个值：保护**对端** —— 否则任何人都能把服务指向自己的 cred 中心。
    pub setup_code: String,
    /// cred 的注册入口（`https://…:4444`）。预置后页面不再让操作者输入。
    pub cred_url: Option<String>,
    /// 接受自签入口的证书。只在首次注册时用；开了会大声告警（P1 换 `ca_file`）。
    pub insecure_tls: bool,
}

/// 注册产物：服务器证书、私钥、客户端信任锚。
#[derive(Debug, Clone)]
pub struct IdentityFiles {
    pub cert: PathBuf,
    pub key: PathBuf,
    pub client_ca: PathBuf,
}

impl Config {
    /// 最小可用配置：一个名字 + 一个落盘位置。
    ///
    /// `allowed_issuers` 留空 —— 也就是说**默认什么都收不了**，必须显式放行签发方。
    pub fn new(audience: impl Into<String>, store_path: impl Into<PathBuf>) -> Self {
        Self {
            audience: audience.into(),
            store_path: store_path.into(),
            base_path: DEFAULT_BASE_PATH.to_string(),
            allowed_issuers: Vec::new(),
            known_roles: Vec::new(),
            max_ttl_by_role: BTreeMap::new(),
            visible_resources: None,
            clock_skew_seconds: 60,
            require_signature: false,
            issuer_public_keys: Vec::new(),
            publish_endpoint: None,
            init: None,
            identity: None,
        }
    }

    /// 本机在 cred 眼里的收数地址（部署配置渲染）。
    pub fn publish_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.publish_endpoint = Some(endpoint.into());
        self
    }

    /// 启用自注册：未初始化时暴露 `/__init`。
    pub fn init(mut self, init: InitConfig) -> Self {
        self.init = Some(init);
        self
    }

    /// 注册产物的落点（证书 / 私钥 / 客户端信任锚）。
    pub fn identity(mut self, files: IdentityFiles) -> Self {
        self.identity = Some(files);
        self
    }

    /// 放行签发方（客户端证书的身份）。不调用它就谁也推不进来。
    pub fn allow_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.allowed_issuers.push(issuer.into());
        self
    }

    /// 声明本服务能验的角色；同时把它们登记进 `known_roles`。
    pub fn known_roles<I, S>(mut self, roles: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.known_roles = roles.into_iter().map(Into::into).collect();
        self
    }

    /// 给某个角色加有效期上限（秒）。
    pub fn max_ttl(mut self, role: impl Into<String>, seconds: i64) -> Self {
        self.max_ttl_by_role.insert(role.into(), seconds);
        self
    }

    /// 改接收路径前缀（默认 `/api/v1/internal/credentials`）。
    pub fn base_path(mut self, path: impl Into<String>) -> Self {
        self.base_path = path.into();
        self
    }

    /// 要求每条授权记录带签发方签名。开了就必须至少放行一把公钥。
    pub fn require_signature(mut self, require: bool) -> Self {
        self.require_signature = require;
        self
    }

    /// 信任一把签发方公钥（裸 32 字节 Ed25519）。可多次调用以支持轮换期。
    pub fn issuer_public_key(mut self, key: impl Into<Vec<u8>>) -> Self {
        self.issuer_public_keys.push(key.into());
        self
    }

    /// 从 32 字节 hex 文本加一把公钥（`require_signature` 时最常用）。
    pub fn issuer_public_key_hex(mut self, text: &str) -> crate::Result<Self> {
        let key = wist_auth::signing::parse_public_key_hex(text).map_err(crate::Error::Config)?;
        self.issuer_public_keys.push(key);
        Ok(self)
    }
}
