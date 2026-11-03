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
        }
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
}
