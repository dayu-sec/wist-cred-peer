//! 自注册与初始化：**未初始化**的服务只暴露 `/__init`。
//!
//! 解决的是一件具体的事：收数地址是**对端的部署事实**（端口映射、反代、DNS），
//! cred 的操作者抄不对，命令行参数又不可信。所以让对端自己报——
//! 但报之前必须先证明两件事，缺一件都能被打穿：
//!
//! | 问的问题 | 用什么回答 |
//! |---|---|
//! | 对端凭什么相信它填的 cred 地址？ | **setup code**（部署生成的秘密） |
//! | cred 凭什么相信这个对端？ | **一次性券**（`wot_…`，由 cred 页面签发） |
//!
//! 前者保护本服务（否则谁都能把它指向自己的 cred 中心、再给自己签 token），
//! 后者保护 cred（否则谁都能注册成认证系统、让 cred 把授权记录推给自己）。
//!
//! ## 状态机
//!
//! - `uninitialized`：没有 `cert` / `key` / `client_ca` 三件材料 → 只放行 `/__init`；
//! - `initialized`：三件齐全 → `/__init` 返回 `409`。
//!
//! 不做「半可用」：没有服务器证书，mTLS 监听本来也起不来。
//!
//! ## 一次提交做完什么
//!
//! 1. 常数时间校验 `setup_code`；不匹配直接 403，**不落任何状态**；
//! 2. `GET <cred>/enroll/<券>/bundle` 取公开材料（client CA + 签发方公钥）；
//! 3. 本机生成密钥与 CSR（**私钥永不出本机**）；
//! 4. `POST <cred>/enroll/<券>/certificate` 换服务器证书；
//! 5. 校验返回物（SAN 含主机名 + 私钥与证书配对），原子落盘；
//! 6. 响应里 `restart_required: false`：宿主用 [`crate::serve_when_ready`] 等材料齐了
//!    自己起 mTLS 监听，**不需要重启进程**。
//!
//! ## 传送门上的两个硬证据
//!
//! - `[init].ca_file`：入口自签时的**信任锚**。配了就不再靠人眼；
//! - 响应里的 `cred_certificate_sha256`：注册时观察到的入口证书指纹。
//!   没有信任锚的部署（`insecure_tls = true`）必须把它和
//!   `openssl s_client -connect … -showcerts </dev/null | openssl x509 -fingerprint -sha256`
//!   的输出对一遍 —— 否则“注册成功”只说明连到了**某个人**。

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::Peer;
use crate::config::{Config, IdentityFiles, InitConfig};

/// 初始化状态：只由**材料是否齐全**决定，不落额外标记（文件本身就是事实）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitState {
    Uninitialized,
    Initialized,
}

impl InitState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Uninitialized => "uninitialized",
            Self::Initialized => "initialized",
        }
    }
}

/// 从配置推导初始化状态。
///
/// **没有配 `identity` 的服务视为“已就绪”**：它们不支持自注册，行为与以前完全一致。
pub fn state(config: &Config) -> InitState {
    match &config.identity {
        None => InitState::Initialized,
        Some(files) => {
            if files.cert.is_file() && files.key.is_file() && files.client_ca.is_file() {
                InitState::Initialized
            } else {
                InitState::Uninitialized
            }
        }
    }
}

/// 未初始化时暴露的路由：`GET /__init`（状态 + 页面）、`POST /__init`（提交）。
///
/// 挂到服务的**明文 HTTP 口**上（不是 mTLS 推送口 —— 那里还没有证书可出示）。
pub fn router(peer: Arc<Peer>) -> Router {
    Router::new()
        .route("/__init", get(show_init).post(submit_init))
        .with_state(peer)
}

async fn show_init(State(peer): State<Arc<Peer>>, headers: HeaderMap) -> Response {
    let config = peer.config();
    let state = state(config);
    let preset_url = config
        .init
        .as_ref()
        .and_then(|init| init.cred_url.clone())
        .unwrap_or_default();
    let wants_html = headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.contains("text/html"));

    if wants_html {
        return Html(page(state, &config.audience, &preset_url)).into_response();
    }
    Json(json!({
        "state": state.as_str(),
        "audience": config.audience,
        "endpoint": config.publish_endpoint,
        "cred_url": if preset_url.is_empty() { Value::Null } else { Value::String(preset_url) },
        "roles": config.known_roles,
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmitInit {
    /// 部署生成的秘密：证明“我有权给这台机器指定 cred 地址”。
    setup_code: String,
    /// cred 注册入口；`[init].cred_url` 预置时可以不给。
    #[serde(default)]
    cred_url: Option<String>,
    /// cred 页面签发的一次性券。
    ticket: String,
    /// 证书 SAN；不给就从收数地址推导（两者必须一致，否则握手必然失败）。
    #[serde(default)]
    host: Option<String>,
    /// 上报给 cred 的角色；不给就用本服务已声明的 `known_roles`。
    #[serde(default)]
    roles: Option<Vec<String>>,
}

async fn submit_init(State(peer): State<Arc<Peer>>, Json(body): Json<SubmitInit>) -> Response {
    // 先拿门再读状态：否则两个并发请求会同时看到 uninitialized，
    // 各自换一张证书，后写的那份把前一份的私钥盖掉。
    let _guard = peer.init_gate().lock().await;
    let config = peer.config();

    if state(config) == InitState::Initialized {
        return fail(
            StatusCode::CONFLICT,
            "already_initialized",
            "this service is already initialized; delete the identity materials to re-enroll",
        );
    }
    let Some(init) = config.init.as_ref() else {
        return fail(
            StatusCode::NOT_FOUND,
            "init_disabled",
            "this deployment does not enable self-registration",
        );
    };

    // 常数时间比较：这条是“谁能决定信任锚”的闸门，不能给计时侧信道。
    if !setup_code_matches(&init.setup_code, &body.setup_code) {
        return fail(
            StatusCode::FORBIDDEN,
            "setup_code_invalid",
            "invalid setup code",
        );
    }

    let Some(ticket) = cleaned(Some(body.ticket.as_str())) else {
        return fail(
            StatusCode::BAD_REQUEST,
            "ticket_required",
            "an onboarding ticket (wot_…) is required",
        );
    };
    let cred_url = cleaned(body.cred_url.as_deref()).or_else(|| {
        init.cred_url
            .as_deref()
            .and_then(|value| cleaned(Some(value)))
    });
    let Some(cred_url) = cred_url else {
        return fail(
            StatusCode::BAD_REQUEST,
            "cred_url_required",
            "the cred registration URL is required",
        );
    };
    let Some(endpoint) = cleaned(config.publish_endpoint.as_deref()) else {
        return fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "publish_endpoint_missing",
            "this deployment has no [publish] endpoint configured; \
             the ingest address must be rendered by the stack, not typed here",
        );
    };

    // 证书 SAN 只能等于 cred 以后拨号的那个主机名：两者不一致时，证书能签出来、
    // 注册也能“成功”，但 cred 一拨号就握手失败 —— 失败点在**对端**，最难查。
    // 所以这里不留“随便填”的自由：地址里没有主机名就直接拒。
    let Some(endpoint_host) = host_of(endpoint) else {
        return fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "publish_endpoint_invalid",
            "[publish].endpoint has no host (e.g. https://:18802/…): the deployment must \
             render a real address — both the certificate SAN and cred's dial target come from it",
        );
    };
    if let Some(given) = cleaned(body.host.as_deref())
        && given != endpoint_host
    {
        return fail(
            StatusCode::BAD_REQUEST,
            "host_mismatch",
            format!(
                "host {given:?} does not match the host of [publish].endpoint ({endpoint_host:?}); \
                 cred dials the endpoint, so the certificate must be issued for that name"
            ),
        );
    }
    let host = endpoint_host;

    let roles = body.roles.unwrap_or_else(|| config.known_roles.clone());

    match enroll(
        init,
        config.identity.as_ref(),
        cred_url,
        ticket,
        &host,
        endpoint,
        &roles,
    )
    .await
    {
        Ok(registered) => Json(json!({
            "state": "initialized",
            "peer": config.audience,
            "host": host,
            "endpoint": endpoint,
            "written": registered.written,
            // 让操作者拿这个和 `openssl s_client … -fingerprint -sha256` 对一下。
            "cred_certificate_sha256": registered.cred_certificate_sha256,
            "restart_required": false,
        }))
        .into_response(),
        Err(error) => fail(error.status(), error.code, error.message),
    }
}

struct EnrollError {
    code: &'static str,
    message: String,
    /// 该回给调用方的状态码：内部错不能伪装成「上游拒绝」。
    status: StatusCode,
}

impl EnrollError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            status: StatusCode::BAD_GATEWAY,
        }
    }

    fn internal(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            status: StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn status(&self) -> StatusCode {
        self.status
    }
}

/// 注册成功的结果。
struct Registered {
    written: Vec<String>,
    /// 注册时观察到的入口证书指纹（SHA-256 hex）：让操作者拿去比对。
    cred_certificate_sha256: Option<String>,
}

/// 取 bundle → 生成密钥与 CSR → 换证书 → 校验 → 落盘。
async fn enroll(
    init: &InitConfig,
    identity: Option<&IdentityFiles>,
    cred_url: &str,
    ticket: &str,
    host: &str,
    endpoint: &str,
    roles: &[String],
) -> Result<Registered, EnrollError> {
    let Some(files) = identity else {
        return Err(EnrollError::internal(
            "identity_paths_missing",
            "this deployment has no [identity] paths configured",
        ));
    };
    let base = cred_url.trim_end_matches('/');

    // ① 公开材料（券授权、不消耗）。
    let bundle_response = client(init)?
        .get(format!("{base}/enroll/{ticket}/bundle"))
        .send()
        .await
        .map_err(|err| unreachable(init, err))?;
    let status = bundle_response.status();
    if status.is_redirection() {
        return Err(redirected(status, &init_url(cred_url, ticket, "bundle")));
    }
    // 在消费 body 之前取：这是“我到底连到了谁”的唯一硬证据。
    let cred_certificate_sha256 = peer_certificate_fingerprint(&bundle_response);
    let body = bundle_response
        .text()
        .await
        .map_err(|err| EnrollError::new("cred_unreachable", format!("bundle: {err}")))?;
    // 入口挂了时返回的是 nginx 的 HTML，不是 JSON：按文本读再试解析，
    // 否则会报一个误导人的 `cred_unreachable`。
    let bundle: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    if !status.is_success() {
        return Err(upstream_error("bundle_rejected", status, &bundle, &body));
    }
    let client_ca_pem = bundle
        .get("client_ca_pem")
        .and_then(Value::as_str)
        .ok_or_else(|| EnrollError::new("bundle_malformed", "bundle has no client_ca_pem"))?
        .to_string();
    let issuer_pub = bundle
        .get("issuer_signing_pub")
        .and_then(Value::as_str)
        .map(ToString::to_string);

    // ② 本机密钥 + CSR（私钥永不上送）。
    let key = rcgen::KeyPair::generate()
        .map_err(|err| EnrollError::new("keygen_failed", format!("{err}")))?;
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, host.to_string());
    let csr_pem = params
        .serialize_request(&key)
        .map_err(|err| EnrollError::new("csr_failed", format!("{err}")))?
        .pem()
        .map_err(|err| EnrollError::new("csr_failed", format!("{err}")))?;

    // ③ 交 CSR 换证书。
    let enroll_response = client(init)?
        .post(format!("{base}/enroll/{ticket}/certificate"))
        .header(header::ACCEPT, "application/x-pem-file")
        .json(&json!({
            "certificate_signing_request": csr_pem,
            "host": host,
            "endpoint": endpoint,
            "roles": roles,
        }))
        .send()
        .await
        .map_err(|err| unreachable(init, err))?;
    let status = enroll_response.status();
    if status.is_redirection() {
        return Err(redirected(
            status,
            &init_url(cred_url, ticket, "certificate"),
        ));
    }
    let body = enroll_response
        .text()
        .await
        .map_err(|err| EnrollError::new("cred_unreachable", format!("{err}")))?;
    if !status.is_success() {
        return Err(upstream_error_text("enroll_rejected", status, &body));
    }
    let cert_pem = body;
    if !cert_pem.contains("BEGIN CERTIFICATE") {
        return Err(EnrollError::new(
            "certificate_malformed",
            "cred returned something that is not a certificate",
        ));
    }

    // ④ 校验：证书 SAN 必须含本机名字（否则 cred 连过来时握手必然失败）。
    if !certificate_covers(&cert_pem, host) {
        return Err(EnrollError::new(
            "certificate_san_mismatch",
            format!("the issued certificate does not cover {host:?}"),
        ));
    }

    // ⑤ 原子落盘：先写临时文件再改名，避免半套材料被当成“已初始化”。
    let written = [
        files.cert.clone(),
        files.key.clone(),
        files.client_ca.clone(),
    ];
    write_atomic(&files.cert, cert_pem.as_bytes(), 0o644)?;
    write_atomic(&files.key, key.serialize_pem().as_bytes(), 0o600)?;
    write_atomic(&files.client_ca, client_ca_pem.as_bytes(), 0o644)?;
    if let Some(pub_hex) = issuer_pub.filter(|value| !value.is_empty()) {
        let path = files.client_ca.with_file_name("issuer-signing.pub");
        write_atomic(&path, pub_hex.as_bytes(), 0o644)?;
    }

    // ⑥ 私钥与证书必须配对：rustls 加载时就会校验，不配对这里就报。
    wist_pki::tls::install_crypto_provider();
    if let Err(error) = wist_pki::tls::server_config(&files.cert, &files.key) {
        let _ = std::fs::remove_file(&files.cert);
        let _ = std::fs::remove_file(&files.key);
        return Err(EnrollError::new(
            "certificate_key_mismatch",
            format!("the issued certificate does not match the local key: {error}"),
        ));
    }

    Ok(Registered {
        written: written
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        cred_certificate_sha256,
    })
}

/// 入口证书的 SHA-256（小写 hex）：让操作者能把它和 `openssl s_client` 的输出对上。
fn peer_certificate_fingerprint(response: &reqwest::Response) -> Option<String> {
    let der = response
        .extensions()
        .get::<reqwest::tls::TlsInfo>()?
        .peer_certificate()?;
    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    let mut hex = String::with_capacity(64);
    for byte in digest.as_ref() {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    Some(hex)
}

/// 「连不上 cred」不能只给一句 reqwest 原文：入口自签 + 没配信任锚是最常见的现场，
/// 而它的报错（`invalid peer certificate: UnknownIssuer`）藏在 source 链里，也不会告诉你该配什么。
fn unreachable(init: &InitConfig, err: reqwest::Error) -> EnrollError {
    let mut message = err.to_string();
    let mut source = std::error::Error::source(&err);
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    // 只有「确实是证书不认」时才提信任锚：连接拒绝 / DNS 错不该被指到这里。
    let certificate_problem = message.to_lowercase().contains("certificate");
    if certificate_problem && init.ca_file.is_none() && !init.insecure_tls {
        message.push_str(
            " —— 本部署没有给入口配信任锚（[init].ca_file）。入口是自签证书时把它的 CA 放进 ca_file；\
             只有在明确要跳过校验时才用 insecure_tls（然后用响应里的指纹人工核对）",
        );
    }
    EnrollError::new("cred_unreachable", message)
}

fn client(init: &InitConfig) -> Result<reqwest::Client, EnrollError> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        // **不跟随重定向**：券在 URL 里，跟一个 302 就等于把一次性券交给了重定向目标
        // （入口配错、多一个斜杠就可能发生）。宁可失败，也不能静默转手。
        .redirect(reqwest::redirect::Policy::none())
        // 拿得到对端证书才能把指纹摆给操作者核对。
        .tls_info(true);
    if let Some(ca_file) = &init.ca_file {
        let pem = std::fs::read(ca_file).map_err(|err| {
            EnrollError::internal(
                "ca_file_unreadable",
                format!("{}: {err}", ca_file.display()),
            )
        })?;
        let cert = reqwest::Certificate::from_pem(&pem).map_err(|err| {
            EnrollError::internal("ca_file_invalid", format!("{}: {err}", ca_file.display()))
        })?;
        builder = builder.add_root_certificate(cert);
    }
    builder
        // 入口通常是自签证书。只有**没配信任锚**时才能显式打开；
        // 开了就必须把返回的指纹拿去和人手上的实例核对。
        .danger_accept_invalid_certs(init.insecure_tls && init.ca_file.is_none())
        .build()
        .map_err(|err| EnrollError::new("client_failed", format!("{err}")))
}

/// 注册客户端**不跟随重定向**：3xx 必须说清楚“为什么不跟”，而不是报成“cred 拒绝”。
fn redirected(status: StatusCode, url: &str) -> EnrollError {
    EnrollError::new(
        "cred_redirected",
        format!(
            "cred answered {status} for {url}: the enrollment client does not follow redirects \
             (the one-time ticket is in the URL — a redirect would hand it to whatever host it \
             points at). Check the cred entry address (scheme / host / trailing slash)"
        ),
    )
}

/// 只给错误消息用：把券留在里面才好定位，但绝不写进日志。
fn init_url(cred_url: &str, ticket: &str, tail: &str) -> String {
    format!("{}/enroll/{ticket}/{tail}", cred_url.trim_end_matches('/'))
}

fn upstream_error(code: &'static str, status: StatusCode, body: &Value, raw: &str) -> EnrollError {
    let upstream = body
        .get("error")
        .and_then(|error| error.get("code"))
        .and_then(Value::as_str);
    match upstream {
        Some(upstream) => EnrollError::new(code, format!("cred refused ({status}): {upstream}")),
        None => upstream_error_text(code, status, raw),
    }
}

fn upstream_error_text(code: &'static str, status: StatusCode, body: &str) -> EnrollError {
    // 按字符截断：响应体可能是中文（cred 的错误消息），按字节切会直接 panic。
    let detail: String = body.trim().chars().take(300).collect();
    EnrollError::new(code, format!("cred refused ({status}): {detail}"))
}

/// 证书是否覆盖这个名字（DNS SAN 或 CN —— cred 把第一个 SAN 同时写进 CN）。
fn certificate_covers(cert_pem: &str, host: &str) -> bool {
    let Ok(der) = wist_pki::inspect::first_certificate_der(cert_pem) else {
        return false;
    };
    let Ok((_, certificate)) = X509Certificate::from_der(&der) else {
        return false;
    };
    let Ok(Some(names)) = certificate.subject_alternative_name() else {
        return certificate.subject().to_string().contains(host);
    };
    names.value.general_names.iter().any(|name| match name {
        x509_parser::extensions::GeneralName::DNSName(dns) => *dns == host,
        _ => false,
    })
}

fn write_atomic(path: &Path, contents: &[u8], mode: u32) -> Result<(), EnrollError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|err| {
            EnrollError::internal("write_failed", format!("{}: {err}", parent.display()))
        })?;
    }
    // 临时文件名带上原文件名：`server.crt` 与 `server.key` 的 `with_extension` 都叫 `server.tmp`，
    // 一旦两个写入交叠（或失败留下残骸），就会把另一份材料蓋掉。
    let name = path
        .file_name()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| "identity".to_string());
    let tmp = path.with_file_name(format!(".{name}.tmp"));
    std::fs::write(&tmp, contents).map_err(|err| {
        EnrollError::internal("write_failed", format!("{}: {err}", tmp.display()))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)).map_err(|err| {
            EnrollError::internal("write_failed", format!("{}: {err}", tmp.display()))
        })?;
    }
    std::fs::rename(&tmp, path)
        .map_err(|err| EnrollError::new("write_failed", format!("{}: {err}", path.display())))
}

/// 常数时间比较（长度不同直接 false —— 口令长度不是秘密，部署时固定）。
fn setup_code_matches(expected: &str, supplied: &str) -> bool {
    let expected = expected.as_bytes();
    let supplied = supplied.as_bytes();
    if expected.len() != supplied.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in expected.iter().zip(supplied) {
        diff |= left ^ right;
    }
    diff == 0
}

fn cleaned(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

/// 从收数地址里取主机名：`https://host:port/path` → `host`（IPv6 字面量去括号）。
///
/// `None` = 地址不成形：没有 `https://`（明文注册等于把 setup code 与一次性券摆到大街上）、
/// 没有主机名（`https://:18802/…` 这种占位符没渲染）、或端口空。
pub(crate) fn host_of(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://")?;
    let authority: String = rest
        .chars()
        .take_while(|character| !matches!(character, '/' | '?' | '#'))
        .collect();
    // IPv6 字面量必须先按括号取，再谈端口：`[::1]` 按 ':' 切会得到 `[:`。
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (inside, after) = rest.split_once(']')?;
        (inside, after.strip_prefix(':'))
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority.as_str(), None),
        }
    };
    let host = host.trim();
    if host.is_empty() || port.is_some_and(|port| port.is_empty()) {
        return None;
    }
    Some(host.to_string())
}

fn fail(status: StatusCode, code: &'static str, message: impl Into<String>) -> Response {
    let mut response = (
        status,
        Json(json!({ "error": { "code": code, "message": message.into() } })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// 初始化页的内联脚本（**不是** format 字符串：里边的花括号原样保留）。
const INIT_SCRIPT: &str = r#"<script>
document.getElementById('f').addEventListener('submit', async (event) => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target).entries());
  for (const key of ['cred_url', 'host']) if (!data[key]) delete data[key];
  const out = document.getElementById('out');
  out.textContent = '注册中…';
  const response = await fetch('/__init', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(data),
  });
  out.textContent = await response.text();
  if (response.ok) out.textContent += '\n\n完成：材料已落盘，收数监听会自动起来（无需重启）。\n若你是在服务**运行中**删掉材料后重新接入的，请重启本服务 —— 已加载的旧证书不会自行替换。\n核对 cred_certificate_sha256 与入口证书指纹一致再离开本页。';
});
</script>"#;

fn page(state: InitState, audience: &str, preset_url: &str) -> String {
    let body = if state == InitState::Initialized {
        format!(
            "<h1>{audience} 已初始化</h1><p>要重新接入，删掉身份材料（server.crt / server.key / client-ca.pem）后重启。</p>"
        )
    } else {
        let cred_field = if preset_url.is_empty() {
            r#"<label>cred 注册入口<input name="cred_url" placeholder="https://cred.example.com:4444" required></label>"#
                .to_string()
        } else {
            format!(
                r#"<label>cred 注册入口<input name="cred_url" value="{preset_url}" readonly></label>"#
            )
        };
        format!(
            r#"<h1>{audience} 初始化</h1>
<p>两样都要：<b>setup code</b> 证明你有权指定 cred 地址，<b>接入券</b>证明 cred 允许这个系统接入。</p>
<form id="f">
  <label>setup code<input name="setup_code" type="password" autocomplete="off" required></label>
  {cred_field}
  <label>接入券（wot_…）<input name="ticket" required></label>
  <label>证书主机名（留空 = 取自收数地址）<input name="host"></label>
  <button>注册</button>
</form>
<pre id="out"></pre>
{INIT_SCRIPT}"#
        )
    };
    format!(
        "<!doctype html><meta charset=utf-8><title>{audience} 初始化</title>\
         <style>body{{font-family:system-ui;max-width:38rem;margin:3rem auto;padding:0 1rem}}\
         label{{display:block;margin:.6rem 0}}input{{width:100%;padding:.4rem}}\
         pre{{background:#f5f5f5;padding:.8rem;white-space:pre-wrap}}</style>{body}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::routing::post;
    use http_body_util::BodyExt;
    use std::net::SocketAddr;
    use tower::ServiceExt;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        // 计数器不能省：macOS 的 `SystemTime` 只到**微秒**，同一瞬间起的两个测试会撞同一纳秒值
        // → 共用目录 → 一个测试的证书被另一个覆盖（表现为随机的 `BadSignature`）。
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "wist-init-{tag}-{}-{}-{seq}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn uninitialized(dir: &std::path::Path) -> std::sync::Arc<Peer> {
        with_init(
            dir,
            InitConfig {
                setup_code: "crp_test_setup_code".to_string(),
                cred_url: None,
                ca_file: None,
                insecure_tls: true,
            },
        )
    }

    /// 未初始化 + 自定义 `[init]`（信任锚 / 不跳校验的用例要它）。
    fn with_init(dir: &std::path::Path, init: InitConfig) -> std::sync::Arc<Peer> {
        let config = Config::new("wist-console", dir.join("credentials.json"))
            .publish_endpoint("https://console.internal:18802/api/v1/internal/credentials")
            .init(init)
            .identity(identity(dir));
        Peer::open(config).expect("peer")
    }

    async fn request(app: Router, method: &str, body: Option<Value>) -> (StatusCode, Value) {
        let mut builder = axum::http::Request::builder()
            .method(method)
            .uri("/__init")
            .header("content-type", "application/json")
            .header("accept", "application/json");
        if body.is_none() {
            builder = builder.method("GET");
        }
        let request = builder
            .body(Body::from(body.map(|v| v.to_string()).unwrap_or_default()))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        (status, value)
    }

    #[test]
    fn setup_code_comparison_is_exact() {
        assert!(setup_code_matches("crp_abc", "crp_abc"));
        assert!(!setup_code_matches("crp_abc", "crp_abd"));
        assert!(!setup_code_matches("crp_abc", "crp_ab"));
        assert!(!setup_code_matches("crp_abc", ""));
    }

    #[test]
    fn host_is_taken_from_the_endpoint() {
        assert_eq!(
            host_of("https://console.internal:18802/api/v1/internal/credentials").as_deref(),
            Some("console.internal")
        );
        assert_eq!(
            host_of("https://console.internal/x").as_deref(),
            Some("console.internal")
        );
        assert_eq!(host_of("http://console.internal/x"), None);
        // IPv6 字面量：先按括号取，再谈端口。
        assert_eq!(host_of("https://[::1]:19499/x").as_deref(), Some("::1"));
        assert_eq!(host_of("https://[::1]/x").as_deref(), Some("::1"));
        // 空的端口 / 空主机都不是合法地址。
        assert_eq!(host_of("https://host:/x"), None);
        assert_eq!(host_of("https:///x"), None);
    }

    #[test]
    fn an_html_upstream_error_is_reported_instead_of_being_called_unreachable() {
        // 入口挂掉时回的是 nginx 的 HTML，不是 JSON —— 不能因此说“连不上 cred”。
        let err = upstream_error(
            "bundle_rejected",
            StatusCode::BAD_GATEWAY,
            &Value::Null,
            "<html><body>502 Bad Gateway</body></html>",
        );
        assert_eq!(err.code, "bundle_rejected");
        assert!(err.message.contains("502 Bad Gateway"), "{}", err.message);
    }

    #[test]
    fn state_without_identity_paths_is_initialized() {
        let config = Config::new("wist-console", "state/credentials.json");
        assert_eq!(state(&config), InitState::Initialized);
    }

    #[test]
    fn missing_materials_mean_uninitialized() {
        let dir = temp_dir("state");
        let config =
            Config::new("wist-console", dir.join("credentials.json")).identity(IdentityFiles {
                cert: dir.join("server.crt"),
                key: dir.join("server.key"),
                client_ca: dir.join("client-ca.pem"),
            });
        assert_eq!(state(&config), InitState::Uninitialized);
    }

    #[tokio::test]
    async fn get_reports_uninitialized_and_the_expected_endpoint() {
        let dir = temp_dir("get");
        let peer = uninitialized(&dir);
        let (status, body) = request(router(peer), "GET", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["state"], "uninitialized");
        assert_eq!(
            body["endpoint"],
            "https://console.internal:18802/api/v1/internal/credentials"
        );
    }

    #[tokio::test]
    async fn a_wrong_setup_code_is_refused_and_writes_nothing() {
        let dir = temp_dir("badcode");
        let peer = uninitialized(&dir);
        let (status, body) = request(
            router(peer),
            "POST",
            Some(json!({ "setup_code": "nope", "ticket": "wot_x", "cred_url": "https://127.0.0.1:1" })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"]["code"], "setup_code_invalid");
        assert!(!dir.join("server.crt").exists());
        assert!(!dir.join("client-ca.pem").exists());
    }

    #[tokio::test]
    async fn an_unreachable_cred_leaves_no_materials_behind() {
        let dir = temp_dir("unreachable");
        let peer = uninitialized(&dir);
        let (status, body) = request(
            router(peer),
            "POST",
            Some(json!({
                "setup_code": "crp_test_setup_code",
                "ticket": "wot_x",
                "cred_url": "http://127.0.0.1:1"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
        assert_eq!(body["error"]["code"], "cred_unreachable");
        assert!(!dir.join("server.crt").exists());
        assert!(!dir.join("server.key").exists());
        assert!(!dir.join("client-ca.pem").exists());
    }

    #[tokio::test]
    async fn a_redirect_is_refused_instead_of_being_followed() {
        // 入口配错（少一个斜杠 / http→https）时 cred 会回 3xx。券在 URL 里，
        // 跟过去等于把一次性券交给了重定向目标 —— 所以注册客户端显式不跟，
        // 而且错误要说清是“重定向”，不能报成“cred 拒绝”让人去查券。
        let app = Router::new().route(
            "/enroll/{token}/bundle",
            get(|| async { (StatusCode::FOUND, [(header::LOCATION, "/elsewhere")]) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let dir = temp_dir("redirect");
        let peer = uninitialized(&dir);
        let (status, body) = request(
            router(peer),
            "POST",
            Some(json!({
                "setup_code": "crp_test_setup_code",
                "ticket": "wot_test",
                "cred_url": format!("http://127.0.0.1:{}", addr.port()),
            })),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
        assert_eq!(body["error"]["code"], "cred_redirected");
        assert!(!dir.join("server.crt").exists());
    }

    #[tokio::test]
    async fn an_initialized_service_refuses_to_initialize_again() {
        let dir = temp_dir("twice");
        std::fs::write(dir.join("server.crt"), "x").unwrap();
        std::fs::write(dir.join("server.key"), "x").unwrap();
        std::fs::write(dir.join("client-ca.pem"), "x").unwrap();
        let peer = uninitialized(&dir);
        let (status, body) = request(
            router(peer),
            "POST",
            Some(json!({ "setup_code": "crp_test_setup_code", "ticket": "wot_x", "cred_url": "https://127.0.0.1:1" })),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["error"]["code"], "already_initialized");
    }

    // ── 配置期就该拒的东西（否则运行期只有一个安静的坑）──

    #[test]
    fn an_empty_setup_code_is_a_config_error() {
        let dir = temp_dir("emptycode");
        let config = Config::new("wist-console", dir.join("credentials.json"))
            .publish_endpoint("https://console.internal:18802/api/v1/internal/credentials")
            .identity(identity(&dir))
            .init(InitConfig {
                setup_code: "   ".to_string(),
                cred_url: None,
                ca_file: None,
                insecure_tls: false,
            });
        let err = match Peer::open(config) {
            Ok(_) => panic!("empty setup code must be refused"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("setup_code"), "{err}");
    }

    #[test]
    fn init_without_paths_or_endpoint_is_refused() {
        let dir = temp_dir("nopaths");
        let no_identity = Config::new("wist-console", dir.join("credentials.json"))
            .publish_endpoint("https://console.internal:18802/api/v1/internal/credentials")
            .init(InitConfig {
                setup_code: "crp_x".to_string(),
                cred_url: None,
                ca_file: None,
                insecure_tls: false,
            });
        assert!(Peer::open(no_identity).is_err());

        let no_endpoint = Config::new("wist-console", dir.join("credentials.json"))
            .identity(identity(&dir))
            .init(InitConfig {
                setup_code: "crp_x".to_string(),
                cred_url: None,
                ca_file: None,
                insecure_tls: false,
            });
        let err = match Peer::open(no_endpoint) {
            Ok(_) => panic!("missing endpoint must be refused"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("publish_endpoint"), "{err}");
    }

    // ── 错误文本截断：cred 的错误消息可能是中文 ──

    #[test]
    fn a_trust_anchor_and_insecure_tls_cannot_be_combined() {
        let dir = temp_dir("bothca");
        let ca = dir.join("ca.pem");
        std::fs::write(
            &ca,
            "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let config = Config::new("wist-console", dir.join("credentials.json"))
            .publish_endpoint("https://console.internal:18802/api/v1/internal/credentials")
            .identity(identity(&dir))
            .init(InitConfig {
                setup_code: "crp_x".to_string(),
                cred_url: None,
                ca_file: Some(ca),
                insecure_tls: true,
            });
        let err = match Peer::open(config) {
            Ok(_) => panic!("must refuse ca_file + insecure_tls"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("mutually exclusive"), "{err}");
    }

    #[test]
    fn a_missing_ca_file_is_refused_at_load_time() {
        let dir = temp_dir("noca");
        let config = Config::new("wist-console", dir.join("credentials.json"))
            .publish_endpoint("https://console.internal:18802/api/v1/internal/credentials")
            .identity(identity(&dir))
            .init(InitConfig {
                setup_code: "crp_x".to_string(),
                cred_url: None,
                ca_file: Some(dir.join("nope.pem")),
                insecure_tls: false,
            });
        let err = match Peer::open(config) {
            Ok(_) => panic!("must refuse a missing ca_file"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("ca_file"), "{err}");
    }

    #[test]
    fn upstream_error_text_truncates_by_characters_not_bytes() {
        let body = "错误".repeat(400);
        let err = upstream_error_text("enroll_rejected", StatusCode::BAD_REQUEST, &body);
        assert!(err.message.chars().count() < 400);
        assert!(err.message.contains("错误"));
    }

    // ── 端到端：stub cred（真签证书）+ 并发提交 ──

    fn identity(dir: &std::path::Path) -> IdentityFiles {
        IdentityFiles {
            cert: dir.join("server.crt"),
            key: dir.join("server.key"),
            client_ca: dir.join("client-ca.pem"),
        }
    }

    async fn stub_cred() -> SocketAddr {
        use wist_pki::CertificateAuthority;

        let (authority, ca_pem, _key) = CertificateAuthority::generate("Stub CA").expect("ca");
        let app = stub_cred_app(std::sync::Arc::new(authority), ca_pem);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        addr
    }

    /// 同一套注册端点（明文）。TLS 版的 stub 复用它，只是外面包一层。
    fn stub_cred_app(
        authority: std::sync::Arc<wist_pki::CertificateAuthority>,
        ca_pem: String,
    ) -> Router {
        use wist_pki::CertificateAuthority;

        let ca_for_bundle = ca_pem;
        Router::new()
            .route(
                "/enroll/{token}/bundle",
                get(move || {
                    let client_ca = ca_for_bundle.clone();
                    async move {
                        Json(json!({
                            "peer": "wist-console",
                            "client_ca_pem": client_ca,
                            "issuer_signing_pub": null,
                        }))
                    }
                }),
            )
            .route(
                "/enroll/{token}/certificate",
                post(
                    |State(authority): State<std::sync::Arc<CertificateAuthority>>,
                     Json(body): Json<Value>| async move {
                        let csr = body["certificate_signing_request"]
                            .as_str()
                            .expect("csr")
                            .to_string();
                        let host = body["host"].as_str().expect("host").to_string();
                        match authority.issue_server_certificate(&csr, &[host], 3600) {
                            Ok(issued) => (StatusCode::OK, issued.certificate_pem),
                            Err(error) => (StatusCode::BAD_REQUEST, error),
                        }
                    },
                ),
            )
            .with_state(authority)
    }

    /// 一套真材料：CA + 它签的服务器证书 + 对应私钥。
    struct Materials {
        ca_pem: String,
        cert_pem: String,
        key_pem: String,
    }

    fn issue_materials(common_name: &str) -> Materials {
        use wist_pki::CertificateAuthority;
        wist_pki::tls::install_crypto_provider();

        let (authority, ca_pem, _key) = CertificateAuthority::generate("Stub CA").expect("ca");
        let (cert_pem, key_pem) = issue_with(&authority, common_name);
        Materials {
            ca_pem,
            cert_pem,
            key_pem,
        }
    }

    /// 用给定的 CA 签一张服务器证书（返回证书 + 对应私钥 PEM）。
    fn issue_with(
        authority: &wist_pki::CertificateAuthority,
        common_name: &str,
    ) -> (String, String) {
        let key = rcgen::KeyPair::generate().expect("key");
        let mut params = rcgen::CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name.to_string());
        let csr = params
            .serialize_request(&key)
            .expect("csr")
            .pem()
            .expect("csr pem");
        let issued = authority
            .issue_server_certificate(&csr, &[common_name.to_string()], 3600)
            .expect("issue");
        (issued.certificate_pem, key.serialize_pem())
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut text = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = write!(text, "{byte:02x}");
        }
        text
    }

    /// 自签入口的 stub cred：真 TLS（rustls），证书由自己的 CA 签，CA 另行返回。
    async fn stub_cred_tls() -> (
        SocketAddr,
        String, /*ca pem*/
        String, /*leaf sha256*/
    ) {
        use std::sync::Arc;
        use wist_pki::CertificateAuthority;

        let (authority, ca_pem, _key) =
            CertificateAuthority::generate("Stub Entry CA").expect("ca");
        let authority = Arc::new(authority);
        let app = stub_cred_app(Arc::clone(&authority), ca_pem.clone());

        // 入口证书签给 `localhost`（reqwest 验证的是 URL 里的主机名），
        // 而且**同一把 CA** 签：测试要的就是“配了这个锚就能验过”。
        let (cert_pem, key_pem) = issue_with(&authority, "localhost");
        let dir = temp_dir("entry-tls");
        let cert = dir.join("entry.crt");
        let key = dir.join("entry.key");
        std::fs::write(&cert, &cert_pem).expect("cert");
        std::fs::write(&key, &key_pem).expect("key");

        // 期望的指纹：叶子证书 DER 的 SHA-256，与 reqwest 观察到的对端证书同口径。
        let chain = wist_pki::tls::chain_from_pem(&cert_pem).expect("chain");
        let leaf = hex(ring::digest::digest(&ring::digest::SHA256, chain[0].as_ref()).as_ref());

        let config = wist_pki::tls::server_config(&cert, &key).expect("server config");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        tokio::spawn(async move {
            loop {
                let Ok((stream, _peer)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let app = app.clone();
                tokio::spawn(async move {
                    let Ok(stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let io = hyper_util::rt::TokioIo::new(stream);
                    let service = hyper::service::service_fn(move |request| {
                        let app = app.clone();
                        async move { tower::ServiceExt::oneshot(app, request).await }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await;
                });
            }
        });

        (addr, ca_pem, leaf)
    }

    fn init_body(cred: SocketAddr) -> Value {
        json!({
            "setup_code": "crp_test_setup_code",
            "ticket": "wot_test",
            "cred_url": format!("http://{cred}"),
        })
    }

    #[tokio::test]
    async fn a_full_self_registration_writes_usable_materials() {
        let cred = stub_cred().await;
        let dir = temp_dir("e2e");
        let peer = uninitialized(&dir);
        let (status, body) = request(router(peer), "POST", Some(init_body(cred))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["state"], "initialized");
        assert_eq!(body["host"], "console.internal");

        let cert = std::fs::read_to_string(dir.join("server.crt")).expect("cert");
        let key = std::fs::read_to_string(dir.join("server.key")).expect("key");
        assert!(cert.contains("BEGIN CERTIFICATE"));
        assert!(key.contains("PRIVATE KEY"));
        assert!(
            dir.join("client-ca.pem").is_file(),
            "client CA must be written"
        );
        // 私钥只能自己可读。
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join("server.key"))
                .expect("meta")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "mode {mode:o}");
        }
        // 证书确实覆盖了上报的主机名。
        assert!(certificate_covers(&cert, "console.internal"));
        // 私钥与证书配对（重新加载一次）。
        wist_pki::tls::install_crypto_provider();
        assert!(
            wist_pki::tls::server_config(&dir.join("server.crt"), &dir.join("server.key")).is_ok()
        );
    }

    #[tokio::test]
    async fn concurrent_submissions_enroll_only_once() {
        let cred = stub_cred().await;
        let dir = temp_dir("race");
        let peer = uninitialized(&dir);
        let first = router(peer.clone());
        let second = router(peer);
        let (a, b) = tokio::join!(
            request(first, "POST", Some(init_body(cred))),
            request(second, "POST", Some(init_body(cred))),
        );
        let ok = usize::from(a.0 == StatusCode::OK) + usize::from(b.0 == StatusCode::OK);
        assert_eq!(
            ok, 1,
            "exactly one submission may succeed: {:?} / {:?}",
            a.0, b.0
        );
    }

    // ── P1：信任锚 + 指纹 + 热加载 ──

    #[tokio::test]
    async fn a_trust_anchor_verifies_the_entry_and_reports_its_fingerprint() {
        let (addr, ca_pem, leaf_sha256) = stub_cred_tls().await;
        let dir = temp_dir("anchor");
        let ca_file = dir.join("entry-ca.pem");
        std::fs::write(&ca_file, &ca_pem).expect("ca file");

        let peer = with_init(
            &dir,
            InitConfig {
                setup_code: "crp_test_setup_code".to_string(),
                cred_url: None,
                ca_file: Some(ca_file),
                insecure_tls: false,
            },
        );
        let (status, body) = request(
            router(peer),
            "POST",
            Some(json!({
                "setup_code": "crp_test_setup_code",
                "ticket": "wot_test",
                "cred_url": format!("https://localhost:{}", addr.port()),
            })),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        // 不需要重启：宿主用 serve_when_ready 自己起来。
        assert_eq!(body["restart_required"], false);
        // 指纹必须是真的（跟签出来的叶子证书 DER 对得上），不是个占位符。
        assert_eq!(body["cred_certificate_sha256"], leaf_sha256);
        assert!(dir.join("server.crt").is_file());
        assert!(dir.join("client-ca.pem").is_file());
    }

    #[tokio::test]
    async fn without_a_trust_anchor_a_self_signed_entry_is_refused() {
        let (addr, _ca_pem, _leaf) = stub_cred_tls().await;
        let dir = temp_dir("noanchor");
        let peer = with_init(
            &dir,
            InitConfig {
                setup_code: "crp_test_setup_code".to_string(),
                cred_url: None,
                ca_file: None,
                insecure_tls: false,
            },
        );
        let (status, body) = request(
            router(peer),
            "POST",
            Some(json!({
                "setup_code": "crp_test_setup_code",
                "ticket": "wot_test",
                "cred_url": format!("https://localhost:{}", addr.port()),
            })),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
        assert_eq!(body["error"]["code"], "cred_unreachable");
        // 错误里要说清“该配什么”，而不是只照抄 reqwest 的原文。
        let message = body["error"]["message"].as_str().unwrap_or_default();
        assert!(message.contains("ca_file"), "{message}");
        // 任何一步失败都不落材料。
        assert!(!dir.join("server.crt").exists());
        assert!(!dir.join("server.key").exists());
        assert!(!dir.join("client-ca.pem").exists());
    }

    #[test]
    fn a_publish_endpoint_without_a_host_is_a_config_error() {
        let dir = temp_dir("badendpoint");
        let config = Config::new("wist-console", dir.join("credentials.json"))
            // 栈没渲染 `CONSOLE_ADVERTISE_HOST` 时就是这个形状。
            .publish_endpoint("https://:18802/api/v1/internal/credentials")
            .identity(identity(&dir))
            .init(InitConfig {
                setup_code: "crp_x".to_string(),
                cred_url: None,
                ca_file: None,
                insecure_tls: false,
            });
        let err = match Peer::open(config) {
            Ok(_) => panic!("endpoint without a host must be refused"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("no usable host"), "{err}");
    }

    #[tokio::test]
    async fn a_host_that_differs_from_the_endpoint_is_refused() {
        let dir = temp_dir("hostmismatch");
        let peer = uninitialized(&dir);
        let (status, body) = request(
            router(peer),
            "POST",
            Some(json!({
                "setup_code": "crp_test_setup_code",
                "ticket": "wot_x",
                // 地址里的主机名是 console.internal；证书却要签给别的名字
                // → cred 一拨号就握手失败。宁可在这一步拦住。
                "host": "other.internal",
                "cred_url": "https://127.0.0.1:1",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"]["code"], "host_mismatch");
        assert!(!dir.join("server.crt").exists());
    }

    #[tokio::test]
    async fn serve_when_ready_listens_only_after_the_materials_appear() {
        // 先借一个空闲端口（绑后立刻放开），好断言“材料没齐时没人监听”。
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("probe");
        let listen = probe.local_addr().expect("addr");
        drop(probe);

        let dir = temp_dir("hotstart");
        let files = identity(&dir);
        let peer = uninitialized(&dir);
        let task = tokio::spawn(crate::serve::serve_when_ready(
            peer,
            listen,
            crate::serve::TlsFiles {
                cert: files.cert.clone(),
                key: files.key.clone(),
                client_ca: files.client_ca.clone(),
            },
        ));

        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            tokio::net::TcpStream::connect(listen).await.is_err(),
            "must not bind before the materials exist"
        );

        let materials = issue_materials("console.internal");
        std::fs::write(&files.cert, &materials.cert_pem).expect("cert");
        std::fs::write(&files.key, &materials.key_pem).expect("key");
        std::fs::write(&files.client_ca, &materials.ca_pem).expect("ca");

        let mut listening = false;
        for _ in 0..50 {
            if tokio::net::TcpStream::connect(listen).await.is_ok() {
                listening = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(
            listening,
            "the mTLS listener must come up once the materials are in place"
        );
        task.abort();
    }
}
