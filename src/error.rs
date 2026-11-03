//! 错误类型：库不依赖日志门面，只把结构化原因交回调用方。

use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// 配置本身不成立（缺名字、路径为空…）。
    Config(String),
    /// 摘要表打不开 / 写不进去。
    Store(String),
    /// 监听或 TLS 材料有问题。
    Serve(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Config(message) => write!(f, "invalid peer config: {message}"),
            Error::Store(message) => write!(f, "credential store: {message}"),
            Error::Serve(message) => write!(f, "serve: {message}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
