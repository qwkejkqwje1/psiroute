use thiserror::Error;

/// Ошибки DPI-обхода и DoH.
#[derive(Debug, Error)]
pub enum DpiError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS: {0}")]
    Tls(String),
    #[error("HTTP/2: {0}")]
    Http2(String),
    #[error("DoH: {0}")]
    Doh(String),
    #[error("некорректный URL DoH: {0}")]
    Url(String),
    #[error("TLS-сообщение: {0}")]
    TlsMessage(String),
    #[error("нет DoH-серверов")]
    NoDohServers,
    #[error("не удалось разрешить {name}: {reason}")]
    Resolve { name: String, reason: String },
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, DpiError>;

impl From<DpiError> for psi_core::CoreError {
    fn from(error: DpiError) -> Self {
        psi_core::CoreError::Other(error.to_string())
    }
}
