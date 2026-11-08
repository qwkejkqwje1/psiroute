use thiserror::Error;

/// Ошибки VLESS-клиента.
#[derive(Debug, Error)]
pub enum VlessError {
    #[error("некорректный VLESS UUID: {0}")]
    Uuid(#[from] uuid::Error),
    #[error("некорректный vless:// URI: {0}")]
    Uri(String),
    #[error("не задан сервер VLESS")]
    MissingServer,
    #[error("TLS: {0}")]
    Tls(String),
    #[error("WebSocket: {0}")]
    WebSocket(String),
    #[error("сетевая ошибка: {0}")]
    Io(#[from] std::io::Error),
    #[error("не удалось подключиться ни к одному адресу {0}")]
    NoCandidate(String),
    #[error("некорректный IP/CIDR: {0}")]
    Range(String),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, VlessError>;

impl From<VlessError> for psi_core::CoreError {
    fn from(error: VlessError) -> Self {
        psi_core::CoreError::Other(error.to_string())
    }
}
