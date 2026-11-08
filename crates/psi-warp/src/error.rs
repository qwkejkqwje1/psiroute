use thiserror::Error;

#[derive(Debug, Error)]
pub enum WarpError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("ключи: {0}")]
    Keys(String),
    #[error("регистрация: {0}")]
    Register(String),
    #[error("API: {0}")]
    Api(String),
    #[error("HTTP: {0}")]
    Http(String),
    #[error("TLS: {0}")]
    Tls(String),
    #[error("профиль: {0}")]
    Profile(String),
    #[error("туннель: {0}")]
    Tunnel(String),
    #[error("сеть: {0}")]
    Net(String),
    #[error("таймаут: {0}")]
    Timeout(String),
    #[error("эндпоинт: {0}")]
    Endpoint(String),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, WarpError>;

impl From<WarpError> for psi_core::CoreError {
    fn from(error: WarpError) -> Self {
        psi_core::CoreError::Other(error.to_string())
    }
}
