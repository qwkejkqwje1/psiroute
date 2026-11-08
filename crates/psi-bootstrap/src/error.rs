use std::time::Duration;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum BootstrapError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("конфигурация: {0}")]
    Config(#[from] psi_config::ConfigError),
    #[error("psiphon: {0}")]
    Psiphon(#[from] psi_psiphon::PsiphonError),
    #[error("нет учётных данных Psiphon")]
    MissingCredentials,
    #[error("нет доступных стратегий")]
    NoStrategies,
    #[error("ни одна стратегия не подключилась за {0:?}")]
    Timeout(Duration),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, BootstrapError>;
