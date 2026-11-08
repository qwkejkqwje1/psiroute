use thiserror::Error;

#[derive(Debug, Error)]
pub enum RouterError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("неизвестное действие: {0}")]
    UnknownAction(String),
    #[error("неизвестная сеть: {0}")]
    InvalidNetwork(String),
    #[error("неверный порт: {0}")]
    InvalidPort(String),
    #[error("неверный CIDR: {0}")]
    InvalidCidr(String),
    #[error("неверное регулярное выражение: {0}")]
    InvalidRegex(String),
    #[error("неизвестный пресет: {0}")]
    UnknownPreset(String),
    #[error("загрузка списков: {0}")]
    Download(String),
    #[error("HTTP {status} для {url}")]
    HttpStatus { url: String, status: u16 },
    #[error("пустой файл: {0}")]
    EmptyFile(String),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, RouterError>;
