use std::path::PathBuf;
use std::time::Duration;

use thiserror::Error;

/// Ошибки управления сайдкаром Psiphon.
#[derive(Debug, Error)]
pub enum PsiphonError {
    #[error(
        "не заданы учётные данные Psiphon: заполните propagation_channel_id, sponsor_id, \
         remote_server_list_url и remote_server_list_signature_public_key в config.local.toml"
    )]
    MissingCredentials,
    #[error("не удалось запустить процесс Psiphon: {0}")]
    Spawn(#[source] std::io::Error),
    #[error("у процесса Psiphon нет stderr")]
    NoStderr,
    #[error("не удалось записать config.json в {path}: {source}")]
    ConfigWrite {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("не удалось сериализовать config.json: {0}")]
    ConfigSerialize(#[from] serde_json::Error),
    #[error("таймаут ожидания подключения Psiphon ({0:?})")]
    Timeout(Duration),
    #[error("процесс Psiphon остановился до подключения")]
    Stopped,
    #[error("не удалось определить каталог данных Psiphon: {0}")]
    DataDir(String),
}

pub type Result<T> = std::result::Result<T, PsiphonError>;
