use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::{Result, RouterError};

const RUNETFREEDOM_GEOSITE: &str =
    "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat";
const RUNETFREEDOM_GEOIP: &str =
    "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat";
const ITDOG_GEOSITE: &str =
    "https://github.com/itdoginfo/allow-domains/releases/latest/download/geosite.dat";

const DOWNLOADS: &[(&str, &str)] = &[
    (RUNETFREEDOM_GEOSITE, "geosite.dat"),
    (RUNETFREEDOM_GEOIP, "geoip.dat"),
    (ITDOG_GEOSITE, "allow-geosite.dat"),
];

/// Скачивание geosite/geoip-списков раз в сутки через текущий выход.
pub struct ListUpdater {
    dir: PathBuf,
}

impl ListUpdater {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Скачивает и атомарно заменяет `geosite.dat`, `geoip.dat`, `allow-geosite.dat`.
    pub async fn update(&self, proxy: Option<&str>) -> Result<Vec<PathBuf>> {
        std::fs::create_dir_all(&self.dir)?;

        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .user_agent("PsiRoute/0.1");

        if let Some(proxy) = proxy {
            builder = builder.proxy(
                reqwest::Proxy::all(proxy)
                    .map_err(|error| RouterError::Download(error.to_string()))?,
            );
        }

        let client = builder
            .build()
            .map_err(|error| RouterError::Download(error.to_string()))?;

        // Сначала скачиваем ВСЕ файлы: сбой на любом из них не должен
        // оставлять наполовину обновлённый набор списков на диске.
        let mut downloaded = Vec::with_capacity(DOWNLOADS.len());

        for (url, file) in DOWNLOADS {
            let response = client
                .get(*url)
                .send()
                .await
                .map_err(|error| RouterError::Download(format!("{url}: {error}")))?;

            if !response.status().is_success() {
                return Err(RouterError::HttpStatus {
                    url: (*url).to_string(),
                    status: response.status().as_u16(),
                });
            }

            let bytes = response
                .bytes()
                .await
                .map_err(|error| RouterError::Download(format!("{url}: {error}")))?;

            if bytes.is_empty() {
                return Err(RouterError::EmptyFile((*url).to_string()));
            }

            downloaded.push((self.dir.join(file), bytes));
        }

        let mut saved = Vec::with_capacity(downloaded.len());
        for (path, bytes) in &downloaded {
            write_atomic(path, bytes)?;
            saved.push(path.clone());
        }

        tracing::info!(target: "psi_router", count = saved.len(), "списки geosite/geoip обновлены");
        Ok(saved)
    }

    /// Запускает ежедневное обновление в фоне.
    pub fn spawn_daily(self, proxy: Option<String>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(24 * 60 * 60));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ticker.tick().await;

            loop {
                ticker.tick().await;
                if let Err(error) = self.update(proxy.as_deref()).await {
                    tracing::warn!(target: "psi_router", %error, "не удалось обновить списки");
                }
            }
        })
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let temp = path.with_extension("tmp");
    std::fs::write(&temp, bytes)?;

    // Windows не переименовывает поверх существующего файла.
    let _ = std::fs::remove_file(path);
    std::fs::rename(&temp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_atomically() {
        let dir =
            std::env::temp_dir().join(format!("psiroute-router-updater-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");

        let path = dir.join("geosite.dat");
        write_atomic(&path, b"first").expect("first");
        write_atomic(&path, b"second").expect("second");

        assert_eq!(std::fs::read(&path).expect("read"), b"second");
        assert!(!dir.join("geosite.tmp").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
