use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::Result;

/// Победившая стратегия для конкретной сети.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheEntry {
    pub tag: String,
    pub last_ok: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct CacheFile {
    #[serde(default)]
    networks: HashMap<String, CacheEntry>,
}

/// Кэш `fingerprint -> победившая стратегия` (`bootstrap_cache.json`).
#[derive(Debug, Clone)]
pub struct BootstrapCache {
    path: PathBuf,
    file: CacheFile,
}

impl BootstrapCache {
    pub fn load(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let file = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        Self { path, file }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn get(&self, fingerprint: &str) -> Option<&CacheEntry> {
        self.file.networks.get(fingerprint)
    }

    pub fn winner_tag(&self, fingerprint: &str) -> Option<&str> {
        self.get(fingerprint).map(|entry| entry.tag.as_str())
    }

    /// Запоминает победителя и сохраняет кэш на диск.
    pub fn remember(&mut self, fingerprint: &str, tag: &str) -> Result<()> {
        let last_ok = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default();

        self.file.networks.insert(
            fingerprint.to_string(),
            CacheEntry {
                tag: tag.to_string(),
                last_ok,
            },
        );
        self.save()
    }

    fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let text = serde_json::to_string_pretty(&self.file)?;
        let temp = self.path.with_extension("json.tmp");
        std::fs::write(&temp, text)?;

        // Windows не переименовывает поверх существующего файла.
        let _ = std::fs::remove_file(&self.path);
        std::fs::rename(&temp, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "psiroute-bootstrap-{name}-{}.json",
            std::process::id()
        ))
    }

    #[test]
    fn remembers_and_reloads_winner() {
        let path = temp_path("cache");
        let _ = std::fs::remove_file(&path);

        let mut cache = BootstrapCache::load(&path);
        assert!(cache.get("net-1").is_none());

        cache.remember("net-1", "vless").expect("запись");
        assert_eq!(cache.winner_tag("net-1"), Some("vless"));

        let reloaded = BootstrapCache::load(&path);
        assert_eq!(reloaded.winner_tag("net-1"), Some("vless"));
        assert!(reloaded.get("net-1").is_some());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_or_broken_file_is_empty() {
        let path = temp_path("broken");
        std::fs::write(&path, "{not json").expect("запись");
        let cache = BootstrapCache::load(&path);
        assert!(cache.get("net").is_none());
        let _ = std::fs::remove_file(&path);
    }
}
