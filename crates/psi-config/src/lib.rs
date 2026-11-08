use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const CONFIG_FILE: &str = "config.toml";
const LOCAL_FILE: &str = "config.local.toml";

/// Ошибки загрузки/сохранения конфигурации.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("не удалось определить каталог конфигурации: {0}")]
    ProjectDirs(String),
    #[error("не удалось прочитать {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("не удалось записать {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("ошибка TOML в {path}: {source}")]
    Toml {
        path: PathBuf,
        #[source]
        source: Box<toml::de::Error>,
    },
    #[error("ошибка сериализации TOML: {0}")]
    TomlSer(#[from] toml::ser::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct General {
    pub log_level: String,
}

impl Default for General {
    fn default() -> Self {
        Self {
            log_level: "info".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Inbound {
    pub mixed_port: u16,
    pub tun: bool,
    pub system_proxy: bool,
}

impl Default for Inbound {
    fn default() -> Self {
        Self {
            mixed_port: 7890,
            tun: false,
            system_proxy: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Psiphon {
    pub binary: String,
    pub propagation_channel_id: String,
    pub sponsor_id: String,
    pub remote_server_list_url: String,
    pub remote_server_list_signature_public_key: String,
    pub egress_region: String,
    pub limit_tunnel_protocols: Vec<String>,
    pub tunnel_pool_size: u8,
}

impl Default for Psiphon {
    fn default() -> Self {
        Self {
            binary: String::new(),
            propagation_channel_id: String::new(),
            sponsor_id: String::new(),
            remote_server_list_url: String::new(),
            remote_server_list_signature_public_key: String::new(),
            egress_region: String::new(),
            limit_tunnel_protocols: Vec::new(),
            tunnel_pool_size: 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Vless {
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub path: String,
    pub sni: String,
    pub host: String,
    pub early_data: usize,
    pub clean_ips: Vec<String>,
}

impl Default for Vless {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: 443,
            uuid: String::new(),
            path: "/api/v1/stream".to_string(),
            sni: String::new(),
            host: String::new(),
            early_data: 2048,
            clean_ips: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Awg {
    pub jc: u8,
    pub jmin: u16,
    pub jmax: u16,
    pub i1: Option<String>,
}

impl Default for Awg {
    fn default() -> Self {
        Self {
            jc: 4,
            jmin: 40,
            jmax: 70,
            i1: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Warp {
    pub private_key: String,
    pub peer_public_key: String,
    pub endpoint: String,
    pub address_v4: String,
    pub address_v6: String,
    pub reserved: [u8; 3],
    pub awg: Awg,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Dpi {
    pub strategy: String,
    pub split_pos: String,
    pub doh: Vec<String>,
}

impl Default for Dpi {
    fn default() -> Self {
        Self {
            strategy: "tlsrec".to_string(),
            split_pos: "sni".to_string(),
            doh: Vec::new(),
        }
    }
}

/// Условия правила; внутри одного `match` действует ИЛИ.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MatchCfg {
    pub domain: Vec<String>,
    pub domain_suffix: Vec<String>,
    pub domain_keyword: Vec<String>,
    pub domain_regex: Vec<String>,
    pub geosite: Vec<String>,
    pub ip_cidr: Vec<String>,
    pub geoip: Vec<String>,
    pub process: Vec<String>,
    /// Диапазоны портов: `"443,8000-9000"`.
    pub port: String,
    /// `"tcp"` или `"udp"`.
    pub network: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RuleCfg {
    pub name: String,
    #[serde(rename = "match")]
    pub matcher: MatchCfg,
    /// Все условия должны совпасть (И).
    pub all: Vec<MatchCfg>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not: Option<MatchCfg>,
    pub action: String,
}

impl Default for RuleCfg {
    fn default() -> Self {
        Self {
            name: String::new(),
            matcher: MatchCfg::default(),
            all: Vec::new(),
            not: None,
            action: "direct".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Routing {
    pub preset: String,
    pub rules: Vec<RuleCfg>,
}

impl Default for Routing {
    fn default() -> Self {
        Self {
            preset: "smart_ru".to_string(),
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Bootstrap {
    pub order: Vec<String>,
    pub stagger_ms: u64,
    pub timeout_s: u64,
    /// Автоматически переключаться на прямой путь Psiphon, если он снова доступен.
    pub auto_promote: bool,
}

impl Default for Bootstrap {
    fn default() -> Self {
        Self {
            order: vec![
                "direct".to_string(),
                "dpi".to_string(),
                "vless".to_string(),
                "warp".to_string(),
            ],
            stagger_ms: 300,
            timeout_s: 25,
            auto_promote: true,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub general: General,
    pub inbound: Inbound,
    pub psiphon: Psiphon,
    pub vless: Option<Vless>,
    pub warp: Option<Warp>,
    pub dpi: Dpi,
    pub routing: Routing,
    pub bootstrap: Bootstrap,
}

impl Config {
    /// Каталог конфигурации (`%APPDATA%\PsiRoute` / `~/.config/psiroute`).
    pub fn config_dir() -> Result<PathBuf, ConfigError> {
        directories::ProjectDirs::from("dev", "psiroute", "PsiRoute")
            .map(|dirs| dirs.config_dir().to_path_buf())
            .ok_or_else(|| ConfigError::ProjectDirs("ProjectDirs::from вернул None".to_string()))
    }

    /// Каталог данных (кэш серверов Psiphon, списки гео и т.п.).
    pub fn data_dir() -> Result<PathBuf, ConfigError> {
        directories::ProjectDirs::from("dev", "psiroute", "PsiRoute")
            .map(|dirs| dirs.data_dir().to_path_buf())
            .ok_or_else(|| ConfigError::ProjectDirs("ProjectDirs::from вернул None".to_string()))
    }

    /// Загружает `config.toml` и поверх него `config.local.toml`.
    pub fn load() -> Result<Self, ConfigError> {
        Self::load_from_dir(&Self::config_dir()?)
    }

    /// Загружает конфигурацию из произвольного каталога (удобно для тестов).
    pub fn load_from_dir(dir: &Path) -> Result<Self, ConfigError> {
        let public_path = dir.join(CONFIG_FILE);
        let mut value = match read_value(&public_path)? {
            Some(value) => value,
            None => toml::Value::Table(toml::map::Map::new()),
        };

        if let Some(local) = read_value(&dir.join(LOCAL_FILE))? {
            merge_values(&mut value, &local);
        }

        value
            .try_into::<Config>()
            .map_err(|source| ConfigError::Toml {
                path: public_path,
                source: Box::new(source),
            })
    }

    /// Сохраняет конфигурацию в стандартный каталог.
    pub fn save(&self) -> Result<(), ConfigError> {
        self.save_to_dir(&Self::config_dir()?)
    }

    /// Сохраняет НЕсекретную часть в `config.toml`, секреты — в `config.local.toml`.
    pub fn save_to_dir(&self, dir: &Path) -> Result<(), ConfigError> {
        std::fs::create_dir_all(dir).map_err(|source| ConfigError::Write {
            path: dir.to_path_buf(),
            source,
        })?;

        write_value(&dir.join(CONFIG_FILE), &self.to_public_value()?)?;

        let local_path = dir.join(LOCAL_FILE);
        let local = self.to_local_value()?;
        let is_empty = local
            .as_table()
            .map(|table| table.is_empty())
            .unwrap_or(true);

        if is_empty {
            if local_path.exists() {
                std::fs::remove_file(&local_path).map_err(|source| ConfigError::Write {
                    path: local_path,
                    source,
                })?;
            }
        } else {
            write_value(&local_path, &local)?;
        }

        Ok(())
    }

    fn to_public_value(&self) -> Result<toml::Value, ConfigError> {
        let mut value = toml::Value::try_from(self)?;

        if let Some(table) = value.as_table_mut() {
            if let Some(psiphon) = table.get_mut("psiphon").and_then(toml::Value::as_table_mut) {
                psiphon.insert(
                    "propagation_channel_id".to_string(),
                    toml::Value::String(String::new()),
                );
                psiphon.insert("sponsor_id".to_string(), toml::Value::String(String::new()));
            }

            if let Some(vless) = table.get_mut("vless").and_then(toml::Value::as_table_mut) {
                vless.insert("uuid".to_string(), toml::Value::String(String::new()));
            }

            if let Some(warp) = table.get_mut("warp").and_then(toml::Value::as_table_mut) {
                warp.insert(
                    "private_key".to_string(),
                    toml::Value::String(String::new()),
                );
                warp.insert(
                    "peer_public_key".to_string(),
                    toml::Value::String(String::new()),
                );
                warp.insert(
                    "reserved".to_string(),
                    toml::Value::Array(vec![
                        toml::Value::Integer(0),
                        toml::Value::Integer(0),
                        toml::Value::Integer(0),
                    ]),
                );
            }
        }

        Ok(value)
    }

    fn to_local_value(&self) -> Result<toml::Value, ConfigError> {
        let mut root = toml::map::Map::new();

        let mut psiphon = toml::map::Map::new();
        if !self.psiphon.propagation_channel_id.is_empty() {
            psiphon.insert(
                "propagation_channel_id".to_string(),
                toml::Value::String(self.psiphon.propagation_channel_id.clone()),
            );
        }
        if !self.psiphon.sponsor_id.is_empty() {
            psiphon.insert(
                "sponsor_id".to_string(),
                toml::Value::String(self.psiphon.sponsor_id.clone()),
            );
        }
        if !psiphon.is_empty() {
            root.insert("psiphon".to_string(), toml::Value::Table(psiphon));
        }

        if let Some(vless) = &self.vless {
            if !vless.uuid.is_empty() {
                let mut table = toml::map::Map::new();
                table.insert("uuid".to_string(), toml::Value::String(vless.uuid.clone()));
                root.insert("vless".to_string(), toml::Value::Table(table));
            }
        }

        if let Some(warp) = &self.warp {
            let mut table = toml::map::Map::new();
            if !warp.private_key.is_empty() {
                table.insert(
                    "private_key".to_string(),
                    toml::Value::String(warp.private_key.clone()),
                );
            }
            if !warp.peer_public_key.is_empty() {
                table.insert(
                    "peer_public_key".to_string(),
                    toml::Value::String(warp.peer_public_key.clone()),
                );
            }
            if warp.reserved != [0, 0, 0] {
                table.insert(
                    "reserved".to_string(),
                    toml::Value::Array(
                        warp.reserved
                            .iter()
                            .map(|byte| toml::Value::Integer(i64::from(*byte)))
                            .collect(),
                    ),
                );
            }
            if !table.is_empty() {
                root.insert("warp".to_string(), toml::Value::Table(table));
            }
        }

        Ok(toml::Value::Table(root))
    }
}

/// Рекурсивно накладывает `overlay` на `base` (таблицы сливаются, скаляры заменяются).
pub fn merge_values(base: &mut toml::Value, overlay: &toml::Value) {
    match (base, overlay) {
        (toml::Value::Table(base), toml::Value::Table(overlay)) => {
            for (key, value) in overlay {
                match base.get_mut(key) {
                    Some(existing) => merge_values(existing, value),
                    None => {
                        base.insert(key.clone(), value.clone());
                    }
                }
            }
        }
        (base, overlay) => *base = overlay.clone(),
    }
}

fn read_value(path: &Path) -> Result<Option<toml::Value>, ConfigError> {
    match std::fs::read_to_string(path) {
        Ok(text) => text
            .parse::<toml::Value>()
            .map(Some)
            .map_err(|source| ConfigError::Toml {
                path: path.to_path_buf(),
                source: Box::new(source),
            }),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(source) => Err(ConfigError::Read {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn write_value(path: &Path, value: &toml::Value) -> Result<(), ConfigError> {
    let text = toml::to_string_pretty(value)?;
    std::fs::write(path, text).map_err(|source| ConfigError::Write {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deep_merge_overrides_and_preserves() {
        let mut base: toml::Value = "[inbound]\nmixed_port = 7890\nsystem_proxy = true\n"
            .parse()
            .expect("валидный TOML");
        let overlay: toml::Value =
            "[inbound]\nmixed_port = 1080\n[psiphon]\nsponsor_id = \"abc\"\n"
                .parse()
                .expect("валидный TOML");

        merge_values(&mut base, &overlay);
        let config: Config = base.try_into().expect("десериализация");

        assert_eq!(config.inbound.mixed_port, 1080);
        assert!(config.inbound.system_proxy);
        assert_eq!(config.psiphon.sponsor_id, "abc");
        assert_eq!(config.bootstrap.stagger_ms, 300);
        assert_eq!(config.inbound.tun, false);
    }

    #[test]
    fn save_splits_secrets() {
        let dir = std::env::temp_dir().join(format!("psiroute-config-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mut config = Config::default();
        config.psiphon.sponsor_id = "secret-sponsor".to_string();
        config.vless = Some(Vless {
            uuid: "secret-uuid".to_string(),
            ..Vless::default()
        });

        config.save_to_dir(&dir).expect("сохранение");

        let public = std::fs::read_to_string(dir.join(CONFIG_FILE)).expect("config.toml");
        let local = std::fs::read_to_string(dir.join(LOCAL_FILE)).expect("config.local.toml");

        assert!(!public.contains("secret-sponsor"));
        assert!(!public.contains("secret-uuid"));
        assert!(local.contains("secret-sponsor"));
        assert!(local.contains("secret-uuid"));

        let loaded = Config::load_from_dir(&dir).expect("загрузка");
        assert_eq!(loaded.psiphon.sponsor_id, "secret-sponsor");
        assert_eq!(
            loaded.vless.as_ref().map(|vless| vless.uuid.as_str()),
            Some("secret-uuid")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
