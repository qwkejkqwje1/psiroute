use serde::{Deserialize, Serialize};

use crate::error::{PsiphonError, Result};

/// Конфигурация, которая сериализуется в `config.json` для `psiphon-tunnel-core`.
///
/// Ключи — PascalCase, как их ожидает ConsoleClient.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct PsiphonConfig {
    /// Путь к бинарю. В config.json не попадает.
    #[serde(skip)]
    pub binary: String,
    pub propagation_channel_id: String,
    pub sponsor_id: String,
    pub remote_server_list_url: String,
    pub remote_server_list_signature_public_key: String,
    pub data_root_directory: String,
    /// Пустая строка — Psiphon выберет лучшую страну.
    pub egress_region: String,
    /// 0 — Psiphon выберет порт сам.
    pub local_socks_proxy_port: u16,
    pub local_http_proxy_port: u16,
    /// `None` — ПРЯМОЙ запуск Psiphon: ядро само обходит блокировки своими
    /// протоколами (OSSH, TLS-OSSH, meek/CDN, QUIC) без внешних хопов.
    /// `Some("socks5://...")` — Psiphon ходит через VLESS/WARP/DPI-мост.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_proxy_url: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub limit_tunnel_protocols: Vec<String>,
    pub network_id: String,
    pub tunnel_pool_size: u8,
    pub emit_bytes_transferred: bool,
    pub emit_diagnostic_notices: bool,
    pub establish_tunnel_timeout_seconds: u32,
}

impl Default for PsiphonConfig {
    fn default() -> Self {
        Self {
            binary: "psiphon-tunnel-core".to_string(),
            propagation_channel_id: String::new(),
            sponsor_id: String::new(),
            remote_server_list_url: String::new(),
            remote_server_list_signature_public_key: String::new(),
            data_root_directory: String::new(),
            egress_region: String::new(),
            local_socks_proxy_port: 0,
            local_http_proxy_port: 0,
            upstream_proxy_url: None,
            limit_tunnel_protocols: Vec::new(),
            network_id: "default".to_string(),
            tunnel_pool_size: 1,
            emit_bytes_transferred: true,
            emit_diagnostic_notices: false,
            establish_tunnel_timeout_seconds: 25,
        }
    }
}

impl PsiphonConfig {
    /// Собирает конфиг из TOML-настроек `psi-config`.
    ///
    /// `upstream_proxy_url = None` означает прямой режим: Psiphon использует
    /// собственный обход блокировок. Если нужен внешний хоп (VLESS/WARP/DPI),
    /// передайте `Some("socks5://127.0.0.1:PORT")`.
    pub fn from_settings(
        settings: &psi_config::Psiphon,
        data_root_directory: impl Into<String>,
        upstream_proxy_url: Option<String>,
        network_id: impl Into<String>,
    ) -> Result<Self> {
        if settings.propagation_channel_id.trim().is_empty()
            || settings.sponsor_id.trim().is_empty()
            || settings.remote_server_list_url.trim().is_empty()
            || settings
                .remote_server_list_signature_public_key
                .trim()
                .is_empty()
        {
            return Err(PsiphonError::MissingCredentials);
        }

        let binary = if settings.binary.trim().is_empty() {
            "psiphon-tunnel-core".to_string()
        } else {
            settings.binary.clone()
        };

        Ok(Self {
            binary,
            propagation_channel_id: settings.propagation_channel_id.clone(),
            sponsor_id: settings.sponsor_id.clone(),
            remote_server_list_url: settings.remote_server_list_url.clone(),
            remote_server_list_signature_public_key: settings
                .remote_server_list_signature_public_key
                .clone(),
            data_root_directory: data_root_directory.into(),
            egress_region: settings.egress_region.clone(),
            local_socks_proxy_port: 0,
            local_http_proxy_port: 0,
            upstream_proxy_url,
            limit_tunnel_protocols: settings.limit_tunnel_protocols.clone(),
            network_id: network_id.into(),
            tunnel_pool_size: settings.tunnel_pool_size,
            emit_bytes_transferred: true,
            emit_diagnostic_notices: false,
            establish_tunnel_timeout_seconds: 25,
        })
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.propagation_channel_id.trim().is_empty()
            || self.sponsor_id.trim().is_empty()
            || self.remote_server_list_url.trim().is_empty()
            || self
                .remote_server_list_signature_public_key
                .trim()
                .is_empty()
        {
            return Err(PsiphonError::MissingCredentials);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_pascal_case_keys() {
        let config = PsiphonConfig {
            data_root_directory: "C:/data".to_string(),
            ..PsiphonConfig::default()
        };
        let json = serde_json::to_value(&config).expect("json");

        assert!(json.get("PropagationChannelId").is_some());
        assert!(json.get("LocalSocksProxyPort").is_some());
        assert!(json.get("EmitBytesTransferred").is_some());
        assert!(json.get("binary").is_none());
        assert!(json.get("UpstreamProxyUrl").is_none());
    }

    #[test]
    fn empty_credentials_are_rejected() {
        let settings = psi_config::Psiphon::default();
        let error = PsiphonConfig::from_settings(&settings, "data", None, "default")
            .expect_err("должна быть ошибка");
        assert!(matches!(error, PsiphonError::MissingCredentials));
    }

    #[test]
    fn direct_mode_has_no_upstream() {
        let settings = psi_config::Psiphon {
            propagation_channel_id: "id".to_string(),
            sponsor_id: "sponsor".to_string(),
            remote_server_list_url: "https://example.org/list".to_string(),
            remote_server_list_signature_public_key: "key".to_string(),
            ..psi_config::Psiphon::default()
        };

        let config =
            PsiphonConfig::from_settings(&settings, "data", None, "default").expect("config");
        assert!(config.upstream_proxy_url.is_none());
        assert_eq!(config.network_id, "default");
    }
}
