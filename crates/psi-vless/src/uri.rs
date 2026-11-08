use std::collections::HashMap;

use url::Url;
use uuid::Uuid;

use crate::error::{Result, VlessError};

/// Нормализованные настройки VLESS-WS-TLS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessSettings {
    pub server: String,
    pub port: u16,
    pub uuid: Uuid,
    pub path: String,
    pub sni: String,
    pub host: String,
    pub early_data: usize,
    pub clean_ips: Vec<String>,
    pub fragment: bool,
}

impl VlessSettings {
    /// Собирает настройки из TOML-конфига.
    pub fn from_config(config: &psi_config::Vless) -> Result<Self> {
        if config.server.trim().is_empty() {
            return Err(VlessError::MissingServer);
        }

        let uuid = Uuid::parse_str(config.uuid.trim())?;
        let sni = if config.sni.trim().is_empty() {
            config.server.clone()
        } else {
            config.sni.clone()
        };
        let host = if config.host.trim().is_empty() {
            sni.clone()
        } else {
            config.host.clone()
        };
        let path = if config.path.trim().is_empty() {
            "/".to_string()
        } else {
            config.path.clone()
        };

        Ok(Self {
            server: config.server.clone(),
            port: if config.port == 0 { 443 } else { config.port },
            uuid,
            path,
            sni,
            host,
            early_data: config.early_data.min(64 * 1024),
            clean_ips: config.clean_ips.clone(),
            fragment: false,
        })
    }

    /// Парсит `vless://UUID@host:port?type=ws&security=tls&sni=..&host=..&path=..&ed=..`.
    pub fn from_uri(uri: &str) -> Result<Self> {
        let url = Url::parse(uri).map_err(|error| VlessError::Uri(error.to_string()))?;
        if url.scheme() != "vless" {
            return Err(VlessError::Uri(format!(
                "ожидалась схема vless://, получена {}://",
                url.scheme()
            )));
        }

        let uuid = Uuid::parse_str(url.username())?;
        let server = url
            .host_str()
            .ok_or_else(|| VlessError::Uri("нет хоста".to_string()))?
            .to_string();
        let port = url.port().unwrap_or(443);

        let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
        let security = params
            .get("security")
            .map(String::as_str)
            .unwrap_or("tls");
        if security != "tls" {
            return Err(VlessError::Uri(format!(
                "поддерживается только security=tls, получено {security}"
            )));
        }
        let transport = params.get("type").map(String::as_str).unwrap_or("ws");
        if transport != "ws" {
            return Err(VlessError::Uri(format!(
                "поддерживается только type=ws, получено {transport}"
            )));
        }

        let path = params.get("path").cloned().unwrap_or_else(|| "/".to_string());
        let sni = params
            .get("sni")
            .or_else(|| params.get("host"))
            .cloned()
            .unwrap_or_else(|| server.clone());
        let host = params.get("host").cloned().unwrap_or_else(|| sni.clone());
        let early_data = params
            .get("ed")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(2048)
            .min(64 * 1024);

        Ok(Self {
            server,
            port,
            uuid,
            path,
            sni,
            host,
            early_data,
            clean_ips: Vec::new(),
            fragment: false,
        })
    }

    /// Список `(host, port)` для подключения: clean IP, затем основной сервер.
    pub(crate) fn candidates(&self) -> Vec<(String, u16)> {
        let mut candidates: Vec<(String, u16)> = self
            .clean_ips
            .iter()
            .filter(|ip| !ip.trim().is_empty())
            .map(|ip| (ip.clone(), self.port))
            .collect();

        if !candidates.iter().any(|(host, _)| host == &self.server) {
            candidates.push((self.server.clone(), self.port));
        }

        candidates
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_vless_uri() {
        let uri = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@vpn.example.com:443\
                   ?type=ws&security=tls&sni=cdn.example.com&host=cdn.example.com\
                   &path=%2Fapi%2Fv1%2Fstream%3Fed%3D2048&ed=2048";

        let settings = VlessSettings::from_uri(uri).expect("URI");

        assert_eq!(settings.server, "vpn.example.com");
        assert_eq!(settings.port, 443);
        assert_eq!(settings.sni, "cdn.example.com");
        assert_eq!(settings.host, "cdn.example.com");
        assert_eq!(settings.path, "/api/v1/stream?ed=2048");
        assert_eq!(settings.early_data, 2048);
        assert_eq!(
            settings.uuid,
            Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").expect("uuid")
        );
    }

    #[test]
    fn rejects_unknown_transport() {
        let uri = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@vpn.example.com:443?type=grpc";
        assert!(VlessSettings::from_uri(uri).is_err());
    }
}
