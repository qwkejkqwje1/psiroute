use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use psi_core::{BoxStream, Outbound, Target};

use crate::junk::JunkConfig;
use crate::keys::KeyPair;
use crate::{Result, WarpError};

const API_HOST: &str = "api.cloudflareclient.com";
const API_PATH: &str = "/v0a2158/reg";
const CLIENT_VERSION: &str = "a-6.11-2223";
const USER_AGENT: &str = "okhttp/3.12.1";
const DEFAULT_ENDPOINT: &str = "162.159.192.1:2408";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WarpRegistration {
    pub private_key: String,
    pub peer_public_key: String,
    pub address_v4: String,
    pub address_v6: String,
    pub reserved: [u8; 3],
    pub endpoint: String,
    pub client_id: String,
}

impl Default for WarpRegistration {
    fn default() -> Self {
        Self {
            private_key: String::new(),
            peer_public_key: String::new(),
            address_v4: "172.16.0.2".to_string(),
            address_v6: String::new(),
            reserved: [0, 0, 0],
            endpoint: DEFAULT_ENDPOINT.to_string(),
            client_id: String::new(),
        }
    }
}

impl WarpRegistration {
    /// Регистрирует новый WARP-профиль (как wgcf).
    pub async fn register() -> Result<Self> {
        Self::register_via(None).await
    }

    /// Регистрация напрямую или через готовый выход (VLESS/DPI).
    pub async fn register_via(outbound: Option<&dyn Outbound>) -> Result<Self> {
        let keys = KeyPair::generate();

        let body = serde_json::json!({
            "key": keys.public_base64(),
            "install_id": "",
            "fcm_token": "",
            "tos": rfc3339_now(),
            "type": "Android",
            "locale": "en_US",
        })
        .to_string();

        let (status, response) = post_json(API_PATH, body.as_bytes(), outbound).await?;
        if status != 200 {
            return Err(WarpError::Api(format!(
                "регистрация вернула HTTP {status}: {}",
                String::from_utf8_lossy(&response)
            )));
        }

        let value: serde_json::Value = serde_json::from_slice(&response)
            .map_err(|error| WarpError::Api(format!("JSON: {error}")))?;

        let peer_public_key = value["config"]["peers"][0]["public_key"]
            .as_str()
            .ok_or_else(|| WarpError::Api("нет config.peers[0].public_key".to_string()))?
            .to_string();
        let address_v4 = value["config"]["interface"]["addresses"]["v4"]
            .as_str()
            .ok_or_else(|| WarpError::Api("нет config.interface.addresses.v4".to_string()))?
            .to_string();
        let address_v6 = value["config"]["interface"]["addresses"]["v6"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let client_id = value["config"]["client_id"].as_str().unwrap_or_default();
        let reserved = decode_reserved(client_id);

        Ok(Self {
            private_key: keys.private_base64(),
            peer_public_key,
            address_v4: strip_prefix(address_v4),
            address_v6: strip_prefix(address_v6),
            reserved,
            endpoint: DEFAULT_ENDPOINT.to_string(),
            client_id: client_id.to_string(),
        })
    }

    /// Преобразует профиль в секцию `[warp]` конфигурации.
    pub fn to_settings(&self) -> psi_config::Warp {
        let (host, port) = split_endpoint(&self.endpoint).unwrap_or(("162.159.192.1", 2408));
        psi_config::Warp {
            private_key: self.private_key.clone(),
            peer_public_key: self.peer_public_key.clone(),
            endpoint: format!("{host}:{port}"),
            address_v4: self.address_v4.clone(),
            address_v6: self.address_v6.clone(),
            reserved: self.reserved,
            awg: psi_config::Awg::default(),
        }
    }
}

pub struct ImportedProfile {
    pub registration: WarpRegistration,
    pub junk: JunkConfig,
}

/// Импорт `wgcf-profile.conf` / AmneziaWG `.conf`.
pub fn import_conf(text: &str) -> Result<ImportedProfile> {
    let values = parse_ini(text);

    let private_key = values
        .get("privatekey")
        .or_else(|| values.get("private_key"))
        .ok_or_else(|| WarpError::Profile("нет PrivateKey".to_string()))?
        .clone();
    let peer_public_key = values
        .get("publickey")
        .or_else(|| values.get("public_key"))
        .ok_or_else(|| WarpError::Profile("нет PublicKey".to_string()))?
        .clone();

    let mut address_v4 = String::new();
    let mut address_v6 = String::new();
    for raw in values
        .get("address")
        .map(|value| value.split(',').collect::<Vec<_>>())
        .unwrap_or_default()
    {
        let address = strip_prefix(raw.trim().to_string());
        if address.parse::<std::net::Ipv4Addr>().is_ok() {
            address_v4 = address;
        } else if address.parse::<std::net::Ipv6Addr>().is_ok() {
            address_v6 = address;
        }
    }

    let endpoint = values
        .get("endpoint")
        .cloned()
        .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());
    let reserved = values
        .get("reserved")
        .map(|value| parse_reserved(value))
        .transpose()?
        .unwrap_or([0, 0, 0]);

    let awg = psi_config::Awg {
        jc: values
            .get("jc")
            .and_then(|value| value.parse().ok())
            .unwrap_or(4),
        jmin: values
            .get("jmin")
            .and_then(|value| value.parse().ok())
            .unwrap_or(40),
        jmax: values
            .get("jmax")
            .and_then(|value| value.parse().ok())
            .unwrap_or(70),
        i1: values.get("i1").cloned(),
    };
    let junk = JunkConfig::from_awg(&awg)?;

    // Проверяем, что ключи действительно x25519 в base64.
    KeyPair::from_private_base64(&private_key)?;
    crate::keys::public_from_base64(&peer_public_key)?;

    Ok(ImportedProfile {
        registration: WarpRegistration {
            private_key,
            peer_public_key,
            address_v4,
            address_v6,
            reserved,
            endpoint,
            client_id: String::new(),
        },
        junk,
    })
}

fn parse_ini(text: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') || line.starts_with('[')
        {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            values.insert(
                key.trim().to_ascii_lowercase(),
                value.trim().to_string(),
            );
        }
    }
    values
}

fn parse_reserved(value: &str) -> Result<[u8; 3]> {
    let parts: Vec<u8> = value
        .split(',')
        .map(|part| {
            part.trim()
                .parse::<u8>()
                .map_err(|error| WarpError::Profile(format!("reserved: {error}")))
        })
        .collect::<Result<_>>()?;

    parts
        .try_into()
        .map_err(|_| WarpError::Profile("reserved должен содержать 3 байта".to_string()))
}

fn decode_reserved(client_id: &str) -> [u8; 3] {
    STANDARD
        .decode(client_id)
        .ok()
        .and_then(|bytes| bytes.get(..3).map(|slice| [slice[0], slice[1], slice[2]]))
        .unwrap_or([0, 0, 0])
}

fn strip_prefix(address: String) -> String {
    address
        .split_once('/')
        .map(|(address, _)| address.to_string())
        .unwrap_or(address)
}

fn split_endpoint(endpoint: &str) -> Option<(&str, u16)> {
    let (host, port) = endpoint.rsplit_once(':')?;
    Some((host, port.parse().ok()?))
}

async fn post_json(
    path: &str,
    body: &[u8],
    outbound: Option<&dyn Outbound>,
) -> Result<(u16, Vec<u8>)> {
    let attempt = async {
        let stream: BoxStream = match outbound {
            Some(outbound) => outbound
                .connect_tcp(&Target::Domain(API_HOST.to_string(), 443))
                .await
                .map_err(|error| WarpError::Register(error.to_string()))?,
            None => Box::new(TcpStream::connect((API_HOST, 443)).await?),
        };

        let connector = tls_connector()?;
        let server_name = ServerName::try_from(API_HOST.to_string())
            .map_err(|error| WarpError::Tls(error.to_string()))?;
        let mut tls = connector
            .connect(server_name, stream)
            .await
            .map_err(|error| WarpError::Tls(error.to_string()))?;

        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: {API_HOST}\r\nUser-Agent: {USER_AGENT}\r\nCF-Client-Version: {CLIENT_VERSION}\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );

        tls.write_all(request.as_bytes()).await?;
        tls.write_all(body).await?;
        tls.flush().await?;

        let mut response = Vec::new();
        tls.read_to_end(&mut response).await?;
        parse_http_response(&response)
    };

    tokio::time::timeout(Duration::from_secs(20), attempt)
        .await
        .map_err(|_| WarpError::Timeout("регистрация WARP".to_string()))?
}

fn parse_http_response(response: &[u8]) -> Result<(u16, Vec<u8>)> {
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| WarpError::Http("нет конца заголовков".to_string()))?;

    let headers = String::from_utf8_lossy(&response[..split]).to_ascii_lowercase();
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| WarpError::Http("нет кода статуса".to_string()))?;

    let body = &response[split + 4..];
    let body = if headers.contains("transfer-encoding: chunked") {
        dechunk(body)?
    } else {
        body.to_vec()
    };

    Ok((status, body))
}

fn dechunk(body: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut rest = body;

    loop {
        let line_end = rest
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| WarpError::Http("chunked: нет CRLF".to_string()))?;
        let size_text = String::from_utf8_lossy(&rest[..line_end]);
        let size = usize::from_str_radix(size_text.trim(), 16)
            .map_err(|error| WarpError::Http(format!("chunked: {error}")))?;

        rest = &rest[line_end + 2..];
        if size == 0 {
            break;
        }
        if rest.len() < size {
            return Err(WarpError::Http("chunked: обрезанный чанк".to_string()));
        }
        output.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }

    Ok(output)
}

fn tls_connector() -> Result<TlsConnector> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(TlsConnector::from(std::sync::Arc::new(config)))
}

fn rfc3339_now() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default();

    let days = seconds.div_euclid(86_400);
    let rem = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);

    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = (z - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year =
        day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    } as u32;

    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_timestamp() {
        // 2021-01-01T00:00:00Z
        let (year, month, day) = civil_from_days(18_628);
        assert_eq!((year, month, day), (2021, 1, 1));
    }

    #[test]
    fn imports_wgcf_profile() {
        let profile = r#"
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 172.16.0.2/32, 2606:4700:110:8a36::2/128
DNS = 1.1.1.1

[Peer]
PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Endpoint = 162.159.192.1:2408
AllowedIPs = 0.0.0.0/0
"#;
        let imported = import_conf(profile).expect("import");
        assert_eq!(imported.registration.address_v4, "172.16.0.2");
        assert_eq!(imported.registration.endpoint, "162.159.192.1:2408");
        assert!(imported.registration.address_v6.starts_with("2606:"));
    }

    #[test]
    fn imports_amnezia_junk() {
        let profile = r#"
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 172.16.0.2/32
Jc = 5
Jmin = 40
Jmax = 80
[Peer]
PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Endpoint = 162.159.192.1:2408
"#;
        let imported = import_conf(profile).expect("import");
        assert_eq!(imported.junk.jc, 5);
        assert_eq!(imported.junk.jmin, 40);
        assert_eq!(imported.junk.jmax, 80);
    }

    #[test]
    fn decodes_http_response() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let (status, body) = parse_http_response(response).expect("response");
        assert_eq!(status, 200);
        assert_eq!(body, b"ok");
    }
}
