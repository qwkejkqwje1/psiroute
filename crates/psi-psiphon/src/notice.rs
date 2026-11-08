use serde_json::Value;

/// Разобранное notice-событие Psiphon (JSON-строка в stderr).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    ListeningSocksProxyPort { port: u16 },
    ListeningHttpProxyPort { port: u16 },
    Tunnels { count: u32 },
    AvailableEgressRegions { regions: Vec<String> },
    ActiveTunnel { protocol: String, region: String },
    BytesTransferred { sent: u64, received: u64 },
    Alert { message: String },
    Error { message: String },
    Unknown { notice_type: String },
}

impl Notice {
    /// Разбирает строку stderr. `None` — строка не является JSON-notice.
    pub fn parse(line: &str) -> Option<Self> {
        let value: Value = serde_json::from_str(line.trim()).ok()?;
        let notice_type = value.get("noticeType")?.as_str()?;
        let data = value.get("data").cloned().unwrap_or(Value::Null);

        let notice = match notice_type {
            "ListeningSocksProxyPort" => Self::ListeningSocksProxyPort {
                port: data.get("port").and_then(Value::as_u64)? as u16,
            },
            "ListeningHttpProxyPort" => Self::ListeningHttpProxyPort {
                port: data.get("port").and_then(Value::as_u64)? as u16,
            },
            "Tunnels" => Self::Tunnels {
                count: data.get("count").and_then(Value::as_u64).unwrap_or(0) as u32,
            },
            "AvailableEgressRegions" => Self::AvailableEgressRegions {
                regions: data
                    .get("regions")
                    .and_then(Value::as_array)
                    .map(|regions| {
                        regions
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default(),
            },
            "ActiveTunnel" => Self::ActiveTunnel {
                protocol: data
                    .get("protocol")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                region: data
                    .get("region")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            },
            "BytesTransferred" => Self::BytesTransferred {
                sent: data.get("sent").and_then(Value::as_u64).unwrap_or(0),
                received: data.get("received").and_then(Value::as_u64).unwrap_or(0),
            },
            "Alert" => Self::Alert {
                message: data
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            },
            "Error" => Self::Error {
                message: data
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            },
            other => Self::Unknown {
                notice_type: other.to_string(),
            },
        };

        Some(notice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TUNNELS: &str =
        r#"{"noticeType":"Tunnels","data":{"count":1},"timestamp":"2024-01-01T00:00:00Z"}"#;
    const SOCKS: &str = r#"{"noticeType":"ListeningSocksProxyPort","data":{"port":1080},"timestamp":"2024-01-01T00:00:00Z"}"#;
    const REGIONS: &str = r#"{"noticeType":"AvailableEgressRegions","data":{"regions":["US","DE","JP"]},"timestamp":"2024-01-01T00:00:00Z"}"#;
    const BYTES: &str = r#"{"noticeType":"BytesTransferred","data":{"sent":1024,"received":2048},"timestamp":"2024-01-01T00:00:00Z"}"#;
    const TUNNEL: &str = r#"{"noticeType":"ActiveTunnel","data":{"protocol":"OSSH","region":"DE"},"timestamp":"2024-01-01T00:00:00Z"}"#;

    #[test]
    fn parses_tunnels_notice() {
        assert_eq!(
            Notice::parse(TUNNELS),
            Some(Notice::Tunnels { count: 1 })
        );
    }

    #[test]
    fn parses_socks_port_notice() {
        assert_eq!(
            Notice::parse(SOCKS),
            Some(Notice::ListeningSocksProxyPort { port: 1080 })
        );
    }

    #[test]
    fn parses_regions_notice() {
        assert_eq!(
            Notice::parse(REGIONS),
            Some(Notice::AvailableEgressRegions {
                regions: vec!["US".to_string(), "DE".to_string(), "JP".to_string()],
            })
        );
    }

    #[test]
    fn parses_bytes_notice() {
        assert_eq!(
            Notice::parse(BYTES),
            Some(Notice::BytesTransferred {
                sent: 1024,
                received: 2048,
            })
        );
    }

    #[test]
    fn parses_active_tunnel_notice() {
        assert_eq!(
            Notice::parse(TUNNEL),
            Some(Notice::ActiveTunnel {
                protocol: "OSSH".to_string(),
                region: "DE".to_string(),
            })
        );
    }

    #[test]
    fn ignores_non_json_lines() {
        assert_eq!(Notice::parse("starting psiphon-tunnel-core..."), None);
    }
}
