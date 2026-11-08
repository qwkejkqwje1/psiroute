use std::fmt;
use std::net::IpAddr;

use serde::Deserialize;

use crate::error::{Result, RouterError};

/// Действие маршрутизации.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Direct,
    Dpi,
    Psiphon,
    Vless,
    Warp,
    Block,
}

impl Action {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "direct" => Ok(Self::Direct),
            "dpi" => Ok(Self::Dpi),
            "psiphon" => Ok(Self::Psiphon),
            "vless" => Ok(Self::Vless),
            "warp" => Ok(Self::Warp),
            "block" => Ok(Self::Block),
            other => Err(RouterError::UnknownAction(other.to_string())),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Dpi => "dpi",
            Self::Psiphon => "psiphon",
            Self::Vless => "vless",
            Self::Warp => "warp",
            Self::Block => "block",
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Транспорт соединения.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    Tcp,
    Udp,
}

impl Network {
    pub fn parse(value: &str) -> Result<Option<Self>> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" => Ok(None),
            "tcp" => Ok(Some(Self::Tcp)),
            "udp" => Ok(Some(Self::Udp)),
            other => Err(RouterError::InvalidNetwork(other.to_string())),
        }
    }
}

/// Метаданные соединения для маршрутизации.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Meta {
    pub domain: Option<String>,
    pub ip: Option<IpAddr>,
    pub port: u16,
    pub process: Option<String>,
    pub network: Option<Network>,
}

impl Meta {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            ..Self::default()
        }
    }

    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    pub fn with_ip(mut self, ip: IpAddr) -> Self {
        self.ip = Some(ip);
        self
    }

    pub fn with_process(mut self, process: impl Into<String>) -> Self {
        self.process = Some(process.into());
        self
    }

    pub fn with_network(mut self, network: Network) -> Self {
        self.network = Some(network);
        self
    }
}

/// Решение роутера и правило, которое его приняло.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDecision {
    pub action: Action,
    pub rule_idx: Option<usize>,
    pub rule_name: String,
}

impl RouteDecision {
    pub fn final_action(action: Action) -> Self {
        Self {
            action,
            rule_idx: None,
            rule_name: "final".to_string(),
        }
    }

    pub fn explain(&self) -> String {
        match self.rule_idx {
            Some(index) => format!("{} ← правило #{} «{}»", self.action, index, self.rule_name),
            None => format!("{} ← final", self.action),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub(crate) struct Preset {
    #[serde(rename = "final")]
    pub final_action: String,
    pub rules: Vec<psi_config::RuleCfg>,
}

impl Default for Preset {
    fn default() -> Self {
        Self {
            final_action: "direct".to_string(),
            rules: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_actions() {
        assert_eq!(Action::parse("DIRECT").expect("action"), Action::Direct);
        assert_eq!(Action::parse("").expect("action"), Action::Direct);
        assert_eq!(Action::parse("psiphon").expect("action"), Action::Psiphon);
        assert!(Action::parse("proxy").is_err());
    }

    #[test]
    fn parses_network() {
        assert_eq!(Network::parse("tcp").expect("tcp"), Some(Network::Tcp));
        assert_eq!(Network::parse("").expect("any"), None);
        assert!(Network::parse("sctp").is_err());
    }
}
