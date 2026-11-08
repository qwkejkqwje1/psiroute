use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Отпечаток текущей сети: хэш шлюза и его MAC/SSID.
///
/// Используется как `NetworkID` Psiphon и ключ кэша победившей стратегии.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkFingerprint {
    pub id: String,
    pub gateway: Option<String>,
    pub gateway_mac: Option<String>,
    pub interface: Option<String>,
    pub ssid: Option<String>,
}

impl NetworkFingerprint {
    /// Снимает отпечаток с активного сетевого интерфейса.
    pub fn current() -> Self {
        let gateway = netdev::get_default_gateway().ok();
        let interface = netdev::get_default_interface().ok();

        let gateway_ip = gateway
            .as_ref()
            .and_then(|device| device.ipv4.first().map(ToString::to_string));

        let interface_mac = interface
            .as_ref()
            .and_then(|iface| iface.mac_addr)
            .map(|mac| format!("{mac:?}"));

        let gateway_mac = gateway
            .as_ref()
            .map(|device| format!("{:?}", device.mac_addr))
            .or_else(|| interface_mac.clone());

        let interface_name = interface.as_ref().map(|iface| iface.name.clone());

        Self::from_parts(gateway_ip, gateway_mac, interface_name, None)
    }

    /// Собирает отпечаток вручную (например, в тестах или при подмене сети).
    pub fn from_parts(
        gateway: Option<String>,
        gateway_mac: Option<String>,
        interface: Option<String>,
        ssid: Option<String>,
    ) -> Self {
        let mut parts = Vec::new();
        for value in [
            gateway.as_deref(),
            gateway_mac.as_deref(),
            interface.as_deref(),
            ssid.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if !value.is_empty() {
                parts.push(value);
            }
        }

        if parts.is_empty() {
            parts.push("unknown-network");
        }

        let digest = Sha256::digest(parts.join("|").as_bytes());
        let mut id = String::with_capacity(digest.len() * 2);
        for byte in digest {
            id.push_str(&format!("{byte:02x}"));
        }

        Self {
            id,
            gateway,
            gateway_mac,
            interface,
            ssid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_parts_same_id() {
        let first = NetworkFingerprint::from_parts(
            Some("192.168.1.1".to_string()),
            Some("aa:bb:cc:dd:ee:ff".to_string()),
            Some("Wi-Fi".to_string()),
            Some("home".to_string()),
        );
        let second = NetworkFingerprint::from_parts(
            Some("192.168.1.1".to_string()),
            Some("aa:bb:cc:dd:ee:ff".to_string()),
            Some("Wi-Fi".to_string()),
            Some("home".to_string()),
        );

        assert_eq!(first.id, second.id);
        assert_eq!(first.id.len(), 64);
    }

    #[test]
    fn different_parts_different_id() {
        let first = NetworkFingerprint::from_parts(
            Some("192.168.1.1".to_string()),
            Some("aa:bb:cc:dd:ee:ff".to_string()),
            None,
            None,
        );
        let second = NetworkFingerprint::from_parts(
            Some("10.0.0.1".to_string()),
            Some("aa:bb:cc:dd:ee:ff".to_string()),
            None,
            None,
        );

        assert_ne!(first.id, second.id);
    }

    #[test]
    fn empty_parts_are_stable() {
        let first = NetworkFingerprint::from_parts(None, None, None, None);
        let second = NetworkFingerprint::from_parts(Some(String::new()), None, None, None);

        assert_eq!(first.id, second.id);
    }
}
