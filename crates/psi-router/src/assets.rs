use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use maxminddb::Reader;
use prost::Message;
use regex::RegexSet;

use crate::normalize::{normalize_domain, normalize_suffix, suffix_matches};

#[derive(Clone, PartialEq, Message)]
struct GeoSiteList {
    #[prost(message, repeated, tag = "1")]
    entry: Vec<GeoSite>,
}

#[derive(Clone, PartialEq, Message)]
struct GeoSite {
    #[prost(string, tag = "1")]
    country_code: String,
    #[prost(message, repeated, tag = "2")]
    domain: Vec<Domain>,
}

#[derive(Clone, PartialEq, Message)]
struct Domain {
    /// Тип записи v2ray: 0 = Plain (подстрока), 1 = Regex,
    /// 2 = Domain (домен и поддомены), 3 = Full (точное совпадение).
    #[prost(int32, tag = "1")]
    kind: i32,
    #[prost(string, tag = "2")]
    value: String,
}

#[derive(Clone, PartialEq, Message)]
struct GeoIpList {
    #[prost(message, repeated, tag = "1")]
    entry: Vec<GeoIp>,
}

#[derive(Clone, PartialEq, Message)]
struct GeoIp {
    #[prost(string, tag = "1")]
    country_code: String,
    #[prost(message, repeated, tag = "2")]
    cidr: Vec<Cidr>,
}

#[derive(Clone, PartialEq, Message)]
struct Cidr {
    #[prost(bytes = "vec", tag = "1")]
    ip: Vec<u8>,
    #[prost(uint32, tag = "2")]
    prefix: u32,
}

#[derive(Default)]
struct GeoDomains {
    exact: HashSet<String>,
    suffix: HashSet<String>,
    keywords: Vec<String>,
    keyword_ac: Option<aho_corasick::AhoCorasick>,
    regex: Vec<String>,
    compiled: Option<RegexSet>,
}

impl GeoDomains {
    fn merge(&mut self, entries: Vec<Domain>) {
        for entry in entries {
            match entry.kind {
                // Plain — подстрока домена.
                0 => {
                    let keyword = normalize_domain(&entry.value);
                    if !keyword.is_empty() {
                        self.keywords.push(keyword);
                    }
                }
                1 => self.regex.push(entry.value),
                // Domain — домен и все его поддомены.
                2 => {
                    self.suffix.insert(normalize_suffix(&entry.value));
                }
                // Full и неизвестные типы — только точное совпадение.
                _ => {
                    self.exact.insert(normalize_domain(&entry.value));
                }
            }
        }
    }

    fn compile(&mut self) {
        if !self.keywords.is_empty() {
            self.keyword_ac = aho_corasick::AhoCorasick::new(&self.keywords).ok();
        }
        if !self.regex.is_empty() {
            self.compiled = RegexSet::new(&self.regex).ok();
        }
    }

    fn matches(&self, domain: &str) -> bool {
        self.exact.contains(domain)
            || suffix_matches(domain, &self.suffix)
            || self
                .keyword_ac
                .as_ref()
                .is_some_and(|keywords| keywords.is_match(domain))
            || self
                .compiled
                .as_ref()
                .is_some_and(|regex| regex.is_match(domain))
    }
}

/// Загруженные geosite/geoip-базы (v2ray dat и MaxMind mmdb).
#[derive(Default)]
pub struct RouterAssets {
    geosite: HashMap<String, GeoDomains>,
    geoip: HashMap<String, Vec<(IpAddr, u8)>>,
    mmdb: Option<Reader<Vec<u8>>>,
}

impl RouterAssets {
    /// Загружает `geosite.dat`, `allow-geosite.dat`, `geoip.dat` и `GeoLite2-Country.mmdb`
    /// из каталога, если файлы существуют.
    pub fn load(dir: &Path) -> Self {
        let mut assets = Self::default();

        for name in ["geosite.dat", "allow-geosite.dat"] {
            if let Ok(bytes) = std::fs::read(dir.join(name)) {
                assets.merge_geosite(&bytes);
            }
        }

        if let Ok(bytes) = std::fs::read(dir.join("geoip.dat")) {
            assets.merge_geoip(&bytes);
        }

        if let Ok(reader) = Reader::open_readfile(dir.join("GeoLite2-Country.mmdb")) {
            assets.mmdb = Some(reader);
        }

        assets
    }

    pub fn from_parts(geosite: Option<&[u8]>, geoip: Option<&[u8]>) -> Self {
        let mut assets = Self::default();
        if let Some(bytes) = geosite {
            assets.merge_geosite(bytes);
        }
        if let Some(bytes) = geoip {
            assets.merge_geoip(bytes);
        }
        assets
    }

    pub fn is_empty(&self) -> bool {
        self.geosite.is_empty() && self.geoip.is_empty() && self.mmdb.is_none()
    }

    pub(crate) fn geosite_matches(&self, code: &str, domain: &str) -> bool {
        let domain = normalize_domain(domain);
        self.geosite
            .get(&code.to_ascii_uppercase())
            .is_some_and(|entry| entry.matches(&domain))
    }

    pub(crate) fn geoip_cidrs(&self, code: &str) -> &[(IpAddr, u8)] {
        self.geoip
            .get(&code.to_ascii_uppercase())
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    pub(crate) fn country_of(&self, ip: IpAddr) -> Option<String> {
        let reader = self.mmdb.as_ref()?;
        let result = reader.lookup(ip).ok()?;
        let country: maxminddb::geoip2::Country = result.decode().ok()??;
        country
            .country
            .iso_code
            .map(|code| code.to_ascii_uppercase())
    }

    fn merge_geosite(&mut self, bytes: &[u8]) {
        let Ok(list) = GeoSiteList::decode(bytes) else {
            return;
        };

        for entry in list.entry {
            let code = entry.country_code.to_ascii_uppercase();
            self.geosite.entry(code).or_default().merge(entry.domain);
        }

        for entry in self.geosite.values_mut() {
            entry.compile();
        }
    }

    fn merge_geoip(&mut self, bytes: &[u8]) {
        let Ok(list) = GeoIpList::decode(bytes) else {
            return;
        };

        for entry in list.entry {
            let code = entry.country_code.to_ascii_uppercase();
            let cidrs = self.geoip.entry(code).or_default();

            for cidr in entry.cidr {
                if let Some(value) = cidr_to_address(&cidr) {
                    cidrs.push(value);
                }
            }
        }
    }
}

fn cidr_to_address(cidr: &Cidr) -> Option<(IpAddr, u8)> {
    let prefix = u8::try_from(cidr.prefix).ok()?;

    match cidr.ip.len() {
        4 => {
            let octets: [u8; 4] = cidr.ip.as_slice().try_into().ok()?;
            Some((IpAddr::V4(Ipv4Addr::from(octets)), prefix))
        }
        16 => {
            let octets: [u8; 16] = cidr.ip.as_slice().try_into().ok()?;
            Some((IpAddr::V6(Ipv6Addr::from(octets)), prefix))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_geosite_dat() {
        let list = GeoSiteList {
            entry: vec![GeoSite {
                country_code: "ru-blocked".to_string(),
                domain: vec![
                    // Domain: домен и поддомены.
                    Domain {
                        kind: 2,
                        value: "blocked.example".to_string(),
                    },
                    Domain {
                        kind: 2,
                        value: "рф".to_string(),
                    },
                    // Full: только точное совпадение.
                    Domain {
                        kind: 3,
                        value: "exact.example".to_string(),
                    },
                    // Plain: подстрока.
                    Domain {
                        kind: 0,
                        value: "sample".to_string(),
                    },
                ],
            }],
        };
        let mut bytes = Vec::new();
        list.encode(&mut bytes).expect("encode");

        let assets = RouterAssets::from_parts(Some(&bytes), None);
        assert!(assets.geosite_matches("RU-BLOCKED", "blocked.example"));
        assert!(assets.geosite_matches("ru-blocked", "sub.blocked.example"));
        assert!(!assets.geosite_matches("ru-blocked", "notblocked.example"));
        assert!(assets.geosite_matches("ru-blocked", "пример.рф"));
        assert!(assets.geosite_matches("ru-blocked", "exact.example"));
        assert!(!assets.geosite_matches("ru-blocked", "sub.exact.example"));
        assert!(assets.geosite_matches("ru-blocked", "mysample.net"));
        assert!(!assets.geosite_matches("ru-blocked", "example.com"));
    }

    #[test]
    fn parses_geoip_dat() {
        let list = GeoIpList {
            entry: vec![GeoIp {
                country_code: "RU".to_string(),
                cidr: vec![Cidr {
                    ip: vec![10, 0, 0, 0],
                    prefix: 8,
                }],
            }],
        };
        let mut bytes = Vec::new();
        list.encode(&mut bytes).expect("encode");

        let assets = RouterAssets::from_parts(None, Some(&bytes));
        assert_eq!(
            assets.geoip_cidrs("ru"),
            &[("10.0.0.0".parse().expect("ip"), 8)]
        );
    }
}
