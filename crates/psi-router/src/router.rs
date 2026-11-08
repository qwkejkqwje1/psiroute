use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use aho_corasick::AhoCorasick;
use arc_swap::ArcSwap;
use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use quick_cache::sync::Cache;
use regex::RegexSetBuilder;

use psi_config::{MatchCfg, Routing, RuleCfg};

use crate::assets::RouterAssets;
use crate::error::{Result, RouterError};
use crate::model::{Action, Meta, Network, Preset, RouteDecision};
use crate::normalize::{normalize_domain, normalize_suffix, parse_ports, suffix_matches};

const CACHE_CAPACITY: usize = 10_000;

/// Скомпилированный набор условий одного `match`.
struct MatcherSet {
    domains: HashSet<String>,
    suffixes: HashSet<String>,
    keywords: Option<AhoCorasick>,
    regexes: Option<regex::RegexSet>,
    cidrs: IpNetworkTable<()>,
    geoip_codes: Vec<String>,
    geoip_table: IpNetworkTable<()>,
    geosite_codes: Vec<String>,
    processes: HashSet<String>,
    ports: Vec<(u16, u16)>,
    network: Option<Network>,
    empty: bool,
}

impl MatcherSet {
    fn compile(config: &MatchCfg, assets: &RouterAssets) -> Result<Self> {
        let domains: HashSet<String> = config
            .domain
            .iter()
            .map(|value| normalize_domain(value))
            .filter(|value| !value.is_empty())
            .collect();

        let suffixes: HashSet<String> = config
            .domain_suffix
            .iter()
            .map(|value| normalize_suffix(value))
            .filter(|value| !value.is_empty())
            .collect();

        let keywords: Vec<String> = config
            .domain_keyword
            .iter()
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty())
            .collect();

        let keywords = if keywords.is_empty() {
            None
        } else {
            Some(
                AhoCorasick::new(&keywords)
                    .map_err(|error| RouterError::InvalidRegex(format!("aho-corasick: {error}")))?,
            )
        };

        let regexes = if config.domain_regex.is_empty() {
            None
        } else {
            Some(
                RegexSetBuilder::new(&config.domain_regex)
                    .case_insensitive(true)
                    .build()
                    .map_err(|error| RouterError::InvalidRegex(error.to_string()))?,
            )
        };

        let mut cidrs = IpNetworkTable::new();
        for value in &config.ip_cidr {
            let network = IpNetwork::from_str(value.trim())
                .map_err(|_| RouterError::InvalidCidr(value.clone()))?;
            cidrs.insert(network, ());
        }

        let geoip_codes: Vec<String> = config
            .geoip
            .iter()
            .map(|code| code.trim().to_ascii_uppercase())
            .filter(|code| !code.is_empty())
            .collect();

        let mut geoip_table = IpNetworkTable::new();
        for code in &geoip_codes {
            for (ip, prefix) in assets.geoip_cidrs(code) {
                if let Ok(network) = IpNetwork::new(*ip, *prefix) {
                    geoip_table.insert(network, ());
                }
            }
        }

        let geosite_codes: Vec<String> = config
            .geosite
            .iter()
            .map(|code| code.trim().to_ascii_uppercase())
            .filter(|code| !code.is_empty())
            .collect();

        let processes: HashSet<String> = config
            .process
            .iter()
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty())
            .collect();

        let ports = parse_ports(&config.port)?;
        let network = Network::parse(&config.network)?;

        let empty = domains.is_empty()
            && suffixes.is_empty()
            && keywords.is_none()
            && regexes.is_none()
            && cidrs.is_empty()
            && geoip_codes.is_empty()
            && geosite_codes.is_empty()
            && processes.is_empty()
            && ports.is_empty()
            && network.is_none();

        Ok(Self {
            domains,
            suffixes,
            keywords,
            regexes,
            cidrs,
            geoip_codes,
            geoip_table,
            geosite_codes,
            processes,
            ports,
            network,
            empty,
        })
    }

    fn matches(&self, meta: &Meta, domain: Option<&str>, assets: &RouterAssets) -> bool {
        if self.empty {
            return false;
        }

        if let Some(domain) = domain {
            if self.domains.contains(domain)
                || suffix_matches(domain, &self.suffixes)
                || self
                    .keywords
                    .as_ref()
                    .is_some_and(|keywords| keywords.is_match(domain))
                || self
                    .regexes
                    .as_ref()
                    .is_some_and(|regexes| regexes.is_match(domain))
                || self
                    .geosite_codes
                    .iter()
                    .any(|code| assets.geosite_matches(code, domain))
            {
                return true;
            }
        }

        if let Some(ip) = meta.ip {
            if self.cidrs.longest_match(ip).is_some() {
                return true;
            }

            if !self.geoip_codes.is_empty() {
                if let Some(country) = assets.country_of(ip) {
                    if self.geoip_codes.iter().any(|code| code == &country) {
                        return true;
                    }
                }

                if self.geoip_table.longest_match(ip).is_some() {
                    return true;
                }
            }
        }

        if let Some(process) = &meta.process {
            let process = process.to_ascii_lowercase();
            if self.processes.contains(&process) {
                return true;
            }
        }

        if !self.ports.is_empty() {
            let port = meta.port;
            if self
                .ports
                .iter()
                .any(|(start, end)| (*start..=*end).contains(&port))
            {
                return true;
            }
        }

        if let Some(network) = self.network {
            if meta.network == Some(network) {
                return true;
            }
        }

        false
    }
}

struct CompiledRule {
    name: String,
    action: Action,
    matcher: MatcherSet,
    all: Vec<MatcherSet>,
    not: Option<MatcherSet>,
}

impl CompiledRule {
    fn compile(rule: &RuleCfg, index: usize, assets: &RouterAssets) -> Result<Self> {
        let action = Action::parse(&rule.action)?;
        let name = if rule.name.trim().is_empty() {
            format!("rule #{index}")
        } else {
            rule.name.clone()
        };

        let matcher = MatcherSet::compile(&rule.matcher, assets)?;
        let all = rule
            .all
            .iter()
            .map(|item| MatcherSet::compile(item, assets))
            .collect::<Result<Vec<_>>>()?;
        let not = rule
            .not
            .as_ref()
            .map(|item| MatcherSet::compile(item, assets))
            .transpose()?;

        Ok(Self {
            name,
            action,
            matcher,
            all,
            not,
        })
    }

    fn matches(&self, meta: &Meta, domain: Option<&str>, assets: &RouterAssets) -> bool {
        if self.matcher.empty && self.all.is_empty() {
            return false;
        }

        let primary = self.matcher.empty || self.matcher.matches(meta, domain, assets);
        if !primary {
            return false;
        }

        if !self
            .all
            .iter()
            .all(|matcher| matcher.empty || matcher.matches(meta, domain, assets))
        {
            return false;
        }

        match &self.not {
            Some(matcher) => !matcher.matches(meta, domain, assets),
            None => true,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    domain: Option<String>,
    ip: Option<IpAddr>,
    port: u16,
    process: Option<String>,
    network: u8,
}

impl CacheKey {
    fn new(meta: &Meta, domain: Option<String>) -> Self {
        Self {
            domain,
            ip: meta.ip,
            port: meta.port,
            process: meta
                .process
                .as_ref()
                .map(|value| value.to_ascii_lowercase()),
            network: match meta.network {
                Some(Network::Tcp) => 1,
                Some(Network::Udp) => 2,
                None => 0,
            },
        }
    }
}

/// Готовый роутер: правила + кэш решений.
pub struct CompiledRouter {
    rules: Vec<CompiledRule>,
    final_action: Action,
    cache: Cache<CacheKey, RouteDecision>,
    assets: Arc<RouterAssets>,
}

impl CompiledRouter {
    /// Компилирует правила из пресета.
    pub fn from_preset(name: &str) -> Result<Self> {
        Self::from_preset_with_assets(name, Arc::new(RouterAssets::default()))
    }

    pub fn from_preset_with_assets(name: &str, assets: Arc<RouterAssets>) -> Result<Self> {
        let preset = load_preset(name)?;
        Self::build(&preset.rules, &preset.final_action, assets)
    }

    /// Берёт пресет и добавляет пользовательские правила в начало.
    pub fn from_settings(routing: &Routing, assets: Arc<RouterAssets>) -> Result<Self> {
        let preset = load_preset(&routing.preset)?;

        let mut rules = routing.rules.clone();
        rules.extend(preset.rules);

        Self::build(&rules, &preset.final_action, assets)
    }

    pub fn from_settings_without_assets(routing: &Routing) -> Result<Self> {
        Self::from_settings(routing, Arc::new(RouterAssets::default()))
    }

    fn build(rules: &[RuleCfg], final_action: &str, assets: Arc<RouterAssets>) -> Result<Self> {
        let compiled = rules
            .iter()
            .enumerate()
            .map(|(index, rule)| CompiledRule::compile(rule, index, &assets))
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            rules: compiled,
            final_action: Action::parse(final_action)?,
            cache: Cache::new(CACHE_CAPACITY),
            assets,
        })
    }

    pub fn route(&self, meta: &Meta) -> RouteDecision {
        let domain = meta.domain.as_deref().map(normalize_domain);
        let key = CacheKey::new(meta, domain.clone());

        if let Some(decision) = self.cache.get(&key) {
            return decision;
        }

        let decision = self.route_uncached(meta, domain.as_deref());
        self.cache.insert(key, decision.clone());
        decision
    }

    fn route_uncached(&self, meta: &Meta, domain: Option<&str>) -> RouteDecision {
        for (index, rule) in self.rules.iter().enumerate() {
            if rule.matches(meta, domain, &self.assets) {
                return RouteDecision {
                    action: rule.action,
                    rule_idx: Some(index),
                    rule_name: rule.name.clone(),
                };
            }
        }

        RouteDecision::final_action(self.final_action)
    }

    /// Человекочитаемое объяснение решения для UI.
    pub fn explain(&self, meta: &Meta) -> String {
        self.route(meta).explain()
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn final_action(&self) -> Action {
        self.final_action
    }
}

/// Атомарно подменяемый роутер для фонового обновления списков.
pub struct HotRouter {
    inner: ArcSwap<CompiledRouter>,
}

impl HotRouter {
    pub fn new(router: CompiledRouter) -> Self {
        Self {
            inner: ArcSwap::from_pointee(router),
        }
    }

    pub fn replace(&self, router: Arc<CompiledRouter>) {
        self.inner.store(router);
    }

    pub fn current(&self) -> Arc<CompiledRouter> {
        self.inner.load_full()
    }

    pub fn route(&self, meta: &Meta) -> RouteDecision {
        self.inner.load().route(meta)
    }

    pub fn explain(&self, meta: &Meta) -> String {
        self.inner.load().explain(meta)
    }
}

fn load_preset(name: &str) -> Result<Preset> {
    let text = match name {
        "smart_ru" => include_str!("../presets/smart_ru.toml"),
        "blocked_only" => include_str!("../presets/blocked_only.toml"),
        "all_vpn" => include_str!("../presets/all_vpn.toml"),
        other => return Err(RouterError::UnknownPreset(other.to_string())),
    };

    Ok(toml::from_str(text)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn router() -> CompiledRouter {
        let routing = Routing {
            preset: "smart_ru".to_string(),
            rules: vec![RuleCfg {
                name: "adblock".to_string(),
                matcher: MatchCfg {
                    domain_keyword: vec!["ads".to_string()],
                    ..MatchCfg::default()
                },
                action: "block".to_string(),
                ..RuleCfg::default()
            }],
        };

        CompiledRouter::from_settings_without_assets(&routing).expect("router")
    }

    fn meta(domain: &str) -> Meta {
        Meta::new(443).with_domain(domain)
    }

    #[test]
    fn user_rule_has_priority_and_keyword_matches() {
        let decision = router().route(&meta("ads.example.com"));
        assert_eq!(decision.action, Action::Block);
        assert_eq!(decision.rule_idx, Some(0));
        assert_eq!(decision.rule_name, "adblock");
    }

    #[test]
    fn suffix_rule_matches_ru_and_punycode() {
        let router = router();

        assert_eq!(router.route(&meta("example.ru")).action, Action::Direct);
        assert_eq!(router.route(&meta("пример.рф")).action, Action::Direct);
        assert_eq!(
            router.route(&meta("notexample.com")).action,
            Action::Psiphon
        );
    }

    #[test]
    fn cidr_rule_matches_private_network() {
        let router = router();
        let meta = Meta::new(80).with_ip("10.1.2.3".parse().expect("ip"));

        assert_eq!(router.route(&meta).action, Action::Direct);
    }

    #[test]
    fn geoip_rule_requires_database_and_falls_through() {
        let router = router();
        let meta = Meta::new(80).with_ip("8.8.8.8".parse().expect("ip"));

        assert_eq!(router.route(&meta).action, Action::Psiphon);
    }

    #[test]
    fn final_action_is_used_when_nothing_matches() {
        let router = CompiledRouter::from_preset("blocked_only").expect("preset");
        let decision = router.route(&meta("example.com"));

        assert_eq!(decision.action, Action::Direct);
        assert!(decision.rule_idx.is_none());
        assert!(decision.explain().contains("final"));
    }

    #[test]
    fn blocked_only_sends_youtube_to_dpi() {
        let router = CompiledRouter::from_preset("blocked_only").expect("preset");
        assert_eq!(router.route(&meta("www.youtube.com")).action, Action::Dpi);
        assert_eq!(router.route(&meta("discord.com")).action, Action::Dpi);
    }

    #[test]
    fn cache_returns_same_decision() {
        let router = router();
        let first = router.route(&meta("ads.example.com"));
        let second = router.route(&meta("ads.example.com"));
        assert_eq!(first, second);
    }

    #[test]
    fn hot_router_swaps_atomically() {
        let hot = HotRouter::new(router());
        assert_eq!(hot.route(&meta("ads.example.com")).action, Action::Block);

        hot.replace(Arc::new(
            CompiledRouter::from_preset("all_vpn").expect("preset"),
        ));

        assert_eq!(hot.route(&meta("ads.example.com")).action, Action::Psiphon);
    }
}
