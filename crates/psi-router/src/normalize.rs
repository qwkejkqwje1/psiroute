use std::collections::HashSet;

use crate::error::{Result, RouterError};

/// Приводит домен к нижнему регистру и punycode (`.рф` → `.xn--p1ai`).
pub fn normalize_domain(input: &str) -> String {
    let trimmed = input
        .trim()
        .trim_end_matches('.')
        .trim_start_matches('.')
        .to_ascii_lowercase();

    match idna::domain_to_ascii(&trimmed) {
        Ok(ascii) => ascii.to_ascii_lowercase(),
        Err(_) => trimmed,
    }
}

/// Нормализует суффикс, убирая ведущие `.` и `*.`.
pub fn normalize_suffix(input: &str) -> String {
    let value = input.trim();
    let value = value.strip_prefix("*.").unwrap_or(value);
    normalize_domain(value)
}

/// Проверка суффикса по меткам справа налево: `example.ru` не матчит `notexample.ru`.
pub fn suffix_matches(domain: &str, suffixes: &HashSet<String>) -> bool {
    if suffixes.is_empty() {
        return false;
    }

    let mut rest = domain;
    loop {
        if suffixes.contains(rest) {
            return true;
        }
        match rest.find('.') {
            Some(index) => rest = &rest[index + 1..],
            None => return false,
        }
    }
}

/// Разбирает `"443,8000-9000"` в список диапазонов.
pub fn parse_ports(spec: &str) -> Result<Vec<(u16, u16)>> {
    let mut ranges = Vec::new();

    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        let range = match part.split_once('-') {
            Some((start, end)) => {
                let start = parse_port(start)?;
                let end = parse_port(end)?;
                if start > end {
                    return Err(RouterError::InvalidPort(part.to_string()));
                }
                (start, end)
            }
            None => {
                let port = parse_port(part)?;
                (port, port)
            }
        };

        ranges.push(range);
    }

    Ok(ranges)
}

fn parse_port(value: &str) -> Result<u16> {
    value
        .trim()
        .parse::<u16>()
        .map_err(|_| RouterError::InvalidPort(value.to_string()))
}

/// Определяет домен из первого пакета: TLS SNI или HTTP Host.
pub fn sniff_domain(payload: &[u8]) -> Option<String> {
    match psi_dpi::analyze(payload) {
        psi_dpi::PayloadKind::Tls { .. } => {
            let (offset, len) = psi_dpi::find_tls_sni(payload)?;
            domain_at(payload, offset, len)
        }
        psi_dpi::PayloadKind::Http { .. } => {
            let (offset, len) = psi_dpi::find_http_host(payload)?;
            domain_at(payload, offset, len)
        }
        psi_dpi::PayloadKind::Other => None,
    }
}

fn domain_at(payload: &[u8], offset: usize, len: usize) -> Option<String> {
    let bytes = payload.get(offset..offset + len)?;
    let value = std::str::from_utf8(bytes).ok()?;
    let domain = normalize_domain(value);
    (!domain.is_empty()).then_some(domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_punycode() {
        assert_eq!(normalize_domain("Пример.РФ"), "xn--e1afmkfd.xn--p1ai");
        assert_eq!(normalize_domain("EXAMPLE.com."), "example.com");
    }

    #[test]
    fn suffix_respects_label_boundary() {
        let suffixes = HashSet::from(["example.ru".to_string(), "рф".to_string()]);

        assert!(suffix_matches("www.example.ru", &suffixes));
        assert!(suffix_matches("example.ru", &suffixes));
        assert!(!suffix_matches("notexample.ru", &suffixes));
    }

    #[test]
    fn parses_port_ranges() {
        assert_eq!(
            parse_ports("443, 8000-8002").expect("ports"),
            vec![(443, 443), (8000, 8002)]
        );
        assert!(parse_ports("9000-8000").is_err());
        assert!(parse_ports("abc").is_err());
    }
}
