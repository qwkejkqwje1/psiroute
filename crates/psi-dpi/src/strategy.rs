use crate::parse::{analyze, rewrite_http_host, tlsrec_split, PayloadKind};
use crate::Result;

/// Позиция разреза первого сегмента.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitAt {
    Fixed(usize),
    Sni,
    SniPlusOne,
}

/// Действие над первым клиентским пакетом. Действия комбинируются по порядку.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    Split(SplitAt),
    TlsRec(SplitAt),
    Disorder { at: SplitAt, ttl: u8 },
    Oob(SplitAt),
    HttpHost,
}

/// Набор стратегий (пресет).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrategyPlan {
    pub actions: Vec<Strategy>,
}

impl StrategyPlan {
    pub fn new(actions: Vec<Strategy>) -> Self {
        Self { actions }
    }

    /// Пресет по умолчанию: `tlsrec(sni)+split(sni)`.
    pub fn default_plan() -> Self {
        Self::new(vec![Strategy::TlsRec(SplitAt::Sni), Strategy::Split(SplitAt::Sni)])
    }

    pub fn tlsrec_split_sni() -> Self {
        Self::default_plan()
    }

    pub fn disorder_one() -> Self {
        Self::new(vec![Strategy::Disorder {
            at: SplitAt::Fixed(1),
            ttl: 1,
        }])
    }

    pub fn split_oob() -> Self {
        Self::new(vec![
            Strategy::Split(SplitAt::Fixed(1)),
            Strategy::Oob(SplitAt::Fixed(1)),
        ])
    }

    pub fn tlsrec_disorder_sni() -> Self {
        Self::new(vec![
            Strategy::TlsRec(SplitAt::Sni),
            Strategy::Disorder {
                at: SplitAt::Sni,
                ttl: 1,
            },
        ])
    }

    pub fn presets() -> Vec<Self> {
        vec![
            Self::tlsrec_split_sni(),
            Self::disorder_one(),
            Self::split_oob(),
            Self::tlsrec_disorder_sni(),
        ]
    }

    pub fn from_config(config: &psi_config::Dpi) -> Self {
        parse_plan(&config.strategy).unwrap_or_else(Self::default_plan)
    }

    /// Парсит строку вида `tlsrec(sni)+disorder(sni,1)`.
    pub fn parse(spec: &str) -> Option<Self> {
        parse_plan(spec)
    }

    fn resolved_position(&self, kind: &PayloadKind, payload_len: usize) -> usize {
        let at = self
            .actions
            .iter()
            .rev()
            .find_map(|action| match action {
                Strategy::Split(at) | Strategy::TlsRec(at) | Strategy::Oob(at) => Some(*at),
                Strategy::Disorder { at, .. } => Some(*at),
                Strategy::HttpHost => None,
            })
            .unwrap_or(SplitAt::Sni);

        resolve_position(at, kind, payload_len)
    }

    fn ttl(&self) -> Option<u8> {
        self.actions.iter().find_map(|action| match action {
            Strategy::Disorder { ttl, .. } => Some(*ttl),
            _ => None,
        })
    }

    fn has_oob(&self) -> bool {
        self.actions
            .iter()
            .any(|action| matches!(action, Strategy::Oob(_)))
    }

    fn has_tlsrec(&self) -> bool {
        self.actions
            .iter()
            .any(|action| matches!(action, Strategy::TlsRec(_)))
    }
}

impl Default for StrategyPlan {
    fn default() -> Self {
        Self::default_plan()
    }
}

/// Один сегмент первого полёта.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub data: Vec<u8>,
    pub ttl: Option<u8>,
    pub oob: bool,
    pub delay_ms: u64,
}

/// Разбиение первого пакета на сегменты.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FirstFlight {
    pub segments: Vec<Segment>,
}

/// Строит план отправки первого пакета.
pub fn build_first_flight(
    payload: &[u8],
    plan: &StrategyPlan,
) -> Result<FirstFlight> {
    let kind = analyze(payload);
    let rewritten;
    let payload = if matches!(kind, PayloadKind::Http { .. }) {
        rewritten = rewrite_http_host(payload);
        rewritten.as_slice()
    } else {
        payload
    };

    if payload.is_empty() {
        return Ok(FirstFlight::default());
    }

    let ttl = plan.ttl();
    let oob = plan.has_oob();
    let position = plan.resolved_position(&kind, payload.len());

    if plan.has_tlsrec() {
        if let PayloadKind::Tls { .. } = kind {
            let body_split = position.saturating_sub(5);
            if let Some((first, second)) = tlsrec_split(payload, body_split) {
                return Ok(FirstFlight {
                    segments: vec![
                        Segment {
                            data: first,
                            ttl,
                            oob: false,
                            delay_ms: 0,
                        },
                        Segment {
                            data: second,
                            ttl: None,
                            oob,
                            delay_ms: 1,
                        },
                    ],
                });
            }
        }
    }

    let position = position.clamp(1, payload.len().saturating_sub(1).max(1));
    let (first, rest) = payload.split_at(position);

    let mut segments = vec![Segment {
        data: first.to_vec(),
        ttl,
        oob,
        delay_ms: 0,
    }];

    if !rest.is_empty() {
        segments.push(Segment {
            data: rest.to_vec(),
            ttl: None,
            oob: false,
            delay_ms: 2,
        });
    }

    Ok(FirstFlight { segments })
}

fn resolve_position(at: SplitAt, kind: &PayloadKind, payload_len: usize) -> usize {
    let base = match at {
        SplitAt::Fixed(value) => value,
        SplitAt::Sni | SplitAt::SniPlusOne => kind.split_point(payload_len),
    };

    let position = match at {
        SplitAt::SniPlusOne => base.saturating_add(1),
        _ => base,
    };

    position.clamp(1, payload_len.saturating_sub(1).max(1))
}

fn parse_plan(spec: &str) -> Option<StrategyPlan> {
    let mut actions = Vec::new();

    for part in spec.split('+') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        let lower = part.to_ascii_lowercase();
        if lower == "oob" {
            actions.push(Strategy::Oob(SplitAt::Fixed(1)));
            continue;
        }
        if lower == "httphost" {
            actions.push(Strategy::HttpHost);
            continue;
        }

        let (name, argument) = match part.find('(') {
            Some(open) if part.ends_with(')') => {
                (&part[..open], Some(&part[open + 1..part.len() - 1]))
            }
            _ => (part, None),
        };

        match name.trim().to_ascii_lowercase().as_str() {
            "split" => {
                actions.push(Strategy::Split(parse_position(argument, SplitAt::Sni)?));
            }
            "tlsrec" => {
                actions.push(Strategy::TlsRec(parse_position(argument, SplitAt::Sni)?));
            }
            "disorder" => {
                let (at, ttl) = parse_disorder(argument);
                actions.push(Strategy::Disorder { at, ttl });
            }
            "oob" => {
                actions.push(Strategy::Oob(parse_position(argument, SplitAt::Fixed(1))?));
            }
            _ => return None,
        }
    }

    if actions.is_empty() {
        None
    } else {
        Some(StrategyPlan { actions })
    }
}

fn parse_position(argument: Option<&str>, default: SplitAt) -> Option<SplitAt> {
    let Some(argument) = argument else {
        return Some(default);
    };
    let value = argument.trim().to_ascii_lowercase();
    match value.as_str() {
        "sni" => Some(SplitAt::Sni),
        "sni+1" => Some(SplitAt::SniPlusOne),
        other => other.parse::<usize>().ok().map(SplitAt::Fixed),
    }
}

fn parse_disorder(argument: Option<&str>) -> (SplitAt, u8) {
    let Some(argument) = argument else {
        return (SplitAt::Fixed(1), 1);
    };

    let mut parts = argument.split(',');
    let at = parts
        .next()
        .and_then(|value| parse_position(Some(value), SplitAt::Fixed(1)))
        .unwrap_or(SplitAt::Fixed(1));
    let ttl = parts
        .next()
        .and_then(|value| value.trim().parse::<u8>().ok())
        .unwrap_or(1)
        .clamp(1, 3);

    (at, ttl)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_combined_plan() {
        let plan = StrategyPlan::parse("tlsrec(sni)+disorder(sni,2)").expect("plan");
        assert_eq!(
            plan.actions,
            vec![
                Strategy::TlsRec(SplitAt::Sni),
                Strategy::Disorder {
                    at: SplitAt::Sni,
                    ttl: 2
                }
            ]
        );
    }

    #[test]
    fn split_without_arguments_uses_sni() {
        let plan = StrategyPlan::parse("split").expect("plan");
        assert_eq!(plan.actions, vec![Strategy::Split(SplitAt::Sni)]);
    }

    #[test]
    fn builds_two_segments_for_plain_payload() {
        let plan = StrategyPlan::parse("split(4)").expect("plan");
        let flight = build_first_flight(b"abcdefgh", &plan).expect("flight");
        assert_eq!(flight.segments.len(), 2);
        assert_eq!(flight.segments[0].data, b"abcd");
        assert_eq!(flight.segments[1].data, b"efgh");
    }
}
