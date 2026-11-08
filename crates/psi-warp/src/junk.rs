use rand::Rng;

use crate::error::{Result, WarpError};

const MAX_JUNK_LEN: usize = 1400;

/// AmneziaWG-обфускация: junk-пакеты перед handshake + сигнатурные блобы i1..i5.
#[derive(Debug, Clone)]
pub struct JunkConfig {
    pub jc: u8,
    pub jmin: u16,
    pub jmax: u16,
    pub signatures: Vec<Vec<u8>>,
}

impl Default for JunkConfig {
    fn default() -> Self {
        Self {
            jc: 0,
            jmin: 40,
            jmax: 70,
            signatures: Vec::new(),
        }
    }
}

impl JunkConfig {
    pub fn from_awg(awg: &psi_config::Awg) -> Result<Self> {
        let mut signatures = Vec::new();
        if let Some(i1) = &awg.i1 {
            if !i1.trim().is_empty() {
                signatures.push(parse_hex(i1)?);
            }
        }

        Ok(Self {
            jc: awg.jc,
            jmin: awg.jmin,
            jmax: awg.jmax,
            signatures,
        })
    }

    /// Сигнатурные пакеты идут первыми, затем `jc` случайных пакетов длиной `jmin..=jmax`.
    pub fn packets(&self, rng: &mut impl Rng) -> Vec<Vec<u8>> {
        let mut packets = self.signatures.clone();

        if self.jc == 0 {
            return packets;
        }

        let (low, high) = if self.jmin <= self.jmax {
            (self.jmin.max(1), self.jmax)
        } else {
            (self.jmax.max(1), self.jmin)
        };
        let high = high.min(MAX_JUNK_LEN as u16).max(low);

        for _ in 0..self.jc {
            let length = rng.gen_range(low..=high) as usize;
            let mut packet = vec![0u8; length];
            rng.fill(&mut packet[..]);
            packets.push(packet);
        }

        packets
    }
}

pub fn parse_hex(text: &str) -> Result<Vec<u8>> {
    let trimmed = text.trim();
    let digits = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed)
        .replace([' ', ':', '-'], "");

    if digits.len() % 2 != 0 {
        return Err(WarpError::Profile(format!(
            "нечётная длина hex-блоба: {trimmed}"
        )));
    }

    let mut bytes = Vec::with_capacity(digits.len() / 2);
    let chars: Vec<char> = digits.chars().collect();
    for pair in chars.chunks(2) {
        let text: String = pair.iter().collect();
        let byte = u8::from_str_radix(&text, 16)
            .map_err(|error| WarpError::Profile(format!("hex: {error}")))?;
        bytes.push(byte);
    }

    if bytes.len() > MAX_JUNK_LEN {
        return Err(WarpError::Profile("сигнатурный блоб слишком длинный".to_string()));
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn junk_lengths_are_within_range() {
        let config = JunkConfig {
            jc: 8,
            jmin: 40,
            jmax: 70,
            signatures: Vec::new(),
        };
        let mut rng = StdRng::seed_from_u64(7);
        let packets = config.packets(&mut rng);

        assert_eq!(packets.len(), 8);
        for packet in packets {
            assert!((40..=70).contains(&packet.len()));
        }
    }

    #[test]
    fn signatures_prepend_junk() {
        let config = JunkConfig {
            jc: 1,
            jmin: 10,
            jmax: 10,
            signatures: vec![vec![1, 2, 3]],
        };
        let mut rng = StdRng::seed_from_u64(1);
        let packets = config.packets(&mut rng);

        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0], vec![1, 2, 3]);
        assert_eq!(packets[1].len(), 10);
    }

    #[test]
    fn parses_hex_blob() {
        assert_eq!(parse_hex("0x01 0a:ff").expect("hex"), vec![1, 10, 255]);
    }
}
