use std::net::SocketAddr;

use bytes::{BufMut, Bytes, BytesMut};
use uuid::Uuid;

use psi_core::Target;

use crate::error::{Result, VlessError};

pub const VERSION: u8 = 0x00;
pub const CMD_TCP: u8 = 0x01;

pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x02;
pub const ATYP_IPV6: u8 = 0x03;

/// VLESS-заголовок запроса:
/// `[version][uuid 16][addons_len][cmd][port u16][atyp][addr]`.
pub fn build_request_header(uuid: &Uuid, target: &Target) -> Result<Bytes> {
    build_header(uuid, CMD_TCP, target)
}

pub fn build_header(uuid: &Uuid, cmd: u8, target: &Target) -> Result<Bytes> {
    let mut buffer = BytesMut::with_capacity(32);

    buffer.put_u8(VERSION);
    buffer.put_slice(uuid.as_bytes());
    buffer.put_u8(0); // addons_len
    buffer.put_u8(cmd);
    buffer.put_u16(target.port());

    match target {
        Target::Ip(SocketAddr::V4(addr)) => {
            buffer.put_u8(ATYP_IPV4);
            buffer.put_slice(&addr.ip().octets());
        }
        Target::Ip(SocketAddr::V6(addr)) => {
            buffer.put_u8(ATYP_IPV6);
            buffer.put_slice(&addr.ip().octets());
        }
        Target::Domain(host, _) => {
            let bytes = host.as_bytes();
            if bytes.len() > u8::MAX as usize {
                return Err(VlessError::Other(
                    "VLESS: домен длиннее 255 байт".to_string(),
                ));
            }
            buffer.put_u8(ATYP_DOMAIN);
            buffer.put_u8(bytes.len() as u8);
            buffer.put_slice(bytes);
        }
    }

    Ok(buffer.freeze())
}

/// Парсит адрес из VLESS-заголовка (после `cmd` и порта).
pub fn parse_address(atyp: u8, data: &[u8]) -> Result<(Target, usize)> {
    match atyp {
        ATYP_IPV4 => {
            if data.len() < 4 {
                return Err(VlessError::Other("VLESS: короткий IPv4".to_string()));
            }
            let ip = std::net::Ipv4Addr::new(data[0], data[1], data[2], data[3]);
            Ok((Target::Ip(SocketAddr::new(ip.into(), 0)), 4))
        }
        ATYP_IPV6 => {
            if data.len() < 16 {
                return Err(VlessError::Other("VLESS: короткий IPv6".to_string()));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[..16]);
            let ip = std::net::Ipv6Addr::from(octets);
            Ok((Target::Ip(SocketAddr::new(ip.into(), 0)), 16))
        }
        ATYP_DOMAIN => {
            if data.is_empty() {
                return Err(VlessError::Other("VLESS: пустой домен".to_string()));
            }
            let len = data[0] as usize;
            if data.len() < 1 + len {
                return Err(VlessError::Other("VLESS: короткий домен".to_string()));
            }
            let host = std::str::from_utf8(&data[1..1 + len])
                .map_err(|_| VlessError::Other("VLESS: домен не в UTF-8".to_string()))?;
            Ok((Target::Domain(host.to_string(), 0), 1 + len))
        }
        other => Err(VlessError::Other(format!(
            "VLESS: неизвестный ATYP {other:#x}"
        ))),
    }
}

/// Состояние разбора ответного заголовка `[version][addons_len][addons]`.
#[derive(Debug, Default)]
pub struct ResponseHeaderParser {
    buffer: Vec<u8>,
    done: bool,
}

impl ResponseHeaderParser {
    /// Добавляет данные; возвращает payload, как только заголовок полностью разобран.
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if self.done {
            return Ok(data.to_vec());
        }

        self.buffer.extend_from_slice(data);

        if self.buffer.len() < 2 {
            return Ok(Vec::new());
        }

        if self.buffer[0] != VERSION {
            return Err(VlessError::Other(format!(
                "VLESS: неверная версия ответа {:#x}",
                self.buffer[0]
            )));
        }

        let addons_len = self.buffer[1] as usize;
        let header_len = 2 + addons_len;

        if self.buffer.len() < header_len {
            return Ok(Vec::new());
        }

        self.done = true;
        let payload = self.buffer.split_off(header_len);
        self.buffer.clear();
        Ok(payload)
    }

    pub fn is_done(&self) -> bool {
        self.done
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    #[test]
    fn serializes_domain_header() {
        let uuid = Uuid::parse_str(UUID).expect("uuid");
        let target = Target::Domain("example.com".to_string(), 443);

        let header = build_request_header(&uuid, &target).expect("header");
        let mut expected = Vec::new();
        expected.push(0x00);
        expected.extend_from_slice(uuid.as_bytes());
        expected.push(0x00);
        expected.push(CMD_TCP);
        expected.extend_from_slice(&443u16.to_be_bytes());
        expected.push(ATYP_DOMAIN);
        expected.push(11);
        expected.extend_from_slice(b"example.com");

        assert_eq!(&header[..], &expected[..]);
    }

    #[test]
    fn serializes_ipv4_header() {
        let uuid = Uuid::parse_str(UUID).expect("uuid");
        let target = Target::Ip("1.2.3.4:8443".parse().expect("addr"));

        let header = build_request_header(&uuid, &target).expect("header");
        let mut expected = Vec::new();
        expected.push(0x00);
        expected.extend_from_slice(uuid.as_bytes());
        expected.push(0x00);
        expected.push(CMD_TCP);
        expected.extend_from_slice(&8443u16.to_be_bytes());
        expected.push(ATYP_IPV4);
        expected.extend_from_slice(&[1, 2, 3, 4]);

        assert_eq!(&header[..], &expected[..]);
    }

    #[test]
    fn strips_response_header_across_chunks() {
        let mut parser = ResponseHeaderParser::default();
        assert!(parser.push(&[0x00]).expect("chunk").is_empty());
        let payload = parser
            .push(&[0x02, 0xaa, 0xbb, b'h', b'i'])
            .expect("chunk");
        assert_eq!(payload, b"hi");
        assert!(parser.is_done());
        assert_eq!(parser.push(b"more").expect("more"), b"more");
    }
}
