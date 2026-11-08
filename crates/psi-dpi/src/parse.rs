/// Результат анализа первого клиентского пакета.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadKind {
    Tls {
        sni_offset: usize,
        sni_len: usize,
        record_len: usize,
    },
    Http {
        host_offset: usize,
        host_len: usize,
    },
    Other,
}

impl PayloadKind {
    pub fn split_point(&self, payload_len: usize) -> usize {
        match self {
            Self::Tls {
                sni_offset,
                sni_len,
                ..
            } => sni_offset + sni_len / 2,
            Self::Http {
                host_offset,
                host_len,
            } => host_offset + host_len / 2,
            Self::Other => (payload_len / 2).max(1),
        }
    }
}

pub fn analyze(payload: &[u8]) -> PayloadKind {
    if payload.first() == Some(&0x16) {
        if let Some((sni_offset, sni_len)) = find_tls_sni(payload) {
            let record_len = record_length(payload).unwrap_or(payload.len());
            return PayloadKind::Tls {
                sni_offset,
                sni_len,
                record_len,
            };
        }
    }

    if looks_like_http(payload) {
        if let Some((host_offset, host_len)) = find_http_host(payload) {
            return PayloadKind::Http {
                host_offset,
                host_len,
            };
        }
    }

    PayloadKind::Other
}

fn record_length(payload: &[u8]) -> Option<usize> {
    if payload.len() < 5 {
        return None;
    }
    Some(u16::from_be_bytes([payload[3], payload[4]]) as usize)
}

/// Ищет смещение и длину имени в SNI (extension type 0x0000).
pub fn find_tls_sni(payload: &[u8]) -> Option<(usize, usize)> {
    if payload.len() < 5 + 4 || payload[0] != 0x16 || payload[5] != 0x01 {
        return None;
    }

    let record_len = record_length(payload)?;
    let record_end = (5 + record_len).min(payload.len());

    let mut position = 5 + 4 + 2 + 32;
    if position >= record_end {
        return None;
    }

    let session_len = *payload.get(position)? as usize;
    position += 1 + session_len;

    let cipher_len = read_u16(payload, position)? as usize;
    position += 2 + cipher_len;

    let compression_len = *payload.get(position)? as usize;
    position += 1 + compression_len;

    let extensions_len = read_u16(payload, position)? as usize;
    position += 2;

    let extensions_end = (position + extensions_len).min(record_end);

    while position + 4 <= extensions_end {
        let extension_type = read_u16(payload, position)?;
        let extension_len = read_u16(payload, position + 2)? as usize;
        position += 4;

        if position + extension_len > extensions_end {
            return None;
        }

        if extension_type == 0x0000 {
            let data = &payload[position..position + extension_len];
            if data.len() < 2 {
                return None;
            }

            let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
            let list_end = (2 + list_len).min(data.len());
            let mut cursor = 2;

            while cursor + 3 <= list_end {
                let name_type = data[cursor];
                let name_len = u16::from_be_bytes([data[cursor + 1], data[cursor + 2]]) as usize;
                cursor += 3;

                if cursor + name_len > list_end {
                    return None;
                }

                if name_type == 0 {
                    return Some((position + cursor, name_len));
                }

                cursor += name_len;
            }
        }

        position += extension_len;
    }

    None
}

/// Ищет `Host:` в первых заголовках и возвращает `(смещение значения, длина)`.
pub fn find_http_host(payload: &[u8]) -> Option<(usize, usize)> {
    let host = find_http_host_full(payload)?;
    Some((host.value_start, host.value_len))
}

struct HttpHost {
    name_start: usize,
    value_start: usize,
    value_len: usize,
}

fn find_http_host_full(payload: &[u8]) -> Option<HttpHost> {
    let limit = header_end(payload).min(payload.len());

    let mut index = 0;
    while index + 5 <= limit {
        let is_line_start = index == 0 || payload[index - 1] == b'\n';
        if is_line_start && payload[index..index + 5].eq_ignore_ascii_case(b"host:") {
            let mut value_start = index + 5;
            while value_start < limit
                && (payload[value_start] == b' ' || payload[value_start] == b'\t')
            {
                value_start += 1;
            }

            let mut value_end = value_start;
            while value_end < limit && payload[value_end] != b'\r' && payload[value_end] != b'\n' {
                value_end += 1;
            }

            if value_end > value_start {
                return Some(HttpHost {
                    name_start: index,
                    value_start,
                    value_len: value_end - value_start,
                });
            }
        }
        index += 1;
    }

    None
}

fn header_end(payload: &[u8]) -> usize {
    match payload.windows(4).position(|window| window == b"\r\n\r\n") {
        Some(position) => position + 4,
        None => payload.len(),
    }
}

fn looks_like_http(payload: &[u8]) -> bool {
    const METHODS: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"HEAD ",
        b"PUT ",
        b"DELETE ",
        b"OPTIONS ",
        b"CONNECT ",
        b"PATCH ",
    ];

    METHODS
        .iter()
        .any(|method| payload.starts_with(method))
        || payload
            .windows(9)
            .any(|window| window.eq_ignore_ascii_case(b" HTTP/1."))
}

/// Переписывает `Host:` → `hOsT:` и пробел после двоеточия → табуляцию.
/// Длина не меняется, поэтому смещения SNI/Host остаются валидными.
pub fn rewrite_http_host(payload: &[u8]) -> Vec<u8> {
    let mut output = payload.to_vec();

    if let Some(host) = find_http_host_full(&output) {
        output[host.name_start..host.name_start + 4].copy_from_slice(b"hOsT");
        let colon = host.name_start + 4;
        if output.get(colon) == Some(&b':') && output.get(colon + 1) == Some(&b' ') {
            output[colon + 1] = b'\t';
        }
    }

    output
}

/// Разрезает TLS ClientHello на две валидные TLS-записи.
///
/// `body_split` — смещение разреза внутри тела записи (без 5-байтового заголовка).
pub fn tlsrec_split(payload: &[u8], body_split: usize) -> Option<(Vec<u8>, Vec<u8>)> {
    if payload.len() < 5 || payload[0] != 0x16 {
        return None;
    }

    let record_len = record_length(payload)?;
    let body_end = (5 + record_len).min(payload.len());
    let body = payload.get(5..body_end)?;

    if body_split == 0 || body_split >= body.len() {
        return None;
    }

    let version = [payload[1], payload[2]];
    let first = wrap_record(version, &body[..body_split]);
    let second = wrap_record(version, &body[body_split..]);

    Some((first, second))
}

fn wrap_record(version: [u8; 2], body: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(5 + body.len());
    record.push(0x16);
    record.extend_from_slice(&version);
    record.extend_from_slice(&(body.len() as u16).to_be_bytes());
    record.extend_from_slice(body);
    record
}

fn read_u16(buffer: &[u8], offset: usize) -> Option<u16> {
    let bytes = buffer.get(offset..offset + 2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hello(host: &str) -> Vec<u8> {
        let host = host.as_bytes();

        let mut sni_extension = Vec::new();
        sni_extension.extend_from_slice(&[0x00, 0x00]);
        let list_len = 3 + host.len();
        sni_extension.extend_from_slice(&((list_len + 2) as u16).to_be_bytes());
        sni_extension.extend_from_slice(&(list_len as u16).to_be_bytes());
        sni_extension.push(0x00);
        sni_extension.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni_extension.extend_from_slice(host);

        let mut handshake = Vec::new();
        handshake.push(0x01);
        handshake.extend_from_slice(&[0x00, 0x00, 0x00]); // длина заполнится ниже
        handshake.extend_from_slice(&[0x03, 0x03]);
        handshake.extend_from_slice(&[0x11; 32]);
        handshake.push(0x00);
        handshake.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        handshake.extend_from_slice(&[0x01, 0x00]);
        handshake.extend_from_slice(&(sni_extension.len() as u16).to_be_bytes());
        handshake.extend_from_slice(&sni_extension);

        let handshake_len = (handshake.len() - 4) as u32;
        handshake[1] = (handshake_len >> 16) as u8;
        handshake[2] = (handshake_len >> 8) as u8;
        handshake[3] = handshake_len as u8;

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn finds_sni_offset() {
        let hello = client_hello("www.youtube.com");
        let (offset, len) = find_tls_sni(&hello).expect("SNI");
        assert_eq!(&hello[offset..offset + len], b"www.youtube.com");
    }

    #[test]
    fn tlsrec_produces_two_valid_records() {
        let hello = client_hello("www.youtube.com");
        let (offset, len) = find_tls_sni(&hello).expect("SNI");
        let split = offset + len / 2 - 5;

        let (first, second) = tlsrec_split(&hello, split).expect("tlsrec");

        assert_eq!(first[0], 0x16);
        assert_eq!(second[0], 0x16);
        assert_eq!(
            u16::from_be_bytes([first[3], first[4]]) as usize,
            first.len() - 5
        );
        assert_eq!(
            u16::from_be_bytes([second[3], second[4]]) as usize,
            second.len() - 5
        );

        let mut joined = Vec::new();
        joined.extend_from_slice(&first[5..]);
        joined.extend_from_slice(&second[5..]);
        assert_eq!(joined, hello[5..]);
    }

    #[test]
    fn parses_http_host() {
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (offset, len) = find_http_host(request).expect("Host");
        assert_eq!(&request[offset..offset + len], b"example.com");
    }

    #[test]
    fn rewrites_http_host_without_changing_length() {
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let rewritten = rewrite_http_host(request);
        assert_eq!(rewritten.len(), request.len());
        assert!(rewritten.starts_with(b"GET / HTTP/1.1\r\nhOsT:\texample.com"));
    }
}
