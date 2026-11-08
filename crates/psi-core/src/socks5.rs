use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::{BoxStream, CoreError, Result, Target};

/// Открывает TCP-туннель через SOCKS5-прокси (no-auth, CONNECT).
///
/// Используется для Psiphon, VLESS-WARP и других локальных сайдкаров.
pub async fn socks5_connect(proxy: SocketAddr, target: &Target) -> Result<BoxStream> {
    let mut stream = TcpStream::connect(proxy).await?;
    stream.set_nodelay(true)?;

    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    if method != [0x05, 0x00] {
        return Err(CoreError::Protocol(format!(
            "SOCKS5: прокси отклонил no-auth ({} {:?})",
            method[0], method[1]
        )));
    }

    let request = build_request(target)?;
    stream.write_all(&request).await?;

    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 0x05 {
        return Err(CoreError::Protocol(format!(
            "SOCKS5: неверная версия ответа {:#x}",
            reply[0]
        )));
    }
    if reply[1] != 0x00 {
        return Err(CoreError::Protocol(format!(
            "SOCKS5: прокси вернул код ошибки {:#x}",
            reply[1]
        )));
    }

    match reply[3] {
        0x01 => {
            let mut rest = [0u8; 6];
            stream.read_exact(&mut rest).await?;
        }
        0x04 => {
            let mut rest = [0u8; 18];
            stream.read_exact(&mut rest).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut rest = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut rest).await?;
        }
        atyp => {
            return Err(CoreError::Protocol(format!(
                "SOCKS5: неизвестный ATYP в ответе {atyp:#x}"
            )));
        }
    }

    Ok(Box::new(stream))
}

fn build_request(target: &Target) -> Result<Vec<u8>> {
    let mut request = Vec::with_capacity(22);
    request.extend_from_slice(&[0x05, 0x01, 0x00]);

    match target {
        Target::Ip(SocketAddr::V4(addr)) => {
            request.push(0x01);
            request.extend_from_slice(&addr.ip().octets());
            request.extend_from_slice(&addr.port().to_be_bytes());
        }
        Target::Ip(SocketAddr::V6(addr)) => {
            request.push(0x04);
            request.extend_from_slice(&addr.ip().octets());
            request.extend_from_slice(&addr.port().to_be_bytes());
        }
        Target::Domain(host, port) => {
            let bytes = host.as_bytes();
            if bytes.len() > u8::MAX as usize {
                return Err(CoreError::Protocol(
                    "SOCKS5: домен длиннее 255 байт".to_string(),
                ));
            }
            request.push(0x03);
            request.push(bytes.len() as u8);
            request.extend_from_slice(bytes);
            request.extend_from_slice(&port.to_be_bytes());
        }
    }

    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn performs_socks5_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy = listener.local_addr().expect("addr");

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");

            let mut greeting = [0u8; 3];
            socket.read_exact(&mut greeting).await.expect("greeting");
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            socket.write_all(&[0x05, 0x00]).await.expect("method");

            let mut head = [0u8; 4];
            socket.read_exact(&mut head).await.expect("head");
            assert_eq!(head, [0x05, 0x01, 0x00, 0x03]);

            let mut len = [0u8; 1];
            socket.read_exact(&mut len).await.expect("len");
            let mut host = vec![0u8; len[0] as usize];
            socket.read_exact(&mut host).await.expect("host");
            let mut port = [0u8; 2];
            socket.read_exact(&mut port).await.expect("port");

            assert_eq!(host, b"example.com");
            assert_eq!(u16::from_be_bytes(port), 443);

            socket
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .expect("reply");
            socket.write_all(b"ok").await.expect("payload");
        });

        let mut stream = socks5_connect(proxy, &Target::Domain("example.com".to_string(), 443))
            .await
            .expect("connect");

        let mut payload = [0u8; 2];
        stream.read_exact(&mut payload).await.expect("payload");
        assert_eq!(&payload, b"ok");

        server.await.expect("server");
    }

    #[test]
    fn builds_domain_request() {
        let request = build_request(&Target::Domain("a.ru".to_string(), 80)).expect("request");
        assert_eq!(request, vec![0x05, 0x01, 0x00, 0x03, 4, b'a', b'.', b'r', b'u', 0, 80]);
    }
}
