//! Дымовой тест «из коробки»: без параметров Psiphon и без VLESS подключение
//! должно поднимать прокси, а трафик действия proxy — идти через DPI/direct,
//! а не умирать об заглушку. Требует живой сети, поэтому #[ignore]:
//! запуск — `cargo test -p psi-engine --test smoke -- --ignored`.

use std::time::Duration;

use psi_config::Config;
use psi_engine::{Cmd, Engine};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test]
#[ignore = "нужна живая сеть"]
async fn out_of_box_proxy_works() {
    let dir = std::env::temp_dir().join("psi-engine-smoke");
    let mut cfg = Config::default();
    cfg.inbound.mixed_port = 17_890;
    cfg.inbound.system_proxy = false;

    let handle = Engine::start(cfg, dir);
    handle.send(Cmd::Connect).await;

    // inbound должен подняться
    let mut stream = None;
    for _ in 0..50 {
        if let Ok(s) = TcpStream::connect("127.0.0.1:17890").await {
            stream = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let mut stream = stream.expect("inbound 127.0.0.1:17890 не поднялся");

    // SOCKS5: без аутентификации, CONNECT example.com:80
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf, [0x05, 0x00], "socks greeting");
    let host = b"example.com";
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host);
    req.extend_from_slice(&80u16.to_be_bytes());
    stream.write_all(&req).await.unwrap();
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.unwrap();
    assert_eq!(head[1], 0x00, "SOCKS CONNECT должен пройти (rep=0), got {}", head[1]);
    // дочитать адрес ответа
    match head[3] {
        0x01 => {
            let mut rest = [0u8; 6];
            stream.read_exact(&mut rest).await.unwrap();
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.unwrap();
            let mut rest = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut rest).await.unwrap();
        }
        _ => {}
    }
    stream
        .write_all(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let mut page = Vec::new();
    let mut chunk = [0u8; 1024];
    let read = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => page.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
        }
    })
    .await;
    assert!(read.is_ok(), "чтение ответа зависло");
    // Ответ может подменить сетевой фильтр песочницы — важно, что туннель
    // в принципе пропустил запрос и вернул хоть какие-то байты ответа.
    assert!(
        !page.is_empty(),
        "пустой ответ: соединение через proxy-выход не состоялось"
    );

    handle.send(Cmd::Disconnect).await;
}
