use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio_tungstenite::tungstenite::Message;

use psi_core::Target;

use crate::error::{Result, VlessError};
use crate::protocol::{build_request_header, ResponseHeaderParser};
use crate::tls::TlsClientStream;
use crate::uri::VlessSettings;
use crate::ws::handshake;

/// Ждёт первые байты приложения (≤50 мс), шлёт VLESS-заголовок + early-data
/// в `Sec-WebSocket-Protocol` (base64url) или отдельным первым фреймом.
pub(crate) async fn run_tunnel(
    app: DuplexStream,
    tls: TlsClientStream,
    settings: VlessSettings,
    target: Target,
) -> Result<()> {
    let mut app = app;
    let mut early = vec![0u8; settings.early_data.max(1)];

    let n = match tokio::time::timeout(Duration::from_millis(50), app.read(&mut early)).await {
        Ok(Ok(n)) => n,
        _ => 0,
    };
    early.truncate(n);

    let header = build_request_header(&settings.uuid, &target)?;
    let has_early = !early.is_empty();

    let subprotocol = if has_early {
        let mut payload = Vec::with_capacity(header.len() + early.len());
        payload.extend_from_slice(&header);
        payload.extend_from_slice(&early);
        Some(URL_SAFE_NO_PAD.encode(&payload))
    } else {
        None
    };

    let websocket = handshake(tls, &settings, subprotocol.as_deref()).await?;
    let (mut sink, mut stream) = websocket.split();

    if !has_early {
        sink.send(Message::Binary(header.to_vec()))
            .await
            .map_err(|error| VlessError::WebSocket(error.to_string()))?;
    }

    let (mut app_read, mut app_write) = tokio::io::split(app);

    let upstream = tokio::spawn(async move {
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            match app_read.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => {
                    if sink
                        .send(Message::Binary(buffer[..n].to_vec()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = sink.close().await;
    });

    let downstream = tokio::spawn(async move {
        let mut parser = ResponseHeaderParser::default();

        while let Some(message) = stream.next().await {
            match message {
                Ok(Message::Binary(data)) => match parser.push(&data) {
                    Ok(payload) => {
                        if !payload.is_empty()
                            && app_write.write_all(&payload).await.is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                },
                Ok(Message::Text(text)) => {
                    if app_write.write_all(text.as_bytes()).await.is_err() {
                        break;
                    }
                }
                Ok(Message::Close(_)) => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }

        let _ = app_write.shutdown().await;
    });

    let _ = tokio::join!(upstream, downstream);
    Ok(())
}
