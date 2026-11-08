use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{HOST, SEC_WEBSOCKET_PROTOCOL, USER_AGENT};
use tokio_tungstenite::tungstenite::http::{HeaderValue, Request};
use tokio_tungstenite::{client_async_with_config, WebSocketStream};

use crate::error::{Result, VlessError};
use crate::uri::VlessSettings;

const USER_AGENT_VALUE: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                                (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

pub(crate) fn build_request(
    settings: &VlessSettings,
    subprotocol: Option<&str>,
) -> Result<Request<()>> {
    let host = if settings.host.is_empty() {
        settings.sni.as_str()
    } else {
        settings.host.as_str()
    };
    let authority = if settings.port == 443 {
        host.to_string()
    } else {
        format!("{host}:{}", settings.port)
    };

    let url = format!("wss://{authority}{}", settings.path);
    let mut request = url
        .into_client_request()
        .map_err(|error| VlessError::WebSocket(error.to_string()))?;

    let headers = request.headers_mut();
    let _ = headers.insert(
        HOST,
        HeaderValue::from_str(&authority)
            .map_err(|error| VlessError::WebSocket(error.to_string()))?,
    );
    headers.insert(USER_AGENT, HeaderValue::from_static(USER_AGENT_VALUE));

    if let Some(subprotocol) = subprotocol {
        let _ = headers.insert(
            SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_str(subprotocol)
                .map_err(|error| VlessError::WebSocket(error.to_string()))?,
        );
    }

    Ok(request)
}

/// Выполняет WebSocket-upgrade поверх уже установленного TLS-соединения.
pub(crate) async fn handshake<S>(
    stream: S,
    settings: &VlessSettings,
    subprotocol: Option<&str>,
) -> Result<WebSocketStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = build_request(settings, subprotocol)?;

    let (websocket, response) = client_async_with_config(request, stream, None)
        .await
        .map_err(|error| VlessError::WebSocket(error.to_string()))?;

    if let Some(expected) = subprotocol {
        let echoed = response
            .headers()
            .get(SEC_WEBSOCKET_PROTOCOL)
            .and_then(|value| value.to_str().ok());

        if echoed != Some(expected) {
            return Err(VlessError::WebSocket(
                "сервер не эхо-вернул Sec-WebSocket-Protocol".to_string(),
            ));
        }
    }

    Ok(websocket)
}
