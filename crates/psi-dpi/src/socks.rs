use std::net::SocketAddr;
use std::sync::Arc;

use psi_core::{
    BoxFuture, BoxStream, EventBus, Handler, MixedInbound, Outbound, Result as CoreResult,
};

use crate::outbound::DpiOutbound;

/// Локальный SOCKS5/HTTP-мост поверх DPI-обхода (отдаётся Psiphon как UpstreamProxyURL).
pub async fn serve_socks(
    addr: SocketAddr,
    outbound: DpiOutbound,
    bus: EventBus,
) -> CoreResult<()> {
    let handler: Handler = Arc::new(move |target, _meta| -> BoxFuture<CoreResult<BoxStream>> {
        let outbound = outbound.clone();
        Box::pin(async move { outbound.connect_tcp(&target).await })
    });

    let inbound = Arc::new(MixedInbound::new(bus));
    inbound.serve(addr, handler).await
}
