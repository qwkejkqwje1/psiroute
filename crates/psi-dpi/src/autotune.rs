use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::TlsConnector;

use psi_core::Target;

use crate::outbound::DpiOutbound;
use crate::strategy::StrategyPlan;

/// Хосты для автоподбора стратегии.
pub const DEFAULT_TEST_HOSTS: &[&str] = &["www.youtube.com", "rutracker.org", "x.com", "discord.com"];

/// Перебирает пресеты стратегий и возвращает первый по числу успешных проверок.
pub async fn autotune(test_hosts: &[&str]) -> Option<StrategyPlan> {
    if test_hosts.is_empty() {
        return None;
    }

    let mut best: Option<(usize, StrategyPlan)> = None;

    for plan in StrategyPlan::presets() {
        let outbound = DpiOutbound::new(plan.clone());
        let successes = count_successes(&outbound, test_hosts).await;
        tracing::info!(?plan, successes, "пресет проверен");

        if successes > 0
            && best
                .as_ref()
                .map(|(best_successes, _)| successes > *best_successes)
                .unwrap_or(true)
        {
            best = Some((successes, plan));
        }
    }

    best.map(|(_, plan)| plan)
}

async fn count_successes(outbound: &DpiOutbound, hosts: &[&str]) -> usize {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(4));
    let mut tasks = Vec::new();

    for host in hosts {
        let outbound = outbound.clone();
        let semaphore = semaphore.clone();
        let host = (*host).to_string();

        tasks.push(tokio::spawn(async move {
            let Ok(_permit) = semaphore.acquire_owned().await else {
                return false;
            };
            probe(&outbound, &host).await
        }));
    }

    let mut successes = 0;
    for task in tasks {
        if let Ok(true) = task.await {
            successes += 1;
        }
    }

    successes
}

async fn probe(outbound: &DpiOutbound, host: &str) -> bool {
    let target = Target::Domain(host.to_string(), 443);
    let stream = match outbound.connect_stream(&target).await {
        Ok(stream) => stream,
        Err(_) => return false,
    };

    let connector = match h1_connector() {
        Ok(connector) => connector,
        Err(_) => return false,
    };
    let Ok(server_name) = ServerName::try_from(host.to_string()) else {
        return false;
    };

    let tls = match tokio::time::timeout(
        Duration::from_secs(8),
        connector.connect(server_name, stream),
    )
    .await
    {
        Ok(Ok(tls)) => tls,
        _ => return false,
    };

    probe_http(tls, host).await
}

async fn probe_http<S>(mut tls: S, host: &str) -> bool
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = format!(
        "HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: PsiRoute/0.1\r\nConnection: close\r\n\r\n"
    );

    if tls.write_all(request.as_bytes()).await.is_err() {
        return false;
    }

    let mut buffer = [0u8; 32];
    matches!(
        tokio::time::timeout(Duration::from_secs(8), tls.read(&mut buffer)).await,
        Ok(Ok(read)) if read > 0
    )
}

fn h1_connector() -> crate::Result<TlsConnector> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(TlsConnector::from(Arc::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_are_not_empty() {
        assert_eq!(StrategyPlan::presets().len(), 4);
    }

    #[tokio::test]
    async fn empty_hosts_returns_none() {
        assert!(autotune(&[]).await.is_none());
    }
}
