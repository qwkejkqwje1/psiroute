use std::time::Duration;

use futures::future::BoxFuture;
use tokio::sync::mpsc;

use crate::error::{BootstrapError, Result};

/// Участник гонки: тег, задержка старта и будущий результат.
pub struct RaceEntry<T> {
    pub tag: String,
    pub delay: Duration,
    pub future: BoxFuture<'static, Option<T>>,
}

/// Запускает участников с задержками и возвращает первого, кто дал результат.
///
/// Проигравшие задачи отменяются и дожидаются завершения, чтобы освободить
/// мосты и процессы Psiphon.
pub async fn race_entries<T>(entries: Vec<RaceEntry<T>>, total: Duration) -> Result<T>
where
    T: Send + 'static,
{
    if entries.is_empty() {
        return Err(BootstrapError::NoStrategies);
    }

    let (tx, mut rx) = mpsc::channel(entries.len());
    let mut handles = Vec::with_capacity(entries.len());

    for entry in entries {
        let tx = tx.clone();
        let tag = entry.tag.clone();
        handles.push(tokio::spawn(async move {
            if !entry.delay.is_zero() {
                tokio::time::sleep(entry.delay).await;
            }

            match entry.future.await {
                Some(value) => {
                    tracing::debug!(target: "psi_bootstrap", strategy = %tag, "стратегия завершила гонку");
                    let _ = tx.send(value).await;
                }
                None => {
                    tracing::debug!(target: "psi_bootstrap", strategy = %tag, "стратегия недоступна");
                }
            }
        }));
    }
    drop(tx);

    let winner = tokio::time::timeout(total, rx.recv())
        .await
        .map_err(|_| BootstrapError::Timeout(total))?;

    for handle in handles {
        handle.abort();
        let _ = handle.await;
    }

    winner.ok_or(BootstrapError::NoStrategies)
}

/// Порядок тегов: победитель кэша, затем `order`, затем остальные.
pub fn order_tags(
    order: &[String],
    cached: Option<&str>,
    available: &[String],
) -> Vec<String> {
    let mut tags: Vec<String> = Vec::with_capacity(available.len());

    if let Some(cached) = cached {
        if available.iter().any(|tag| tag == cached) {
            tags.push(cached.to_string());
        }
    }

    for tag in order {
        if available.iter().any(|item| item == tag) && !tags.iter().any(|item| item == tag) {
            tags.push(tag.clone());
        }
    }

    for tag in available {
        if !tags.iter().any(|item| item == tag) {
            tags.push(tag.clone());
        }
    }

    tags
}

/// Задержка старта: кэшированный лидер получает фору, остальные идут через stagger.
pub fn start_delays(
    count: usize,
    cached: bool,
    stagger: Duration,
    head_start: Duration,
) -> Vec<Duration> {
    let mut delays = Vec::with_capacity(count);
    let mut offset = Duration::ZERO;

    for index in 0..count {
        if index == 0 {
            delays.push(Duration::ZERO);
            continue;
        }

        if index == 1 {
            offset = if cached { head_start } else { stagger };
        } else {
            offset += stagger;
        }
        delays.push(offset);
    }

    delays
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;

    struct CancelFlag(Arc<AtomicUsize>);

    impl Drop for CancelFlag {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn entry<T: Send + 'static>(
        tag: &str,
        delay: Duration,
        value: Option<T>,
        guard: Option<CancelFlag>,
        sleep: Duration,
    ) -> RaceEntry<T> {
        let tag = tag.to_string();
        RaceEntry {
            tag,
            delay,
            future: Box::pin(async move {
                let _guard = guard;
                tokio::time::sleep(sleep).await;
                value
            }),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn fastest_wins_and_losers_are_cancelled() {
        let cancelled = Arc::new(AtomicUsize::new(0));

        let entries = vec![
            entry(
                "slow",
                Duration::ZERO,
                Some("slow"),
                Some(CancelFlag(Arc::clone(&cancelled))),
                Duration::from_secs(60),
            ),
            entry(
                "fast",
                Duration::ZERO,
                Some("fast"),
                None,
                Duration::from_millis(50),
            ),
            entry(
                "medium",
                Duration::from_millis(10),
                Some("medium"),
                Some(CancelFlag(Arc::clone(&cancelled))),
                Duration::from_secs(30),
            ),
        ];

        let winner = race_entries(entries, Duration::from_secs(120))
            .await
            .expect("победитель");

        assert_eq!(winner, "fast");
        assert_eq!(cancelled.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn first_available_after_skips_wins() {
        let entries = vec![
            entry::<&str>("skip", Duration::ZERO, None, None, Duration::from_millis(10)),
            entry(
                "next",
                Duration::from_millis(20),
                Some("next"),
                None,
                Duration::from_millis(1),
            ),
        ];

        let winner = race_entries(entries, Duration::from_secs(5))
            .await
            .expect("победитель");
        assert_eq!(winner, "next");
    }

    #[tokio::test(start_paused = true)]
    async fn times_out_without_winner() {
        let entries = vec![entry::<&str>(
            "never",
            Duration::ZERO,
            None,
            None,
            Duration::from_secs(60),
        )];

        let error = race_entries(entries, Duration::from_secs(5))
            .await
            .expect_err("таймаут");
        assert!(matches!(error, BootstrapError::Timeout(_)));
    }

    #[test]
    fn cached_winner_goes_first() {
        let order = vec!["direct".to_string(), "dpi".to_string()];
        let available = vec![
            "direct".to_string(),
            "dpi".to_string(),
            "vless".to_string(),
        ];

        let tags = order_tags(&order, Some("vless"), &available);
        assert_eq!(tags, vec!["vless", "direct", "dpi"]);
    }

    #[test]
    fn cached_head_start_delays() {
        let stagger = Duration::from_millis(300);
        let head_start = Duration::from_millis(1500);

        assert_eq!(
            start_delays(3, true, stagger, head_start),
            vec![
                Duration::ZERO,
                Duration::from_millis(1500),
                Duration::from_millis(1800)
            ]
        );

        assert_eq!(
            start_delays(3, false, stagger, head_start),
            vec![
                Duration::ZERO,
                Duration::from_millis(300),
                Duration::from_millis(600)
            ]
        );
    }
}
