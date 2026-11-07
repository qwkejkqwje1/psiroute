use tokio::sync::broadcast;

/// Состояние движка для UI/логов.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnState {
    Idle,
    Bootstrapping { strategy: String },
    Connecting { region: String },
    Connected { region: String, via: String },
    Error(String),
}

/// События движка.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    State(ConnState),
    Log(String),
    Stats { up: u64, down: u64 },
    Regions(Vec<String>),
    Route { dst: String, outbound: String },
}

/// Шина событий на базе `tokio::sync::broadcast`.
#[derive(Debug, Clone)]
pub struct EventBus {
    tx: broadcast::Sender<Event>,
}

impl EventBus {
    pub fn new() -> Self {
        Self::with_capacity(1024)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity.max(1));
        Self { tx }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }

    /// Публикует событие; отсутствие подписчиков не считается ошибкой.
    pub fn publish(&self, event: Event) {
        let _ = self.tx.send(event);
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn publishes_to_subscriber() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();
        bus.publish(Event::Log("привет".to_string()));
        assert_eq!(rx.recv().await.expect("событие"), Event::Log("привет".to_string()));
    }
}
