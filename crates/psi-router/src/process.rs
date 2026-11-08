use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
use sysinfo::{Pid, ProcessesToUpdate, System};

const CACHE_TTL: Duration = Duration::from_secs(2);

#[derive(Default)]
struct ProcessCache {
    refreshed_at: Option<Instant>,
    system: Option<System>,
    ports: HashMap<u16, u32>,
}

/// Определение процесса по локальному порту (netstat2 + sysinfo, кэш 2 с).
#[derive(Default)]
pub struct ProcessLookup {
    cache: Mutex<ProcessCache>,
}

impl ProcessLookup {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn process_for_port(&self, port: u16) -> Option<String> {
        let mut cache = self.cache.lock().unwrap_or_else(|error| error.into_inner());
        cache.refresh_if_stale();

        let pid = *cache.ports.get(&port)?;
        let system = cache.system.as_ref()?;
        let process = system.process(Pid::from_u32(pid))?;
        Some(process.name().to_string_lossy().into_owned())
    }

    pub fn process_for_meta(&self, port: u16, explicit: Option<&str>) -> Option<String> {
        explicit
            .map(ToOwned::to_owned)
            .or_else(|| self.process_for_port(port))
    }
}

impl ProcessCache {
    fn refresh_if_stale(&mut self) {
        let stale = self
            .refreshed_at
            .map(|at| at.elapsed() >= CACHE_TTL)
            .unwrap_or(true);

        if !stale {
            return;
        }

        // Полный System::new_all() нужен только один раз: дальше дешевле
        // обновлять список процессов в уже созданном экземпляре.
        match &mut self.system {
            Some(system) => {
                system.refresh_processes(ProcessesToUpdate::All, true);
            }
            None => {
                self.system = System::new_all().ok();
            }
        }
        self.ports = collect_ports();
        self.refreshed_at = Some(Instant::now());
    }
}

fn collect_ports() -> HashMap<u16, u32> {
    let mut ports = HashMap::new();

    let flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let protocols = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let Ok(sockets) = get_sockets_info(flags, protocols) else {
        return ports;
    };

    for socket in sockets {
        let port = match socket.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp) => tcp.local_port,
            ProtocolSocketInfo::Udp(udp) => udp.local_port,
        };

        if let Some(pid) = socket.associated_pids.first() {
            ports.entry(port).or_insert(*pid);
        }
    }

    ports
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_does_not_panic_for_unknown_port() {
        let lookup = ProcessLookup::new();
        let _ = lookup.process_for_port(1);
    }
}
