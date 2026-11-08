mod autotune;
mod doh;
mod error;
mod oob;
mod outbound;
mod parse;
mod sidecar;
mod socks;
mod strategy;

pub use autotune::{autotune, DEFAULT_TEST_HOSTS};
pub use doh::{default_doh_servers, DohResolver};
pub use error::{DpiError, Result};
pub use outbound::DpiOutbound;
pub use parse::{
    analyze, find_http_host, find_tls_sni, rewrite_http_host, tlsrec_split, PayloadKind,
};
pub use sidecar::ExternalEngine;
pub use socks::serve_socks;
pub use strategy::{
    build_first_flight, Strategy, StrategyPlan, SplitAt, FirstFlight, Segment,
};
