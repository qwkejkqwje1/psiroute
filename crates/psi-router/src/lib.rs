mod assets;
mod error;
mod model;
mod normalize;
mod process;
mod router;
mod updater;

pub use assets::RouterAssets;
pub use error::{Result, RouterError};
pub use model::{Action, Meta, Network, RouteDecision};
pub use normalize::{
    normalize_domain, normalize_suffix, parse_ports, sniff_domain, suffix_matches,
};
pub use process::ProcessLookup;
pub use router::{CompiledRouter, HotRouter};
pub use updater::ListUpdater;
