mod config;
mod error;
mod instance;
mod notice;
mod outbound;

pub use config::PsiphonConfig;
pub use error::{PsiphonError, Result};
pub use instance::{PsiphonInstance, PsiphonState};
pub use notice::Notice;
pub use outbound::PsiphonOutbound;

/// Страны Psiphon по умолчанию (пока не пришёл notice `AvailableEgressRegions`).
pub const DEFAULT_REGIONS: &[&str] = &[
    "AT", "BE", "BG", "CA", "CH", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GB", "HU", "IE", "IN",
    "IT", "JP", "LV", "NL", "NO", "PL", "RO", "RS", "SE", "SG", "SK", "US",
];

pub fn default_regions() -> Vec<String> {
    DEFAULT_REGIONS.iter().map(|code| (*code).to_string()).collect()
}

/// Каталог данных Psiphon по умолчанию (`%APPDATA%\PsiRoute` / `~/.local/share/psiroute`).
pub fn default_data_dir() -> Result<std::path::PathBuf> {
    psi_config::Config::data_dir().map_err(|error| PsiphonError::DataDir(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_regions_contains_common_countries() {
        let regions = default_regions();
        assert!(regions.iter().any(|code| code == "US"));
        assert!(regions.iter().any(|code| code == "DE"));
        assert!(regions.iter().any(|code| code == "NL"));
    }
}
