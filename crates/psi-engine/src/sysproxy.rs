//! Системный прокси: Windows — реестр Internet Settings + InternetSetOption,
//! остальные платформы пока не поддерживаются (честная ошибка в лог).

#[derive(Debug, thiserror::Error)]
#[cfg_attr(not(windows), allow(dead_code))]
pub enum SysProxyError {
    #[error("системный прокси не поддерживается на этой платформе")]
    Unsupported,
    #[error("реестр: {0}")]
    Registry(String),
}

pub type Result<T> = std::result::Result<T, SysProxyError>;

#[cfg(windows)]
pub fn enable(port: u16) -> Result<()> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let key = hkcu
        .open_subkey_with_flags(
            "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            winreg::enums::KEY_SET_VALUE,
        )
        .map_err(|error| SysProxyError::Registry(error.to_string()))?;

    key.set_value("ProxyEnable", &1u32)
        .map_err(|error| SysProxyError::Registry(error.to_string()))?;
    key.set_value("ProxyServer", &format!("127.0.0.1:{port}"))
        .map_err(|error| SysProxyError::Registry(error.to_string()))?;
    key.set_value("ProxyOverride", &"<local>;localhost;127.*")
        .map_err(|error| SysProxyError::Registry(error.to_string()))?;

    refresh();
    Ok(())
}

#[cfg(windows)]
pub fn disable() -> Result<()> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let key = hkcu
        .open_subkey_with_flags(
            "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            winreg::enums::KEY_SET_VALUE,
        )
        .map_err(|error| SysProxyError::Registry(error.to_string()))?;

    key.set_value("ProxyEnable", &0u32)
        .map_err(|error| SysProxyError::Registry(error.to_string()))?;

    refresh();
    Ok(())
}

#[cfg(windows)]
fn refresh() {
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };

    // SAFETY: вызовы без буферов (null, длина 0) — только флаги обновления настроек.
    unsafe {
        InternetSetOptionW(
            std::ptr::null(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            std::ptr::null_mut(),
            0,
        );
        InternetSetOptionW(
            std::ptr::null(),
            INTERNET_OPTION_REFRESH,
            std::ptr::null_mut(),
            0,
        );
    }
}

#[cfg(not(windows))]
pub fn enable(_port: u16) -> Result<()> {
    Err(SysProxyError::Unsupported)
}

#[cfg(not(windows))]
pub fn disable() -> Result<()> {
    Err(SysProxyError::Unsupported)
}
