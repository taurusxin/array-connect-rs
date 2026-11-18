pub fn network_manager() -> Result<Box<dyn arraysslvpn::NetworkManager>, String> {
    if administrator() {
        return Ok(Box::new(
            arraysslvpn::network::SystemNetworkManager::default(),
        ));
    }
    #[cfg(target_os = "macos")]
    {
        arraysslvpn::network::macos_service::MacNetworkManager::prepare()
            .map(|manager| Box::new(manager) as Box<dyn arraysslvpn::NetworkManager>)
            .map_err(|error| error.to_string())
    }
    #[cfg(not(target_os = "macos"))]
    Err("连接 VPN 需要管理员/root 权限。请退出后以管理员身份重新运行客户端。".into())
}

pub fn network_service_status() -> Option<&'static str> {
    #[cfg(target_os = "macos")]
    {
        Some(arraysslvpn::network::macos_service::service_status().as_str())
    }
    #[cfg(not(target_os = "macos"))]
    None
}

pub fn administrator() -> bool {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::{
            Foundation::CloseHandle,
            Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
            System::Threading::{GetCurrentProcess, OpenProcessToken},
        };
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut length = 0;
        let result = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut length,
        );
        CloseHandle(token);
        result != 0 && elevation.TokenIsElevated != 0
    }
    #[cfg(unix)]
    unsafe {
        libc::geteuid() == 0
    }
}

pub fn wintun_available() -> bool {
    #[cfg(windows)]
    {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("wintun.dll").is_file()))
            .unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        true
    }
}
