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
