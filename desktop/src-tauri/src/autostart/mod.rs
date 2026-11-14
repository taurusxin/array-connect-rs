#[cfg(windows)]
mod windows;
#[cfg(not(windows))]
use tauri_plugin_autostart::ManagerExt;

pub fn is_enabled(app: &tauri::AppHandle) -> Result<bool, String> {
    #[cfg(windows)]
    {
        windows::is_enabled(app)
    }
    #[cfg(not(windows))]
    {
        app.autolaunch()
            .is_enabled()
            .map_err(|_| "开机自启状态读取失败".into())
    }
}
pub fn set_enabled(app: &tauri::AppHandle, enabled: bool) -> Result<bool, String> {
    #[cfg(windows)]
    {
        windows::set_enabled(app, enabled)
    }
    #[cfg(not(windows))]
    {
        if enabled {
            app.autolaunch().enable()
        } else {
            app.autolaunch().disable()
        }
        .map_err(|_| "开机自启设置失败")?;
        is_enabled(app)
    }
}
