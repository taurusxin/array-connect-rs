use crate::{connection::Controller, logging::LogRecord, model::*};
use serde::Serialize;
use std::sync::Arc;
use tauri::State;
use tauri_plugin_autostart::ManagerExt;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Bootstrap {
    profiles: Vec<Profile>,
    preferences: Preferences,
    session: LiveSession,
    credential_request: Option<CredentialRequest>,
    logs: Vec<LogRecord>,
    usage: Usage,
    autostart: bool,
    administrator: bool,
    wintun_available: bool,
    storage_path: String,
    platform: String,
    version: String,
}

#[tauri::command]
pub async fn bootstrap(state: State<'_, Arc<Controller>>) -> Result<Bootstrap, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let profiles = state.db.lock().unwrap().profiles()?;
        let preferences = state.db.lock().unwrap().preferences()?;
        let usage = state.db.lock().unwrap().usage()?;
        Ok(Bootstrap {
            profiles,
            preferences,
            session: state.snapshot(),
            credential_request: state.credential_request(),
            logs: state.logs.all(),
            usage,
            autostart: state
                .app
                .autolaunch()
                .is_enabled()
                .map_err(|_| "开机自启状态读取失败")?,
            administrator: crate::platform::administrator(),
            wintun_available: crate::platform::wintun_available(),
            storage_path: state.directory.display().to_string(),
            platform: std::env::consts::OS.into(),
            version: env!("CARGO_PKG_VERSION").into(),
        })
    })
    .await
    .map_err(|_| "初始化任务失败")?
}
#[tauri::command]
pub async fn save_profile(
    state: State<'_, Arc<Controller>>,
    profile: Profile,
    secrets: SecretUpdates,
) -> Result<Vec<Profile>, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || state.save_profile(profile, secrets))
        .await
        .map_err(|_| "保存任务失败")?
}
#[tauri::command]
pub async fn delete_profile(
    state: State<'_, Arc<Controller>>,
    id: String,
) -> Result<Vec<Profile>, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || state.delete_profile(&id))
        .await
        .map_err(|_| "删除任务失败")?
}
#[tauri::command]
pub async fn connect_profile(state: State<'_, Arc<Controller>>, id: String) -> Result<(), String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || state.start(&id))
        .await
        .map_err(|_| "连接任务失败")?
}
#[tauri::command]
pub async fn disconnect(state: State<'_, Arc<Controller>>) -> Result<(), String> {
    state.disconnect().await;
    Ok(())
}
#[tauri::command]
pub fn submit_credentials(
    state: State<'_, Arc<Controller>>,
    input: CredentialInput,
) -> Result<(), String> {
    state.submit(input)
}
#[tauri::command]
pub async fn save_preferences(
    state: State<'_, Arc<Controller>>,
    preferences: Preferences,
) -> Result<(), String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        state.db.lock().unwrap().save_preferences(&preferences)?;
        state.logs.set_level(&preferences.log_level);
        Ok(())
    })
    .await
    .map_err(|_| "偏好保存任务失败")?
}
#[tauri::command]
pub async fn set_autostart(
    state: State<'_, Arc<Controller>>,
    enabled: bool,
) -> Result<bool, String> {
    let app = state.app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        if enabled {
            app.autolaunch().enable()
        } else {
            app.autolaunch().disable()
        }
        .map_err(|_| "开机自启设置失败")?;
        app.autolaunch()
            .is_enabled()
            .map_err(|_| "无法确认开机自启状态".into())
    })
    .await
    .map_err(|_| "开机自启任务失败")?
}
#[tauri::command]
pub async fn usage(state: State<'_, Arc<Controller>>) -> Result<Usage, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || state.db.lock().unwrap().usage())
        .await
        .map_err(|_| "统计读取任务失败")?
}
#[tauri::command]
pub fn clear_logs(state: State<'_, Arc<Controller>>) {
    state.logs.clear();
}
