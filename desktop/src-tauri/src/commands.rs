use crate::{connection::Controller, logging::LogRecord, model::*};
use serde::Serialize;
use std::sync::Arc;
use tauri::State;

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
    autostart_error: Option<String>,
    administrator: bool,
    wintun_available: bool,
    storage_path: String,
    platform: String,
    version: String,
    tray_available: bool,
    exit_state: String,
}

#[tauri::command]
pub async fn bootstrap(state: State<'_, Arc<Controller>>) -> Result<Bootstrap, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let profiles = state.db.lock().unwrap().profiles()?;
        let preferences = state.db.lock().unwrap().preferences()?;
        let usage = state.db.lock().unwrap().usage()?;
        let (autostart, autostart_error) = match state.autostart_enabled() {
            Ok(enabled) => (enabled, None),
            Err(error) => {
                tracing::warn!(%error, "could not read autostart settings");
                (false, Some(error))
            }
        };
        Ok(Bootstrap {
            profiles,
            preferences,
            session: state.snapshot(),
            credential_request: state.credential_request(),
            logs: state.logs.all(),
            usage,
            autostart,
            autostart_error,
            administrator: crate::platform::administrator(),
            wintun_available: crate::platform::wintun_available(),
            storage_path: state.directory.display().to_string(),
            platform: std::env::consts::OS.into(),
            version: env!("CARGO_PKG_VERSION").into(),
            tray_available: state.lifecycle.tray_available(),
            exit_state: state.lifecycle.state().into(),
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
    tauri::async_runtime::spawn_blocking(move || state.save_preferences(&preferences))
        .await
        .map_err(|_| "偏好保存任务失败")?
}
#[tauri::command]
pub async fn set_autostart(
    state: State<'_, Arc<Controller>>,
    enabled: bool,
) -> Result<bool, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || state.set_autostart(enabled))
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

#[tauri::command]
pub async fn enroll_otp(
    state: State<'_, Arc<Controller>>,
    input: OtpEnrollmentInput,
) -> Result<Profile, String> {
    state.inner().clone().enroll_otp(input).await
}
#[tauri::command]
pub async fn cancel_otp_enrollment(state: State<'_, Arc<Controller>>) -> Result<(), String> {
    state.cancel_otp_enrollment().await;
    Ok(())
}
#[tauri::command]
pub async fn otp_qr(state: State<'_, Arc<Controller>>, id: String) -> Result<OtpQrCode, String> {
    state.inner().clone().otp_qr(&id).await
}

#[tauri::command]
pub async fn choose_close(
    state: State<'_, Arc<Controller>>,
    choice: CloseChoice,
    remember: bool,
) -> Result<Option<Preferences>, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || state.choose_close(choice, remember))
        .await
        .map_err(|_| "关闭选择任务失败")?
}
#[tauri::command]
pub fn request_exit(state: State<'_, Arc<Controller>>) {
    state.lifecycle.request_exit(&state.app);
}
#[tauri::command]
pub fn confirm_exit(state: State<'_, Arc<Controller>>) {
    state.lifecycle.confirm(&state.app);
}
#[tauri::command]
pub fn cancel_exit(state: State<'_, Arc<Controller>>) {
    state.lifecycle.cancel(&state.app);
}
