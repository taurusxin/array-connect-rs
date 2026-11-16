mod autostart;
mod commands;
mod connection;
mod lifecycle;
mod logging;
mod model;
mod platform;
mod storage;
mod totp;
mod vault;

use std::sync::Arc;
use tauri::{Emitter, Manager};
use tracing_subscriber::prelude::*;

pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .setup(|app| {
            let directory = if cfg!(debug_assertions) {
                std::env::var_os("ARRAY_CONNECT_DATA_DIR")
                    .map(std::path::PathBuf::from)
                    .unwrap_or(app.path().app_data_dir()?)
            } else {
                app.path().app_data_dir()?
            };
            std::fs::create_dir_all(&directory)?;
            let database = storage::Database::open(&directory.join("array-connect.sqlite3"))?;
            let logs = logging::LogHub::new();
            let preferences = database.preferences()?;
            logs.set_level(&preferences.log_level);
            tracing_subscriber::registry()
                .with(logging::LogLayer(logs.clone()))
                .try_init()?;
            let lifecycle = lifecycle::Lifecycle::new(&preferences);
            let controller = connection::Controller::new(
                app.handle().clone(),
                database,
                logs.clone(),
                directory,
                lifecycle.clone(),
            );
            app.manage(controller);
            if let Err(error) = lifecycle.install_tray(app.handle()) {
                tracing::warn!(%error, "system tray unavailable; closing the window will request exit");
            }
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let mut cursor = 0;
                let mut timer = tokio::time::interval(std::time::Duration::from_millis(250));
                loop {
                    timer.tick().await;
                    let records = logs.since(cursor);
                    if let Some(last) = records.last() {
                        cursor = last.id;
                        let _ = handle.emit("vpn:logs", records);
                    }
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::bootstrap,
            commands::save_profile,
            commands::delete_profile,
            commands::connect_profile,
            commands::disconnect,
            commands::submit_credentials,
            commands::save_preferences,
            commands::set_autostart,
            commands::usage,
            commands::clear_logs,
            commands::enroll_otp,
            commands::cancel_otp_enrollment,
            commands::otp_qr,
            commands::choose_close,
            commands::request_exit,
            commands::confirm_exit,
            commands::cancel_exit
        ])
        .on_window_event(|window, event| {
            if window.label() == "main" && let tauri::WindowEvent::CloseRequested { api, .. } = event
                && let Some(controller) = window.app_handle().try_state::<Arc<connection::Controller>>()
                && !controller.lifecycle.ready() {
                api.prevent_close();
                controller.lifecycle.close(window.app_handle());
            }
        })
        .build(tauri::generate_context!())
        .expect("failed to initialize Array Connect");
    app.run(move |app, event| {
        if let tauri::RunEvent::ExitRequested { api, .. } = event {
            let controller = app.state::<Arc<connection::Controller>>().inner().clone();
            if !controller.lifecycle.ready() {
                api.prevent_exit();
                controller.lifecycle.request_exit(app);
            }
        }
    });
}
