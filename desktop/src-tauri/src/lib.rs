mod commands;
mod connection;
mod logging;
mod model;
mod platform;
mod storage;
mod totp;
mod vault;

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tauri::{Emitter, Manager};
use tracing_subscriber::prelude::*;

pub fn run() {
    let closing = Arc::new(AtomicBool::new(false));
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
            logs.set_level(&database.preferences()?.log_level);
            tracing_subscriber::registry()
                .with(logging::LogLayer(logs.clone()))
                .try_init()?;
            let controller = connection::Controller::new(
                app.handle().clone(),
                database,
                logs.clone(),
                directory,
            );
            app.manage(controller);
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
            commands::clear_logs
        ])
        .build(tauri::generate_context!())
        .expect("failed to initialize Array Connect");
    app.run(move |app, event| {
        if let tauri::RunEvent::ExitRequested { api, .. } = event {
            let controller = app.state::<Arc<connection::Controller>>().inner().clone();
            if controller.is_active() {
                api.prevent_exit();
                if !closing.swap(true, Ordering::SeqCst) {
                    let app = app.clone();
                    tauri::async_runtime::spawn(async move {
                        controller.disconnect().await;
                        app.exit(0);
                    });
                }
            }
        }
    });
}
