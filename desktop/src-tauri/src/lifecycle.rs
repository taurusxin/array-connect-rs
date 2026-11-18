use crate::{
    connection::Controller,
    model::{CloseBehavior, CloseChoice, Preferences},
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU8, Ordering},
};
use tauri::{
    Emitter, Manager,
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
};

const IDLE: u8 = 0;
const CHOOSE: u8 = 1;
const CHECKING: u8 = 2;
const CONFIRM: u8 = 3;
const CLOSING: u8 = 4;
const READY: u8 = 5;

#[derive(Debug, PartialEq, Eq)]
enum ExitAction {
    None,
    Confirm,
    Shutdown,
}
#[derive(Default)]
struct ExitGate(AtomicU8);
impl ExitGate {
    fn choose(&self) -> bool {
        self.0
            .compare_exchange(IDLE, CHOOSE, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }
    fn begin_choice(&self) -> bool {
        self.0
            .compare_exchange(CHOOSE, CHECKING, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }
    fn finish_exit_check(&self, active: bool) -> ExitAction {
        self.0
            .store(if active { CONFIRM } else { CLOSING }, Ordering::SeqCst);
        if active {
            ExitAction::Confirm
        } else {
            ExitAction::Shutdown
        }
    }
    fn request_exit(&self, active: impl FnOnce() -> bool) -> ExitAction {
        loop {
            let current = self.0.load(Ordering::SeqCst);
            match current {
                IDLE | CHOOSE => {
                    // Reserve exit before checking the session; start() checks this
                    // gate while holding the session lock, so it cannot race past it.
                    if self
                        .0
                        .compare_exchange(current, CHECKING, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                    {
                        return self.finish_exit_check(active());
                    }
                }
                CONFIRM => return ExitAction::Confirm,
                _ => return ExitAction::None,
            }
        }
    }
    fn confirm(&self) -> bool {
        self.0
            .compare_exchange(CONFIRM, CLOSING, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }
    fn cancel(&self) -> bool {
        loop {
            let current = self.0.load(Ordering::SeqCst);
            if !matches!(current, CHOOSE | CONFIRM) {
                return false;
            }
            if self
                .0
                .compare_exchange(current, IDLE, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return true;
            }
        }
    }
}

pub struct Lifecycle {
    gate: ExitGate,
    close_behavior: AtomicU8,
    tray_available: AtomicBool,
}
impl Lifecycle {
    pub fn new(preferences: &Preferences) -> Arc<Self> {
        Arc::new(Self {
            gate: ExitGate::default(),
            close_behavior: AtomicU8::new(preferences.close_behavior as u8),
            tray_available: AtomicBool::new(false),
        })
    }
    pub fn update(&self, preferences: &Preferences) {
        self.close_behavior
            .store(preferences.close_behavior as u8, Ordering::SeqCst);
    }
    pub fn tray_available(&self) -> bool {
        self.tray_available.load(Ordering::SeqCst)
    }
    pub fn ready(&self) -> bool {
        self.gate.0.load(Ordering::SeqCst) == READY
    }
    pub fn closing(&self) -> bool {
        self.gate.0.load(Ordering::SeqCst) >= CLOSING
    }
    pub fn state(&self) -> &'static str {
        match self.gate.0.load(Ordering::SeqCst) {
            IDLE => "idle",
            CHOOSE => "choose",
            CONFIRM => "confirm",
            CHECKING => "checking",
            _ => "closing",
        }
    }
    fn emit_state(&self, app: &tauri::AppHandle) {
        let _ = app.emit("app:exit-state", self.state());
    }
    pub fn close(self: &Arc<Self>, app: &tauri::AppHandle) {
        if self.state() != "idle" {
            if matches!(self.state(), "choose" | "confirm") {
                show_main(app);
                self.emit_state(app);
            }
            return;
        }
        let behavior = self.close_behavior.load(Ordering::SeqCst);
        if behavior == CloseBehavior::Exit as u8 {
            self.request_exit(app);
        } else if behavior == CloseBehavior::Tray as u8 && self.tray_available() {
            if let Err(error) = hide_main(app) {
                tracing::warn!(%error, "could not hide window; asking how to close");
                self.ask_close(app);
            }
        } else {
            self.ask_close(app);
        }
    }
    fn ask_close(&self, app: &tauri::AppHandle) {
        if self.gate.choose() {
            show_main(app);
            self.emit_state(app);
        }
    }
    pub fn begin_close_choice(&self) -> bool {
        self.gate.begin_choice()
    }
    pub fn restore_close_choice(&self, app: &tauri::AppHandle) {
        self.gate.0.store(CHOOSE, Ordering::SeqCst);
        self.emit_state(app);
    }
    pub fn finish_close_choice(
        self: &Arc<Self>,
        app: &tauri::AppHandle,
        choice: CloseChoice,
    ) -> Result<(), String> {
        match choice {
            CloseChoice::Tray => {
                if !self.tray_available() {
                    return Err("系统托盘不可用，请选择退出或取消关闭".into());
                }
                hide_main(app)?;
                self.gate.0.store(IDLE, Ordering::SeqCst);
                self.emit_state(app);
            }
            CloseChoice::Exit => {
                let active = app.state::<Arc<Controller>>().is_active();
                self.perform_exit(app, self.gate.finish_exit_check(active));
            }
        }
        Ok(())
    }
    pub fn request_exit(self: &Arc<Self>, app: &tauri::AppHandle) {
        let action = self
            .gate
            .request_exit(|| app.state::<Arc<Controller>>().is_active());
        self.perform_exit(app, action);
    }
    fn perform_exit(self: &Arc<Self>, app: &tauri::AppHandle, action: ExitAction) {
        match action {
            ExitAction::None => {}
            ExitAction::Confirm => {
                show_main(app);
                self.emit_state(app);
            }
            ExitAction::Shutdown => self.shutdown(app),
        }
    }
    pub fn confirm(self: &Arc<Self>, app: &tauri::AppHandle) {
        if self.gate.confirm() {
            self.shutdown(app);
        }
    }
    pub fn cancel(&self, app: &tauri::AppHandle) {
        if self.gate.cancel() {
            self.emit_state(app);
        }
    }
    fn shutdown(self: &Arc<Self>, app: &tauri::AppHandle) {
        self.emit_state(app);
        let owner = self.clone();
        let app = app.clone();
        let controller = app.state::<Arc<Controller>>().inner().clone();
        tauri::async_runtime::spawn(async move {
            tracing::info!(
                vpn_active = controller.is_active(),
                "application exit requested; waiting for VPN cleanup"
            );
            controller.disconnect().await;
            controller.wait_for_pending_operations().await;
            owner.gate.0.store(READY, Ordering::SeqCst);
            app.exit(0);
        });
    }
    pub fn install_tray(&self, app: &tauri::AppHandle) -> tauri::Result<()> {
        let menu = tray_menu(app, "Disconnected", false)?;
        let builder = TrayIconBuilder::with_id("main-tray")
            .tooltip("Array Connect · 未连接")
            .menu(&menu)
            .show_menu_on_left_click(false);
        #[cfg(target_os = "macos")]
        let builder = builder
            .icon(tauri::image::Image::from_bytes(include_bytes!(
                "../icons/macos-tray.png"
            ))?)
            .icon_as_template(true);
        #[cfg(not(target_os = "macos"))]
        let builder = match app.default_window_icon() {
            Some(icon) => builder.icon(icon.clone()),
            None => builder,
        };
        builder
            .on_menu_event(|app, event| {
                let controller = app.state::<Arc<Controller>>().inner().clone();
                match event.id.as_ref() {
                    "show" => show_main(app),
                    "disconnect" => {
                        tauri::async_runtime::spawn(async move {
                            controller.disconnect().await;
                        });
                    }
                    "quit" => controller.lifecycle.request_exit(app),
                    _ => {}
                }
            })
            .on_tray_icon_event(|tray, event| {
                if matches!(
                    event,
                    TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    }
                ) {
                    show_main(tray.app_handle());
                }
            })
            .build(app)?;
        self.tray_available.store(true, Ordering::SeqCst);
        Ok(())
    }
    pub fn refresh_tray(&self, app: &tauri::AppHandle) {
        if !self.tray_available() {
            return;
        }
        let handle = app.clone();
        // Read the latest state on the main thread; delayed updates cannot restore
        // an obsolete menu, and no session lock is held while calling menu APIs.
        let _ = app.run_on_main_thread(move || {
            let controller = handle.state::<Arc<Controller>>();
            let active = controller.is_active();
            let snapshot = controller.snapshot();
            let Some(tray) = handle.tray_by_id("main-tray") else {
                return;
            };
            let result = tray_menu(&handle, &snapshot.state, active)
                .and_then(|menu| tray.set_menu(Some(menu)));
            if let Err(error) = result {
                tracing::warn!(%error, "could not update tray menu");
            }
            let presentation = tray_presentation(&snapshot.state, active);
            let _ = tray.set_tooltip(Some(format!("Array Connect · {}", presentation.status)));
        });
    }
}

struct TrayPresentation {
    status: &'static str,
    action: Option<(&'static str, bool)>,
}
fn tray_presentation(state: &str, active: bool) -> TrayPresentation {
    if !active {
        return TrayPresentation {
            status: "未连接",
            action: None,
        };
    }
    let (status, action, enabled) = match state {
        "Connected" => ("已连接", "断开 VPN", true),
        "Reconnecting" => ("正在重连", "断开 VPN", true),
        "Disconnecting" | "Disconnected" => ("正在断开", "正在断开…", false),
        _ => ("正在连接", "取消连接", true),
    };
    TrayPresentation {
        status,
        action: Some((action, enabled)),
    }
}
fn tray_menu(app: &tauri::AppHandle, state: &str, active: bool) -> tauri::Result<Menu<tauri::Wry>> {
    let presentation = tray_presentation(state, active);
    let status = MenuItem::with_id(
        app,
        "status",
        format!("VPN {}", presentation.status),
        false,
        None::<&str>,
    )?;
    let show = MenuItem::with_id(app, "show", "显示主窗口", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&status, &show])?;
    if let Some((label, enabled)) = presentation.action {
        menu.append(&MenuItem::with_id(
            app,
            "disconnect",
            label,
            enabled,
            None::<&str>,
        )?)?;
    }
    menu.append(&PredefinedMenuItem::separator(app)?)?;
    menu.append(&MenuItem::with_id(
        app,
        "quit",
        "退出 Array Connect",
        true,
        None::<&str>,
    )?)?;
    Ok(menu)
}
fn hide_main(app: &tauri::AppHandle) -> Result<(), String> {
    app.get_webview_window("main")
        .ok_or("主窗口不可用")?
        .hide()
        .map_err(|error| format!("无法最小化到托盘：{error}"))
}
pub fn show_main(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn choosing_exit_still_requires_confirmation_for_an_active_session() {
        let gate = ExitGate::default();
        assert!(gate.choose());
        assert!(!gate.confirm());
        assert!(gate.begin_choice());
        assert!(!gate.cancel());
        assert_eq!(gate.finish_exit_check(true), ExitAction::Confirm);
        assert!(gate.cancel());
        assert_eq!(gate.request_exit(|| true), ExitAction::Confirm);
        assert!(gate.confirm());
        assert!(!gate.confirm());
        assert_eq!(gate.request_exit(|| false), ExitAction::None);
    }
    #[test]
    fn explicit_exit_skips_the_close_choice_and_idle_exit_needs_no_warning() {
        let gate = ExitGate::default();
        assert!(gate.choose());
        assert_eq!(gate.request_exit(|| false), ExitAction::Shutdown);
        assert!(!gate.begin_choice());
        assert!(!gate.cancel());
    }
    #[test]
    fn new_connections_are_blocked_before_the_exit_connection_check() {
        let gate = ExitGate::default();
        assert_eq!(
            gate.request_exit(|| {
                assert_eq!(gate.0.load(Ordering::SeqCst), CHECKING);
                true
            }),
            ExitAction::Confirm
        );
    }
    #[test]
    fn concurrent_idle_exit_requests_start_exactly_one_cleanup() {
        let gate = Arc::new(ExitGate::default());
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let gate = gate.clone();
                std::thread::spawn(move || gate.request_exit(|| false))
            })
            .collect();
        assert_eq!(
            threads
                .into_iter()
                .filter_map(|t| (t.join().unwrap() == ExitAction::Shutdown).then_some(()))
                .count(),
            1
        );
    }
    #[test]
    fn tray_omits_disconnect_when_idle_and_tracks_connection_phases() {
        for state in ["Disconnected", "Connected", "Reconnecting"] {
            assert_eq!(tray_presentation(state, false).action, None);
        }
        assert_eq!(
            tray_presentation("Connecting", true).action,
            Some(("取消连接", true))
        );
        assert_eq!(
            tray_presentation("Connected", true).action,
            Some(("断开 VPN", true))
        );
        assert_eq!(
            tray_presentation("Disconnecting", true).action,
            Some(("正在断开…", false))
        );
    }
}
