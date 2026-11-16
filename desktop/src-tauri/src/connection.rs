use crate::{
    logging::LogHub,
    model::*,
    storage::Database,
    totp,
    vault::{self, SecretStore, SystemVault},
};
use arraysslvpn::{
    AuthConfig, ClientConfig, ClientEvent, ConnectionState, ExposeSecret, PasswordChallenge,
    PasswordProvider, SecretString, SessionHandle, VpnClient, VpnError,
};
use async_trait::async_trait;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant},
};
use tauri::Emitter;
use tokio::sync::{oneshot, watch};
use zeroize::Zeroizing;

mod otp;

pub struct Controller {
    pub app: tauri::AppHandle,
    pub db: Mutex<Database>,
    pub logs: Arc<LogHub>,
    pub directory: PathBuf,
    pub lifecycle: Arc<crate::lifecycle::Lifecycle>,
    vault: Arc<dyn SecretStore>,
    configuration: Mutex<()>,
    active: Mutex<Option<Active>>,
    snapshot: Mutex<LiveSession>,
    pending: Mutex<Option<Pending>>,
    enrollment: Mutex<Option<OtpOperation>>,
}
struct OtpOperation {
    profile_id: String,
    cancel: arraysslvpn::CancellationToken,
    done: watch::Receiver<bool>,
}
struct Active {
    id: String,
    profile_id: String,
    handle: SessionHandle,
    done: watch::Receiver<bool>,
}
struct Pending {
    request: CredentialRequest,
    sender: oneshot::Sender<CredentialInput>,
}

impl Controller {
    pub fn new(
        app: tauri::AppHandle,
        db: Database,
        logs: Arc<LogHub>,
        directory: PathBuf,
        lifecycle: Arc<crate::lifecycle::Lifecycle>,
    ) -> Arc<Self> {
        Arc::new(Self {
            app,
            db: Mutex::new(db),
            logs,
            directory,
            lifecycle,
            vault: Arc::new(SystemVault),
            configuration: Mutex::new(()),
            active: Mutex::new(None),
            snapshot: Mutex::new(LiveSession {
                state: "Disconnected".into(),
                ..Default::default()
            }),
            pending: Mutex::new(None),
            enrollment: Mutex::new(None),
        })
    }
    pub fn snapshot(&self) -> LiveSession {
        self.snapshot.lock().unwrap().clone()
    }
    pub fn credential_request(&self) -> Option<CredentialRequest> {
        self.pending
            .lock()
            .unwrap()
            .as_ref()
            .map(|p| p.request.clone())
    }
    pub fn is_active(&self) -> bool {
        self.active.lock().unwrap().is_some()
    }
    fn ensure_mutable(&self) -> Result<(), String> {
        if self.lifecycle.closing() {
            Err("应用正在退出，请等待退出后重新操作".into())
        } else {
            Ok(())
        }
    }
    pub async fn wait_for_pending_operations(self: &Arc<Self>) {
        let owner = self.clone();
        if let Err(error) = tauri::async_runtime::spawn_blocking(move || {
            let _configuration = owner.configuration.lock().unwrap();
            let _database = owner.db.lock().unwrap();
        })
        .await
        {
            tracing::warn!(%error, "waiting for pending writes failed");
        }
    }
    pub fn save_preferences(&self, preferences: &Preferences) -> Result<(), String> {
        let _operation = self.configuration.lock().unwrap();
        self.ensure_mutable()?;
        self.db.lock().unwrap().save_preferences(preferences)?;
        self.logs.set_level(&preferences.log_level);
        self.lifecycle.update(preferences);
        Ok(())
    }
    pub fn choose_close(
        &self,
        choice: CloseChoice,
        remember: bool,
    ) -> Result<Option<Preferences>, String> {
        let _operation = self.configuration.lock().unwrap();
        if !self.lifecycle.begin_close_choice() {
            return Err("关闭选择已结束，请重新操作".into());
        }
        let result = (|| {
            if matches!(choice, CloseChoice::Tray) && !self.lifecycle.tray_available() {
                return Err("系统托盘不可用，请选择退出或取消关闭".into());
            }
            let preferences = if remember {
                let database = self.db.lock().unwrap();
                let mut preferences = database.preferences()?;
                preferences.close_behavior = choice.into();
                database.save_preferences(&preferences)?;
                self.lifecycle.update(&preferences);
                Some(preferences)
            } else {
                None
            };
            self.lifecycle.finish_close_choice(&self.app, choice)?;
            Ok(preferences)
        })();
        if result.is_err() {
            self.lifecycle.restore_close_choice(&self.app);
        }
        result
    }
    pub fn autostart_enabled(&self) -> Result<bool, String> {
        let _operation = self.configuration.lock().unwrap();
        self.ensure_mutable()?;
        crate::autostart::is_enabled(&self.app)
    }
    pub fn set_autostart(&self, enabled: bool) -> Result<bool, String> {
        let _operation = self.configuration.lock().unwrap();
        self.ensure_mutable()?;
        crate::autostart::set_enabled(&self.app, enabled)
    }
    fn check_editable(&self, profile: &str) -> Result<(), String> {
        if self
            .enrollment
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|operation| operation.profile_id == profile)
        {
            return Err("OTP 注册尚未完成，请等待或取消后再编辑".into());
        }
        if self
            .active
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|a| a.profile_id == profile)
        {
            Err("请先断开此配置，再编辑或删除".into())
        } else {
            Ok(())
        }
    }
    pub fn save_profile(
        &self,
        mut profile: Profile,
        mut updates: SecretUpdates,
    ) -> Result<Vec<Profile>, String> {
        let _operation = self.configuration.lock().unwrap();
        self.ensure_mutable()?;
        self.check_editable(&profile.id)?;
        profile.normalize_server()?;
        profile.validate()?;
        let password = updates.password.take().map(Zeroizing::new);
        let seed = updates.otp_secret.take().map(Zeroizing::new);
        let proxy_password = updates.proxy_password.take().map(Zeroizing::new);
        for secret in [&password, &seed, &proxy_password].into_iter().flatten() {
            self.logs.secret(secret);
        }
        let mut changes = vec![];
        let prior_password = self.vault.get(&profile.id, "password")?;
        let previous = self
            .db
            .lock()
            .unwrap()
            .profiles()?
            .into_iter()
            .find(|p| p.id == profile.id);
        let same_account = previous
            .as_ref()
            .is_some_and(|old| old.server == profile.server && old.username == profile.username);
        let prior_seed =
            if same_account && previous.as_ref().is_some_and(|old| old.otp_secret_stored) {
                self.vault.get(&profile.id, "totp")?
            } else {
                None
            };
        profile.otp_parameters = previous
            .as_ref()
            .filter(|_| same_account)
            .and_then(|old| old.otp_parameters.clone());
        profile.otp_pending = previous
            .as_ref()
            .is_some_and(|old| same_account && old.otp_pending);
        let prior_proxy = self.vault.get(&profile.id, "proxy")?;
        let next_password = if !profile.save_password {
            None
        } else {
            password
                .filter(|s| !s.is_empty())
                .map(|s| SecretString::from(s.to_string()))
                .or(prior_password)
        };
        let next_seed = if !profile.two_factor {
            None
        } else if let Some(seed) = seed {
            profile.otp_parameters = None;
            profile.otp_pending = false;
            if seed.is_empty() {
                None
            } else {
                Some(SecretString::from(totp::normalize(&seed)?.to_string()))
            }
        } else {
            prior_seed
        };
        let next_proxy = if !profile.proxy_enabled {
            None
        } else {
            proxy_password
                .filter(|s| !s.is_empty())
                .map(|s| SecretString::from(s.to_string()))
                .or(prior_proxy)
        };
        profile.password_stored = next_password.is_some();
        profile.otp_secret_stored = next_seed.is_some();
        if !profile.two_factor {
            profile.otp_pending = false;
            profile.otp_parameters = None;
        }
        profile.proxy_password_stored = next_proxy.is_some();
        changes.push(("password", next_password));
        changes.push(("totp", next_seed));
        changes.push(("proxy", next_proxy));
        if !profile.otp_pending {
            changes.push(("totp-pending", None));
        }
        vault::transaction(&*self.vault, &profile.id, changes, || {
            self.db.lock().unwrap().save_profile(&profile)
        })?;
        self.logs.push("info", "desktop", "连接配置已保存");
        self.db.lock().unwrap().profiles()
    }
    pub fn delete_profile(&self, id: &str) -> Result<Vec<Profile>, String> {
        let _operation = self.configuration.lock().unwrap();
        self.ensure_mutable()?;
        self.check_editable(id)?;
        self.db.lock().unwrap().profile(id)?;
        vault::transaction(
            &*self.vault,
            id,
            vec![
                ("password", None),
                ("totp", None),
                ("totp-pending", None),
                ("proxy", None),
            ],
            || self.db.lock().unwrap().delete_profile(id),
        )?;
        self.db.lock().unwrap().profiles()
    }
    fn remember_password(&self, id: &str, password: &SecretString) -> Result<(), String> {
        let _operation = self.configuration.lock().unwrap();
        if self.lifecycle.closing() {
            return Ok(());
        }
        let mut profile = self.db.lock().unwrap().profile(id)?;
        if profile.save_password {
            profile.password_stored = true;
            vault::transaction(
                &*self.vault,
                id,
                vec![("password", Some(password.clone()))],
                || self.db.lock().unwrap().save_profile(&profile),
            )?;
            let _ = self.app.emit("vpn:profiles-changed", ());
        }
        Ok(())
    }
    pub(super) fn client_config(
        &self,
        profile: &Profile,
        auth: AuthConfig,
    ) -> Result<ClientConfig, String> {
        let mut config = ClientConfig::new(&profile.server, auth).map_err(|e| e.to_string())?;
        config.tls.backend = profile.tls_backend;
        config.tls.insecure = profile.insecure;
        config.tls.ca_file = (!profile.ca_file.is_empty()).then(|| profile.ca_file.clone().into());
        config.tls.server_pins = profile.server_pins.clone();
        config.tls.openssl_ciphers =
            (!profile.openssl_ciphers.is_empty()).then(|| profile.openssl_ciphers.clone());
        if profile.proxy_enabled {
            let mut proxy = url::Url::parse(&format!(
                "{}://{}:{}",
                profile.proxy_scheme, profile.proxy_host, profile.proxy_port
            ))
            .map_err(|_| "代理配置无效")?;
            proxy
                .set_username(&profile.proxy_username)
                .map_err(|_| "代理用户名无效")?;
            if let Some(secret) = self.vault.get(&profile.id, "proxy")? {
                self.logs.secret(secret.expose_secret());
                proxy
                    .set_password(Some(secret.expose_secret()))
                    .map_err(|_| "代理密码无效")?;
            }
            config.proxy = Some(proxy);
        }
        config.resolve = if profile.resolve.is_empty() {
            None
        } else {
            Some(profile.resolve.parse().map_err(|_| "解析地址无效")?)
        };
        if !profile.hostname.is_empty() {
            config.hostname = profile.hostname.clone();
        }
        if !profile.user_agent.is_empty() {
            config.user_agent = profile.user_agent.clone();
        }
        config.connect_timeout = Duration::from_secs(profile.connect_timeout);
        config.reconnect.timeout = Duration::from_secs(profile.reconnect_timeout);
        config.dpd_interval = profile.dpd.map(Duration::from_secs);
        config.network.interface_name =
            (!profile.interface_name.is_empty()).then(|| profile.interface_name.clone());
        config.network.mtu = profile.mtu;
        config.network.route_mode = profile.route_mode;
        config.network.manage_dns = profile.manage_dns;
        config.network.include_routes = profile
            .include_routes
            .iter()
            .map(|r| r.parse().map_err(|_| "包含路由无效"))
            .collect::<Result<_, _>>()?;
        config.network.exclude_routes = profile
            .exclude_routes
            .iter()
            .map(|r| r.parse().map_err(|_| "排除路由无效"))
            .collect::<Result<_, _>>()?;
        Ok(config)
    }
    pub fn start(self: &Arc<Self>, id: &str) -> Result<(), String> {
        let _operation = self.configuration.lock().unwrap();
        let mut active = self.active.lock().unwrap();
        if self.lifecycle.state() != "idle" {
            return Err("关闭选择、退出确认或清理期间不能开始新的连接".into());
        }
        if active.is_some() {
            return Err("已有配置正在连接或断开，请等待当前会话结束".into());
        }
        if self.enrollment.lock().unwrap().is_some() {
            return Err("请先等待 OTP 注册完成".into());
        }
        if !crate::platform::administrator() {
            return Err(
                "连接 VPN 需要管理员/root 权限。请退出后以管理员身份重新运行客户端。".into(),
            );
        }
        let profile = self.db.lock().unwrap().profile(id)?;
        profile.validate()?;
        if profile.two_factor
            && (profile.otp_pending
                || (profile.otp_mode == OtpMode::Automatic && !profile.otp_secret_stored))
        {
            return Err(
                "请先完成 OTP 注册；如需手动输入验证码，请选择手动模式并移除待注册密钥".into(),
            );
        }
        let provider = Arc::new(DesktopPassword {
            owner: Arc::downgrade(self),
            profile: profile.clone(),
            password: Mutex::new(None),
        });
        let config = self.client_config(
            &profile,
            AuthConfig::DeferredPassword {
                username: profile.username.clone(),
                authgroup: profile.authgroup.clone(),
                provider,
            },
        )?;
        let client = VpnClient::new(config).map_err(|e| self.logs.redact(&e.to_string()))?;
        let handle = client.handle();
        let events = handle.subscribe();
        let session_id = uuid::Uuid::new_v4().to_string();
        self.db
            .lock()
            .unwrap()
            .begin_session(&profile, &session_id)?;
        let (done, receiver) = watch::channel(false);
        *active = Some(Active {
            id: session_id.clone(),
            profile_id: id.into(),
            handle: handle.clone(),
            done: receiver,
        });
        *self.snapshot.lock().unwrap() = LiveSession {
            profile_id: Some(id.into()),
            profile_name: Some(profile.name),
            state: "Connecting".into(),
            ..Default::default()
        };
        drop(active);
        self.lifecycle.refresh_tray(&self.app);
        let _ = self.app.emit("vpn:session", self.snapshot());
        let owner = self.clone();
        tauri::async_runtime::spawn(async move {
            owner
                .run_session(session_id, client, handle, events, done)
                .await;
        });
        Ok(())
    }
    async fn run_session(
        self: Arc<Self>,
        id: String,
        client: VpnClient,
        handle: SessionHandle,
        mut events: tokio::sync::broadcast::Receiver<ClientEvent>,
        done: watch::Sender<bool>,
    ) {
        let operation = async { client.connect().await?.run().await };
        tokio::pin!(operation);
        let mut timer = tokio::time::interval(Duration::from_secs(1));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut connected_since = None::<Instant>;
        let mut elapsed = Duration::ZERO;
        let mut sample_at = Instant::now();
        let mut last_stats = handle.stats();
        let mut checkpoints = 0;
        let result = loop {
            tokio::select! {
                result = &mut operation => break result,
                event = events.recv() => match event {
                    Ok(ClientEvent::StateChanged(state)) => {
                        if state == ConnectionState::Connected && connected_since.is_none() { connected_since = Some(Instant::now()); }
                        if state != ConnectionState::Connected && let Some(start) = connected_since.take() { elapsed += start.elapsed(); }
                        self.snapshot.lock().unwrap().state = if state == ConnectionState::Disconnected { "Disconnecting".into() } else { format!("{state:?}") };
                        self.lifecycle.refresh_tray(&self.app);
                        let _ = self.app.emit("vpn:session", self.snapshot());
                    }
                    Ok(ClientEvent::NetworkConfigured(network)) => { self.snapshot.lock().unwrap().network = Some(network); }
                    Ok(ClientEvent::Error(error)) => { self.snapshot.lock().unwrap().error = Some(self.logs.redact(&error)); }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        let state = handle.state();
                        if state == ConnectionState::Connected && connected_since.is_none() { connected_since = Some(Instant::now()); }
                        if state != ConnectionState::Connected && let Some(start) = connected_since.take() { elapsed += start.elapsed(); }
                        self.snapshot.lock().unwrap().state = if state == ConnectionState::Disconnected { "Disconnecting".into() } else { format!("{state:?}") };
                        self.lifecycle.refresh_tray(&self.app);
                    }
                    _ => {}
                },
                _ = timer.tick() => {
                    let stats = handle.stats();
                    let seconds = sample_at.elapsed().as_secs_f64().max(0.01);
                    {
                        let mut live = self.snapshot.lock().unwrap();
                        live.connected_seconds = (elapsed + connected_since.map(|start| start.elapsed()).unwrap_or_default()).as_secs();
                        live.download_rate = stats.bytes_received.saturating_sub(last_stats.bytes_received) as f64 / seconds;
                        live.upload_rate = stats.bytes_sent.saturating_sub(last_stats.bytes_sent) as f64 / seconds;
                        live.stats = stats.clone();
                    }
                    last_stats = stats; sample_at = Instant::now();
                    let live = self.snapshot();
                    let _ = self.app.emit("vpn:session", &live);
                    checkpoints += 1;
                    if checkpoints % 5 == 0 {
                        let owner = self.clone(); let id = id.clone();
                        tauri::async_runtime::spawn_blocking(move || {
                            if let Err(error) = owner.db.lock().unwrap().checkpoint(&id, &live, false) { owner.logs.push("error", "desktop", &error); }
                        });
                    }
                }
            }
        };
        if let Some(start) = connected_since {
            elapsed += start.elapsed();
        }
        // connect()/run() has awaited network rollback and remote logout here.
        let mut active = self.active.lock().unwrap();
        if active.as_ref().is_some_and(|active| active.id == id) {
            let mut live = self.snapshot();
            live.state = "Disconnected".into();
            live.connected_seconds = elapsed.as_secs();
            live.stats = handle.stats();
            live.download_rate = 0.;
            live.upload_rate = 0.;
            match result {
                Err(VpnError::Cancelled) => live.error = None,
                Err(error) => live.error = Some(self.logs.redact(&error.to_string())),
                Ok(()) => {}
            }
            if let Err(error) = self.db.lock().unwrap().checkpoint(&id, &live, true) {
                self.logs.push("error", "desktop", &error);
            }
            self.pending.lock().unwrap().take();
            *active = None;
            *self.snapshot.lock().unwrap() = live.clone();
            let _ = self.app.emit("vpn:session", live);
            let _ = self.app.emit("vpn:history-changed", ());
            self.logs.clear_secrets();
        }
        drop(active);
        self.lifecycle.refresh_tray(&self.app);
        let _ = done.send(true);
    }
    pub async fn disconnect(&self) {
        self.cancel_otp_enrollment().await;
        let active = self
            .active
            .lock()
            .unwrap()
            .as_ref()
            .map(|a| (a.handle.clone(), a.done.clone()));
        if let Some((handle, mut done)) = active {
            handle.disconnect();
            let _ = done.wait_for(|finished| *finished).await;
        }
    }
    pub fn submit(&self, input: CredentialInput) -> Result<(), String> {
        let mut pending = self.pending.lock().unwrap();
        if pending.as_ref().is_none_or(|p| p.request.id != input.id) {
            return Err("认证请求已过期".into());
        }
        pending
            .take()
            .expect("checked pending request")
            .sender
            .send(input)
            .map_err(|_| "认证请求已取消".into())
    }
}

struct DesktopPassword {
    owner: Weak<Controller>,
    profile: Profile,
    password: Mutex<Option<SecretString>>,
}
#[async_trait]
impl PasswordProvider for DesktopPassword {
    fn cache_password(&self) -> bool {
        !self.profile.two_factor
    }
    async fn password(&self, challenge: PasswordChallenge) -> arraysslvpn::Result<SecretString> {
        let owner = self.owner.upgrade().ok_or(VpnError::Cancelled)?;
        let cached = self.password.lock().unwrap().clone();
        let mut password = if cached.is_some() {
            cached
        } else if self.profile.save_password {
            let vault = owner.vault.clone();
            let id = self.profile.id.clone();
            tauri::async_runtime::spawn_blocking(move || vault.get(&id, "password"))
                .await
                .map_err(|_| VpnError::Config("密钥库任务失败".into()))?
                .map_err(VpnError::Config)?
        } else {
            None
        };
        let needs_otp = self.profile.two_factor && !self.profile.otp_secret_stored;
        let mut manual_otp = Zeroizing::new(String::new());
        if password.is_none() || needs_otp {
            let request = CredentialRequest {
                id: uuid::Uuid::new_v4().to_string(),
                profile_id: self.profile.id.clone(),
                needs_password: password.is_none(),
                needs_otp,
            };
            let (sender, receiver) = oneshot::channel();
            *owner.pending.lock().unwrap() = Some(Pending {
                request: request.clone(),
                sender,
            });
            let _ = owner.app.emit("vpn:credentials", &request);
            let reply = tokio::select! { _ = challenge.cancellation.cancelled() => Err(VpnError::Cancelled), reply = receiver => reply.map_err(|_| VpnError::Cancelled) };
            {
                let mut pending = owner.pending.lock().unwrap();
                if pending.as_ref().is_some_and(|p| p.request.id == request.id) {
                    pending.take();
                }
            }
            let mut reply = reply?;
            let entered = Zeroizing::new(std::mem::take(&mut reply.password));
            manual_otp = Zeroizing::new(std::mem::take(&mut reply.otp));
            if password.is_none() {
                if entered.is_empty() {
                    return Err(VpnError::Config("密码不能为空".into()));
                }
                let secret = SecretString::from(entered.to_string());
                if self.profile.save_password {
                    let remember = owner.clone();
                    let id = self.profile.id.clone();
                    let next = secret.clone();
                    tauri::async_runtime::spawn_blocking(move || {
                        remember.remember_password(&id, &next)
                    })
                    .await
                    .map_err(|_| VpnError::Config("密钥库任务失败".into()))?
                    .map_err(VpnError::Config)?;
                }
                password = Some(secret);
            }
        }
        let password = password.ok_or_else(|| VpnError::Config("缺少密码".into()))?;
        owner.logs.secret(password.expose_secret());
        *self.password.lock().unwrap() = Some(password.clone());
        if !self.profile.two_factor {
            return Ok(password);
        }
        let code = if self.profile.otp_secret_stored {
            let vault = owner.vault.clone();
            let id = self.profile.id.clone();
            let seed = tauri::async_runtime::spawn_blocking(move || vault.get(&id, "totp"))
                .await
                .map_err(|_| VpnError::Config("密钥库任务失败".into()))?
                .map_err(VpnError::Config)?
                .ok_or_else(|| VpnError::Config("系统密钥库中没有此配置的 BASE32 密钥".into()))?;
            owner.logs.secret(seed.expose_secret());
            let parameters = tokio::select! {
                _ = challenge.cancellation.cancelled() => return Err(VpnError::Cancelled),
                parameters = owner.otp_parameters(&self.profile) => parameters.map_err(VpnError::Config)?,
            };
            let offset = parameters.time_offset_seconds.unwrap_or(0);
            let time = totp::adjusted_time(now_ms(), offset).map_err(VpnError::Config)?;
            let remaining = parameters.period - (time % parameters.period);
            if remaining <= 2.min(parameters.period / 4) {
                tokio::select! { _ = challenge.cancellation.cancelled() => return Err(VpnError::Cancelled), _ = tokio::time::sleep(Duration::from_secs(remaining)) => {} }
            }
            totp::code(
                seed.expose_secret(),
                parameters.period,
                totp::adjusted_time(now_ms(), offset).map_err(VpnError::Config)?,
            )
            .map_err(VpnError::Config)?
        } else {
            if manual_otp.len() != 6 || !manual_otp.bytes().all(|b| b.is_ascii_digit()) {
                return Err(VpnError::Config("验证码位数或格式不正确".into()));
            }
            manual_otp
        };
        owner.logs.secret(&code);
        let combined = SecretString::from(format!("{}{}", password.expose_secret(), *code));
        owner.logs.secret(combined.expose_secret());
        Ok(combined)
    }
}
