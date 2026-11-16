use super::{Controller, OtpOperation};
use crate::{model::*, totp, vault};
use arraysslvpn::{AuthConfig, ExposeSecret, SecretString, VpnClient, VpnError};
use std::sync::Arc;
use tauri::Emitter;
use tokio::sync::watch;

impl Controller {
    fn prepare_otp(
        &self,
        mut input: OtpEnrollmentInput,
        cancel: arraysslvpn::CancellationToken,
    ) -> Result<(Profile, VpnClient, SecretString), String> {
        let _configuration = self.configuration.lock().unwrap();
        if !input.confirm_overwrite {
            return Err("请先确认注册会覆盖网关中已有的 OTP 密钥，旧设备的验证码可能失效".into());
        }
        if self.lifecycle.state() != "idle" || self.is_active() || cancel.is_cancelled() {
            return Err("请先断开 VPN 并等待其他操作结束后再注册 OTP".into());
        }
        let mut profile = self.db.lock().unwrap().profile(&input.id)?;
        profile.validate()?;
        if !profile.two_factor {
            return Err("请先启用两步验证并保存配置".into());
        }
        let password = if input.password.is_empty() {
            self.vault
                .get(&profile.id, "password")?
                .ok_or("请输入账号静态密码（不要追加验证码）")?
        } else {
            SecretString::from(std::mem::take(&mut input.password))
        };
        self.logs.secret(password.expose_secret());
        let seed = if profile.otp_pending {
            self.vault
                .get(&profile.id, "totp-pending")?
                .ok_or("待注册密钥缺失，请移除后重新注册")?
        } else {
            SecretString::from(totp::generate_secret().to_string())
        };
        self.logs.secret(seed.expose_secret());
        let config = self.client_config(
            &profile,
            AuthConfig::Password {
                username: profile.username.clone(),
                password,
                authgroup: profile.authgroup.clone(),
            },
        )?;
        let client =
            VpnClient::new(config).map_err(|error| self.logs.redact(&error.to_string()))?;
        if cancel.is_cancelled() {
            return Err("OTP 注册已取消".into());
        }
        profile.otp_pending = true;
        // Durably keep the candidate BEFORE an irreversible remote POST. An
        // interrupted/ambiguous result must never lose the only usable new seed.
        vault::transaction(
            &*self.vault,
            &profile.id,
            vec![("totp-pending", Some(seed.clone()))],
            || self.db.lock().unwrap().save_profile(&profile),
        )?;
        let _ = self.app.emit("vpn:profiles-changed", ());
        self.logs
            .push("info", "otp", "正在注册 OTP；网关已有注册将被覆盖");
        Ok((profile, client, seed))
    }
    pub async fn enroll_otp(
        self: &Arc<Self>,
        input: OtpEnrollmentInput,
    ) -> Result<Profile, String> {
        let cancel = arraysslvpn::CancellationToken::new();
        let (done, receiver) = watch::channel(false);
        {
            let mut operation = self.enrollment.lock().unwrap();
            if operation.is_some() {
                return Err("已有 OTP 注册正在进行".into());
            }
            *operation = Some(OtpOperation {
                profile_id: input.id.clone(),
                cancel: cancel.clone(),
                done: receiver,
            });
        }
        let owner = self.clone();
        let preparing = cancel.clone();
        let prepared =
            tauri::async_runtime::spawn_blocking(move || owner.prepare_otp(input, preparing))
                .await
                .map_err(|_| "OTP 注册准备任务失败".to_string())
                .and_then(|result| result);
        let (mut profile, client, seed) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                self.enrollment.lock().unwrap().take();
                let _ = done.send(true);
                return Err(error);
            }
        };
        let handle = client.handle();
        let operation = client.enroll_otp(seed.clone());
        tokio::pin!(operation);
        let result = tokio::select! {
            result = &mut operation => result,
            _ = cancel.cancelled() => { handle.disconnect(); operation.await }
        };
        let owner = self.clone();
        let finished = tauri::async_runtime::spawn_blocking(move || {
            let _configuration = owner.configuration.lock().unwrap();
            match result {
                Ok(enrolled) => {
                    profile.otp_mode = OtpMode::Automatic;
                    profile.otp_parameters = Some(enrolled.parameters);
                    profile.otp_secret_stored = true;
                    profile.otp_pending = false;
                    // The pending copy remains outside rollback until both the
                    // active key and its confirmed parameters are committed.
                    vault::promote_otp(&*owner.vault,&profile.id,seed,|| {
                        owner.db.lock().unwrap().save_profile(&profile)
                    }).map_err(|error|format!("网关已完成注册，但本地保存失败：{error}。候选密钥已保留，可重试同一密钥的注册。"))?;
                    owner.logs.push("info","otp","OTP 注册成功，密钥已保存到系统密钥库");
                    if profile.otp_parameters.as_ref().is_some_and(|parameters|parameters.time_offset_seconds.is_none()) {
                        owner.logs.push("warn","otp","注册成功，但网关校时失败；验证码暂使用本机时间，请检查系统时间");
                    }
                    Ok(profile)
                }
                Err(error) => {
                    let uncertain = matches!(error,VpnError::OtpEnrollmentUncertain(_));
                    if !uncertain {
                        profile.otp_pending = false;
                        vault::transaction(&*owner.vault,&profile.id,vec![("totp-pending",None)],|| {
                            owner.db.lock().unwrap().save_profile(&profile)
                        })?;
                    }
                    let reason = owner.logs.redact(&error.to_string());
                    owner.logs.push("error","otp",&reason);
                    Err(if uncertain { format!("注册结果未确认，网关可能已覆盖旧密钥。候选密钥已保存在系统密钥库，重试将使用同一密钥。{reason}") } else { reason })
                }
            }
        }).await.map_err(|_|"OTP 注册保存任务失败".to_string()).and_then(|result|result);
        self.enrollment.lock().unwrap().take();
        let _ = done.send(true);
        let _ = self.app.emit("vpn:profiles-changed", ());
        finished
    }
    pub async fn cancel_otp_enrollment(&self) {
        let operation = self
            .enrollment
            .lock()
            .unwrap()
            .as_ref()
            .map(|operation| (operation.cancel.clone(), operation.done.clone()));
        if let Some((cancel, mut done)) = operation {
            cancel.cancel();
            let _ = done.wait_for(|done| *done).await;
        }
    }
    pub(super) async fn otp_parameters(
        self: &Arc<Self>,
        profile: &Profile,
    ) -> Result<arraysslvpn::OtpParameters, String> {
        if let Some(parameters) = &profile.otp_parameters {
            return Ok(parameters.clone());
        }
        let owner = self.clone();
        let snapshot = profile.clone();
        let client = tauri::async_runtime::spawn_blocking(move || {
            VpnClient::new(owner.client_config(&snapshot, AuthConfig::None)?)
                .map_err(|error| owner.logs.redact(&error.to_string()))
        })
        .await
        .map_err(|_| "OTP 参数任务失败")??;
        let parameters = client
            .otp_parameters()
            .await
            .map_err(|error| self.logs.redact(&error.to_string()))?;
        let owner = self.clone();
        let snapshot = profile.clone();
        let saved = parameters.clone();
        tauri::async_runtime::spawn_blocking(move || {
            let _configuration = owner.configuration.lock().unwrap();
            let mut profile = owner.db.lock().unwrap().profile(&snapshot.id)?;
            if profile.server == snapshot.server
                && profile.username == snapshot.username
                && profile.otp_secret_stored
            {
                profile.otp_parameters = Some(saved);
                owner.db.lock().unwrap().save_profile(&profile)?;
                let _ = owner.app.emit("vpn:profiles-changed", ());
            }
            Ok::<_, String>(())
        })
        .await
        .map_err(|_| "OTP 参数保存失败")??;
        Ok(parameters)
    }
    pub async fn otp_qr(self: &Arc<Self>, id: &str) -> Result<OtpQrCode, String> {
        let owner = self.clone();
        let id = id.to_owned();
        let profile =
            tauri::async_runtime::spawn_blocking(move || owner.db.lock().unwrap().profile(&id))
                .await
                .map_err(|_| "配置读取失败")??;
        if !profile.two_factor || !profile.otp_secret_stored || profile.otp_pending {
            return Err("请先导入密钥或完成 OTP 注册，再生成二维码".into());
        }
        self.otp_parameters(&profile).await?;
        let owner = self.clone();
        tauri::async_runtime::spawn_blocking(move || owner.otp_qr_saved(&profile.id))
            .await
            .map_err(|_| "二维码生成任务失败")?
    }
    fn otp_qr_saved(&self, id: &str) -> Result<OtpQrCode, String> {
        let _configuration = self.configuration.lock().unwrap();
        self.ensure_mutable()?;
        let profile = self.db.lock().unwrap().profile(id)?;
        if !profile.two_factor || !profile.otp_secret_stored || profile.otp_pending {
            return Err("请先导入密钥或完成 OTP 注册，再生成二维码".into());
        }
        let seed = self
            .vault
            .get(id, "totp")?
            .ok_or("系统密钥库中没有 OTP 密钥")?;
        self.logs.secret(seed.expose_secret());
        let period = profile
            .otp_parameters
            .as_ref()
            .map_or(30, |parameters| parameters.period);
        Ok(OtpQrCode {
            svg: totp::qr_svg(
                seed.expose_secret(),
                &profile.server,
                &profile.username,
                period,
            )?,
        })
    }
}
