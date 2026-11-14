use arraysslvpn::{ExposeSecret, SecretString};

pub trait SecretStore: Send + Sync {
    fn get(&self, profile: &str, kind: &str) -> Result<Option<SecretString>, String>;
    fn set(&self, profile: &str, kind: &str, secret: Option<&SecretString>) -> Result<(), String>;
}

pub struct SystemVault;
impl SystemVault {
    fn entry(profile: &str, kind: &str) -> Result<keyring::Entry, String> {
        keyring::Entry::new("com.taurusxin.arrayconnect", &format!("{profile}:{kind}"))
            .map_err(|_| "无法访问系统密钥库".into())
    }
}
impl SecretStore for SystemVault {
    fn get(&self, profile: &str, kind: &str) -> Result<Option<SecretString>, String> {
        match Self::entry(profile, kind)?.get_password() {
            Ok(password) => Ok(Some(password.into())),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err("无法读取系统密钥库；请确认密钥库已解锁且当前用户有访问权限".into()),
        }
    }
    fn set(&self, profile: &str, kind: &str, secret: Option<&SecretString>) -> Result<(), String> {
        let entry = Self::entry(profile, kind)?;
        let result = match secret {
            Some(secret) => entry.set_password(secret.expose_secret()),
            None => entry.delete_credential(),
        };
        match result {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err("系统密钥库写入失败；未将凭据保存到明文配置".into()),
        }
    }
}

/// Rolls back prior writes if a later keychain or database operation fails.
pub fn transaction<T>(
    vault: &dyn SecretStore,
    profile: &str,
    changes: Vec<(&str, Option<SecretString>)>,
    commit: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let undo = changes
        .iter()
        .map(|(kind, _)| vault.get(profile, kind).map(|previous| (*kind, previous)))
        .collect::<Result<Vec<_>, _>>()?;
    for (index, (kind, next)) in changes.iter().enumerate() {
        if let Err(error) = vault.set(profile, kind, next.as_ref()) {
            return rollback(vault, profile, &undo[..=index], error);
        }
    }
    match commit() {
        Ok(value) => Ok(value),
        Err(error) => rollback(vault, profile, &undo, error),
    }
}

fn rollback<T>(
    vault: &dyn SecretStore,
    profile: &str,
    undo: &[(&str, Option<SecretString>)],
    error: String,
) -> Result<T, String> {
    let mut failed = false;
    for (kind, previous) in undo.iter().rev() {
        failed |= vault.set(profile, kind, previous.as_ref()).is_err();
    }
    Err(if failed {
        format!("{error}；密钥库回滚失败，请在系统密钥库中检查该配置的凭据")
    } else {
        error
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashMap,
        sync::{
            Mutex,
            atomic::{AtomicBool, Ordering},
        },
    };
    struct MemoryVault {
        values: Mutex<HashMap<String, String>>,
        fail_next_totp: AtomicBool,
    }
    impl SecretStore for MemoryVault {
        fn get(&self, _: &str, kind: &str) -> Result<Option<SecretString>, String> {
            Ok(self
                .values
                .lock()
                .unwrap()
                .get(kind)
                .cloned()
                .map(Into::into))
        }
        fn set(&self, _: &str, kind: &str, secret: Option<&SecretString>) -> Result<(), String> {
            if kind == "totp" && self.fail_next_totp.swap(false, Ordering::SeqCst) {
                return Err("injected keychain failure".into());
            }
            let mut values = self.values.lock().unwrap();
            match secret {
                Some(secret) => {
                    values.insert(kind.into(), secret.expose_secret().into());
                }
                None => {
                    values.remove(kind);
                }
            }
            Ok(())
        }
    }
    #[test]
    fn partial_keychain_failure_and_database_failure_restore_old_secrets() {
        for fail_keychain in [true, false] {
            let vault = MemoryVault {
                values: Mutex::new(HashMap::from([("password".into(), "old-password".into())])),
                fail_next_totp: AtomicBool::new(fail_keychain),
            };
            let result: Result<(), String> = transaction(
                &vault,
                "profile",
                vec![
                    ("password", Some("new-password".into())),
                    ("totp", Some("new-seed".into())),
                ],
                || Err("injected database failure".into()),
            );
            assert!(result.is_err());
            assert_eq!(
                vault
                    .get("profile", "password")
                    .unwrap()
                    .unwrap()
                    .expose_secret(),
                "old-password"
            );
            assert!(vault.get("profile", "totp").unwrap().is_none());
        }
    }

    #[test]
    #[ignore = "explicit local credential-store integration check"]
    fn system_keyring_roundtrip() {
        let id = format!("integration-test-{}", uuid::Uuid::new_v4());
        struct Cleanup(String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = SystemVault.set(&self.0, "password", None);
            }
        }
        let cleanup = Cleanup(id.clone());
        SystemVault
            .set(
                &id,
                "password",
                Some(&SecretString::from("synthetic-credential-store-test")),
            )
            .unwrap();
        assert_eq!(
            SystemVault
                .get(&id, "password")
                .unwrap()
                .unwrap()
                .expose_secret(),
            "synthetic-credential-store-test"
        );
        drop(cleanup);
        assert!(SystemVault.get(&id, "password").unwrap().is_none());
    }
}
