use crate::model::{HistoryItem, LiveSession, Preferences, Profile, Usage, now_ms};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;

pub struct Database(Connection);
type Result<T> = std::result::Result<T, String>;

impl Database {
    pub fn open(path: &Path) -> Result<Self> {
        let connection = Connection::open(path).map_err(|_| "无法打开本地数据库")?;
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| "数据库初始化失败")?;
        connection.execute_batch("PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS profiles (id TEXT PRIMARY KEY, data TEXT NOT NULL, updated_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS preferences (id INTEGER PRIMARY KEY CHECK (id=1), data TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY, profile_name TEXT NOT NULL, server TEXT NOT NULL,
                started_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, ended_at INTEGER,
                connected_seconds INTEGER NOT NULL DEFAULT 0, bytes_sent INTEGER NOT NULL DEFAULT 0,
                bytes_received INTEGER NOT NULL DEFAULT 0, state TEXT NOT NULL);
            UPDATE sessions SET ended_at=updated_at, state='interrupted' WHERE ended_at IS NULL;")
            .map_err(|_| "数据库建表或迁移失败")?;
        migrate_otp_profiles(&connection)?;
        Ok(Self(connection))
    }
    pub fn profiles(&self) -> Result<Vec<Profile>> {
        let mut query = self
            .0
            .prepare("SELECT data FROM profiles ORDER BY updated_at DESC, id")
            .map_err(|_| "配置读取失败")?;
        query
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|_| "配置读取失败")?
            .map(|row| {
                serde_json::from_str(&row.map_err(|_| "配置读取失败")?)
                    .map_err(|_| "配置数据损坏".into())
            })
            .collect()
    }
    pub fn profile(&self, id: &str) -> Result<Profile> {
        let json: String = self
            .0
            .query_row("SELECT data FROM profiles WHERE id=?1", [id], |row| {
                row.get(0)
            })
            .optional()
            .map_err(|_| "配置读取失败")?
            .ok_or("配置不存在")?;
        serde_json::from_str(&json).map_err(|_| "配置数据损坏".into())
    }
    pub fn save_profile(&self, profile: &Profile) -> Result<()> {
        let json = serde_json::to_string(profile).map_err(|_| "配置序列化失败")?;
        self.0.execute("INSERT INTO profiles VALUES (?1,?2,?3) ON CONFLICT(id) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at",
            params![profile.id, json, now_ms()]).map_err(|_| "配置保存失败")?;
        Ok(())
    }
    pub fn delete_profile(&self, id: &str) -> Result<()> {
        self.0
            .execute("DELETE FROM profiles WHERE id=?1", [id])
            .map_err(|_| "配置删除失败")?;
        Ok(())
    }
    pub fn preferences(&self) -> Result<Preferences> {
        let json: Option<String> = self
            .0
            .query_row("SELECT data FROM preferences WHERE id=1", [], |row| {
                row.get(0)
            })
            .optional()
            .map_err(|_| "偏好读取失败")?;
        json.map(|json| serde_json::from_str(&json).map_err(|_| "偏好数据损坏".into()))
            .unwrap_or(Ok(Preferences::default()))
    }
    pub fn save_preferences(&self, preferences: &Preferences) -> Result<()> {
        preferences.validate()?;
        self.0.execute("INSERT INTO preferences VALUES (1, ?1) ON CONFLICT(id) DO UPDATE SET data=excluded.data",
            [serde_json::to_string(preferences).map_err(|_| "偏好序列化失败")?]).map_err(|_| "偏好保存失败")?;
        Ok(())
    }
    pub fn begin_session(&self, profile: &Profile, id: &str) -> Result<()> {
        self.0.execute("INSERT INTO sessions (id,profile_name,server,started_at,updated_at,state) VALUES (?1,?2,?3,?4,?4,'Connecting')",
            params![id, profile.name, profile.server, now_ms()]).map_err(|_| "连接记录创建失败")?;
        Ok(())
    }
    pub fn checkpoint(&self, id: &str, session: &LiveSession, finished: bool) -> Result<()> {
        let now = now_ms();
        self.0.execute("UPDATE sessions SET updated_at=?2, ended_at=?3, connected_seconds=?4, bytes_sent=?5, bytes_received=?6, state=?7 WHERE id=?1 AND ended_at IS NULL",
            params![id, now, finished.then_some(now), session.connected_seconds, session.stats.bytes_sent, session.stats.bytes_received,
                if finished && session.error.is_some() { "failed" } else { &session.state }]).map_err(|_| "流量统计保存失败")?;
        Ok(())
    }
    pub fn usage(&self) -> Result<Usage> {
        let mut usage = self.0.query_row("SELECT COALESCE(SUM(bytes_sent),0),COALESCE(SUM(bytes_received),0),COALESCE(SUM(connected_seconds),0),COUNT(*) FROM sessions", [], |row| {
            Ok(Usage { bytes_sent: row.get(0)?, bytes_received: row.get(1)?, connected_seconds: row.get(2)?, sessions: row.get(3)?, recent: vec![] })
        }).map_err(|_| "统计读取失败")?;
        let mut query = self.0.prepare("SELECT id,profile_name,server,started_at,ended_at,connected_seconds,bytes_sent,bytes_received,state FROM sessions ORDER BY started_at DESC LIMIT 100").map_err(|_| "历史记录读取失败")?;
        usage.recent = query
            .query_map([], |row| {
                Ok(HistoryItem {
                    id: row.get(0)?,
                    profile_name: row.get(1)?,
                    server: row.get(2)?,
                    started_at: row.get(3)?,
                    ended_at: row.get(4)?,
                    connected_seconds: row.get(5)?,
                    bytes_sent: row.get(6)?,
                    bytes_received: row.get(7)?,
                    state: row.get(8)?,
                })
            })
            .map_err(|_| "历史记录读取失败")?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| "历史记录读取失败")?;
        Ok(usage)
    }
}

fn migrate_otp_profiles(connection: &Connection) -> Result<()> {
    let mut query = connection
        .prepare("SELECT id,data FROM profiles")
        .map_err(|_| "OTP 配置迁移失败")?;
    let rows = query
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|_| "OTP 配置迁移失败")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| "OTP 配置迁移失败")?;
    drop(query);
    for (id, json) in rows {
        let mut value: serde_json::Value =
            serde_json::from_str(&json).map_err(|_| "配置数据损坏")?;
        let object = value.as_object_mut().ok_or("配置数据损坏")?;
        if !object.contains_key("autoTotp") && !object.contains_key("totpAlgorithm") {
            continue;
        }
        let auto = object
            .remove("autoTotp")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let standard = object
            .remove("totpAlgorithm")
            .and_then(|v| v.as_str().map(str::to_owned))
            .as_deref()
            == Some("SHA1")
            && object.get("totpDigits").and_then(|v| v.as_u64()) == Some(6);
        object.remove("totpDigits");
        let period = object
            .remove("totpPeriod")
            .and_then(|v| v.as_u64())
            .unwrap_or(30);
        let stored = object
            .remove("totpStored")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        object.insert("otpMode".into(), "manual".into());
        object.insert(
            "otpSecretStored".into(),
            (auto && standard && stored).into(),
        );
        object.insert(
            "otpParameters".into(),
            if auto && standard && stored {
                serde_json::json!({"period":period.clamp(1,300),"time_offset_seconds":0})
            } else {
                serde_json::Value::Null
            },
        );
        object.insert("otpPending".into(), false.into());
        let profile: Profile = serde_json::from_value(value).map_err(|_| "OTP 配置迁移失败")?;
        connection
            .execute(
                "UPDATE profiles SET data=?2 WHERE id=?1",
                params![
                    id,
                    serde_json::to_string(&profile).map_err(|_| "OTP 配置迁移失败")?
                ],
            )
            .map_err(|_| "OTP 配置迁移失败")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_otp_fields_are_removed_without_losing_accounts_or_supported_keys() {
        for standard in [true, false] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("migration.sqlite3");
            let db = Database::open(&path).unwrap();
            let mut legacy: serde_json::Value =
                serde_json::from_str(include_str!("../../fixtures/profile.json")).unwrap();
            let object = legacy.as_object_mut().unwrap();
            for key in ["otpMode", "otpSecretStored", "otpParameters", "otpPending"] {
                object.remove(key);
            }
            object.insert("autoTotp".into(), true.into());
            object.insert("totpStored".into(), true.into());
            object.insert(
                "totpAlgorithm".into(),
                if standard { "SHA1" } else { "SHA512" }.into(),
            );
            object.insert("totpDigits".into(), 6.into());
            object.insert("totpPeriod".into(), 60.into());
            let id = legacy["id"].as_str().unwrap().to_owned();
            let username = legacy["username"].as_str().unwrap().to_owned();
            db.0.execute(
                "INSERT INTO profiles VALUES (?1,?2,1)",
                params![id, legacy.to_string()],
            )
            .unwrap();
            drop(db);
            let db = Database::open(&path).unwrap();
            let profile = db.profile(&id).unwrap();
            assert_eq!(profile.username, username);
            assert!(profile.two_factor);
            assert_eq!(profile.otp_secret_stored, standard);
            assert!(profile.otp_mode == crate::model::OtpMode::Manual);
            let json = serde_json::to_value(&profile).unwrap();
            for key in [
                "autoTotp",
                "totpStored",
                "totpAlgorithm",
                "totpDigits",
                "totpPeriod",
            ] {
                assert!(json.get(key).is_none());
            }
            if standard {
                assert_eq!(profile.otp_parameters.unwrap().period, 60);
            }
            drop(db);
            assert_eq!(Database::open(&path).unwrap().profiles().unwrap().len(), 1);
        }
    }
    #[test]
    fn sessions_are_checkpointed_without_double_counting_and_recovered_after_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("test.sqlite3");
        let db = Database::open(&path).unwrap();
        let profile: Profile =
            serde_json::from_str(include_str!("../../fixtures/profile.json")).unwrap();
        db.save_profile(&profile).unwrap();
        db.begin_session(&profile, "finished").unwrap();
        let mut live = LiveSession {
            connected_seconds: 30,
            state: "Connected".into(),
            ..Default::default()
        };
        live.stats.bytes_sent = 100;
        live.stats.bytes_received = 200;
        db.checkpoint("finished", &live, false).unwrap();
        live.stats.bytes_received = 300;
        db.checkpoint("finished", &live, true).unwrap();
        db.checkpoint("finished", &LiveSession::default(), false)
            .unwrap();
        assert_eq!(db.usage().unwrap().bytes_received, 300);
        db.begin_session(&profile, "interrupted").unwrap();
        db.checkpoint("interrupted", &live, false).unwrap();
        drop(db);
        let db = Database::open(&path).unwrap();
        let usage = db.usage().unwrap();
        assert_eq!(
            (
                usage.bytes_sent,
                usage.bytes_received,
                usage.connected_seconds
            ),
            (200, 600, 60)
        );
        assert!(usage.recent.iter().all(|s| s.ended_at.is_some()));
        assert!(usage.recent.iter().any(|s| s.state == "interrupted"));
        assert_eq!(db.profiles().unwrap().len(), 1);
    }
    #[test]
    fn profile_payload_rejects_passwords_and_urls_with_credentials() {
        let mut payload: serde_json::Value =
            serde_json::from_str(include_str!("../../fixtures/profile.json")).unwrap();
        payload["password"] = "not-for-sqlite".into();
        assert!(serde_json::from_value::<Profile>(payload.clone()).is_err());
        payload.as_object_mut().unwrap().remove("password");
        payload["server"] = "https://user:password@vpn.example.test".into();
        assert!(
            serde_json::from_value::<Profile>(payload)
                .unwrap()
                .validate()
                .is_err()
        );
    }
}
