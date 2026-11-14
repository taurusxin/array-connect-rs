use crate::model::now_ms;
use serde::Serialize;
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, AtomicU64, Ordering},
    },
};
use tracing::{
    Event, Level, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::{Layer, layer::Context};
use zeroize::Zeroizing;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogRecord {
    pub id: u64,
    pub timestamp: u64,
    pub level: String,
    pub target: String,
    pub message: String,
}
pub struct LogHub {
    records: Mutex<VecDeque<LogRecord>>,
    secrets: Mutex<Vec<Zeroizing<String>>>,
    level: AtomicU8,
    sequence: AtomicU64,
}
impl LogHub {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            records: Mutex::new(VecDeque::new()),
            secrets: Mutex::new(vec![]),
            level: AtomicU8::new(3),
            sequence: AtomicU64::new(0),
        })
    }
    pub fn set_level(&self, level: &str) {
        self.level.store(
            match level {
                "error" => 1,
                "warn" => 2,
                "debug" => 4,
                "trace" => 5,
                _ => 3,
            },
            Ordering::Relaxed,
        );
    }
    pub fn secret(&self, secret: &str) {
        if secret.is_empty() {
            return;
        }
        let mut secrets = self.secrets.lock().unwrap();
        if !secrets.iter().any(|old| old.as_str() == secret) {
            secrets.push(Zeroizing::new(secret.into()));
        }
    }
    pub fn redact(&self, message: &str) -> String {
        let secrets = self.secrets.lock().unwrap();
        let mut message = message.to_owned();
        // Replace long strings first so that a base password cannot expose the OTP suffix.
        let mut ordered: Vec<_> = secrets.iter().collect();
        ordered.sort_by_key(|s| std::cmp::Reverse(s.len()));
        for secret in ordered {
            message = message.replace(secret.as_str(), "[redacted]");
        }
        message
    }
    pub fn clear_secrets(&self) {
        self.secrets.lock().unwrap().clear();
    }
    pub fn push(&self, level: &str, target: &str, message: &str) {
        let record = LogRecord {
            id: self.sequence.fetch_add(1, Ordering::Relaxed) + 1,
            timestamp: now_ms(),
            level: level.into(),
            target: target.into(),
            message: self.redact(message),
        };
        let mut records = self.records.lock().unwrap();
        records.push_back(record);
        while records.len() > 2000 {
            records.pop_front();
        }
    }
    pub fn since(&self, cursor: u64) -> Vec<LogRecord> {
        self.records
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.id > cursor)
            .take(250)
            .cloned()
            .collect()
    }
    pub fn all(&self) -> Vec<LogRecord> {
        self.records.lock().unwrap().iter().cloned().collect()
    }
    pub fn clear(&self) {
        self.records.lock().unwrap().clear();
    }
}

pub struct LogLayer(pub Arc<LogHub>);
struct Fields(Vec<String>);
impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let name = field.name();
        let sensitive = ["password", "secret", "cookie", "authorization", "otp"]
            .iter()
            .any(|key| name.to_lowercase().contains(key));
        let value = if sensitive {
            "[redacted]".into()
        } else {
            format!("{value:?}")
        };
        self.0.push(if name == "message" {
            value.trim_matches('"').into()
        } else {
            format!("{name}={value}")
        });
    }
}
impl<S: Subscriber> Layer<S> for LogLayer {
    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        let metadata = event.metadata();
        let level = match *metadata.level() {
            Level::ERROR => 1,
            Level::WARN => 2,
            Level::INFO => 3,
            Level::DEBUG => 4,
            Level::TRACE => 5,
        };
        if level > self.0.level.load(Ordering::Relaxed)
            || !metadata.target().starts_with("arraysslvpn")
        {
            return;
        }
        let mut fields = Fields(vec![]);
        event.record(&mut fields);
        self.0.push(
            &metadata.level().as_str().to_lowercase(),
            metadata.target(),
            &fields.0.join(" "),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn redaction_precedes_buffering_and_buffer_is_bounded() {
        let hub = LogHub::new();
        hub.secret("test-password");
        hub.secret("test-password123456");
        hub.secret("BASE32-SECRET");
        for _ in 0..2100 {
            hub.push("trace", "test", "test-password123456 BASE32-SECRET");
        }
        let records = hub.all();
        assert_eq!(records.len(), 2000);
        assert!(records.iter().all(|r| r.message == "[redacted] [redacted]"));
    }
}
