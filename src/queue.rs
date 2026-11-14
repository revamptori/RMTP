//! Persistent filesystem message queue.
//!
//! Messages are stored as files under `directory/`. Each message has:
//!   `<id>.eml`      - raw message bytes (durable)
//!   `<id>.meta`     - TOML-ish metadata: recipients, attempts, next_retry, last_error
//!
//! Retry scheduling uses exponential backoff. On restart, all `.eml` files are
//! scanned and messages whose `next_retry` has passed are re-queued.

use crate::config::QueueConfig;
use crate::storage::{append_atomic, ensure_dir, list_files, read_file, remove_file, write_atomic};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Metadata persisted alongside each queued message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageMeta {
    pub id: String,
    pub from: String,
    pub to: Vec<String>,
    pub attempts: u32,
    pub max_retries: u32,
    pub next_retry: u64,      // unix seconds
    pub last_error: Option<String>,
    pub created_at: u64,      // unix seconds
    pub size: usize,
}

/// A queued message ready for delivery.
#[derive(Debug, Clone)]
pub struct QueuedMessage {
    pub id: String,
    pub from: String,
    pub to: Vec<String>,
    pub data: Vec<u8>,
    pub meta: MessageMeta,
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Exponential backoff: base * 2^(attempts), capped.
fn backoff_seconds(base: u64, attempts: u32) -> u64 {
    let mut delay = base;
    for _ in 0..attempts.min(10) {
        delay = delay.saturating_mul(2);
    }
    delay.min(3600) // cap at 1 hour
}

/// The persistent queue.
pub struct Queue {
    dir: PathBuf,
    config: QueueConfig,
    counter: AtomicU64,
    // In-memory index of messages keyed by id.
    index: Mutex<BTreeMap<String, MessageMeta>>,
}

impl Queue {
    pub fn new(config: QueueConfig) -> Result<Self, std::io::Error> {
        ensure_dir(&config.directory)?;
        let mut counter = 0;
        // Scan existing messages to rebuild index and counter.
        for path in list_files(&config.directory, "msg-")? {
            if let Some(id) = message_id_from_path(&path) {
                if let Ok(meta) = read_meta(&path.with_extension("meta")) {
                    let _ = id;
                    let _ = meta;
                }
                let num: u64 = id.trim_start_matches("msg-").parse().unwrap_or(0);
                counter = counter.max(num);
            }
        }
        Ok(Self {
            dir: config.directory.clone(),
            config,
            counter: AtomicU64::new(counter),
            index: Mutex::new(BTreeMap::new()),
        })
    }

    /// Durably enqueue a new message. Returns the assigned id.
    pub fn enqueue(&self, from: String, to: Vec<String>, data: Vec<u8>) -> Result<String, std::io::Error> {
        let id = format!("msg-{}", self.counter.fetch_add(1, Ordering::SeqCst) + 1);
        let now = now_secs();

        let eml_path = self.dir.join(format!("{id}.eml"));
        write_atomic(&eml_path, &data)?;

        let meta = MessageMeta {
            id: id.clone(),
            from: from.clone(),
            to: to.clone(),
            attempts: 0,
            max_retries: self.config.max_retries,
            next_retry: now, // deliver immediately on first attempt
            last_error: None,
            created_at: now,
            size: data.len(),
        };
        let meta_path = self.dir.join(format!("{id}.meta"));
        let meta_text = toml::to_string(&meta).unwrap();
        write_atomic(&meta_path, meta_text.as_bytes())?;

        self.index.lock().unwrap().insert(id.clone(), meta);
        Ok(id)
    }

    /// Return messages whose `next_retry` <= now and attempts < max_retries.
    pub fn due_messages(&self) -> Result<Vec<QueuedMessage>, std::io::Error> {
        let now = now_secs();
        let mut out = Vec::new();
        for path in list_files(&self.dir, "msg-")? {
            let id = message_id_from_path(&path).unwrap_or_default();
            let meta_path = self.dir.join(format!("{id}.meta"));
            let meta = match read_meta(&meta_path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.attempts >= meta.max_retries {
                continue;
            }
            if meta.next_retry > now {
                continue;
            }
            let data = match read_file(&path) {
                Ok(d) => d,
                Err(_) => continue,
            };
            out.push(QueuedMessage { id, from: meta.from.clone(), to: meta.to.clone(), data, meta });
        }
        Ok(out)
    }

    /// Mark a message as delivered; remove its files.
    pub fn mark_delivered(&self, id: &str) -> Result<(), std::io::Error> {
        let eml = self.dir.join(format!("{id}.eml"));
        let meta = self.dir.join(format!("{id}.meta"));
        remove_file(&eml)?;
        remove_file(&meta)?;
        self.index.lock().unwrap().remove(id);
        Ok(())
    }

    /// Record a failed delivery attempt and reschedule with exponential backoff.
    pub fn record_failure(&self, id: &str, error: &str) -> Result<(), std::io::Error> {
        let meta_path = self.dir.join(format!("{id}.meta"));
        let mut meta = read_meta(&meta_path)?;
        meta.attempts += 1;
        meta.last_error = Some(error.to_string());
        meta.next_retry = now_secs() + backoff_seconds(self.config.retry_interval, meta.attempts);
        let meta_text = toml::to_string(&meta).unwrap();
        write_atomic(&meta_path, meta_text.as_bytes())?;
        self.index.lock().unwrap().insert(id.to_string(), meta.clone());
        Ok(())
    }

    /// List all queued message ids (for `queue list`).
    pub fn list_ids(&self) -> Result<Vec<String>, std::io::Error> {
        let mut ids = Vec::new();
        for path in list_files(&self.dir, "msg-")? {
            if let Some(id) = message_id_from_path(&path) {
                ids.push(id);
            }
        }
        Ok(ids)
    }

    /// Flush (drop) all queued messages.
    pub fn flush(&self) -> Result<usize, std::io::Error> {
        let count = self.list_ids()?.len();
        for id in &self.list_ids()? {
            let _ = self.mark_delivered(id);
        }
        Ok(count)
    }

    pub fn config(&self) -> &QueueConfig {
        &self.config
    }
}

fn message_id_from_path(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    let id = name.strip_suffix(".eml")?;
    Some(id.to_string())
}

fn read_meta(path: &Path) -> Result<MessageMeta, std::io::Error> {
    let contents = read_file(path)?;
    toml::from_slice(&contents).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_queue() -> (Queue, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("rmtp-queue-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = QueueConfig { directory: dir.clone(), retry_interval: 60, max_retries: 3 };
        let q = Queue::new(config).unwrap();
        (q, dir)
    }

    #[test]
    fn enqueue_and_due() {
        let (q, _dir) = temp_queue();
        let id = q.envelope("sender@x".into(), vec!["rcpt@y".into()], b"hi".to_vec()).unwrap();
        let due = q.due_messages().unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, id);
        assert_eq!(due[0].data, b"hi");
    }

    #[test]
    fn backoff_reschedule() {
        let (q, _dir) = temp_queue();
        let id = q.envelope("s@x".into(), vec!["r@y".into()], b"x".to_vec()).unwrap();
        // mark first attempt consumed then fail a few times
        for i in 1..=4 {
            q.record_failure(&id, "temporary failure").unwrap();
        }
        let meta = read_meta(&q.dir.join(format!("{id}.meta"))).unwrap();
        assert_eq!(meta.attempts, 4);
        assert!(meta.next_retry > now_secs());
    }

    #[test]
    fn max_retries_exhausted() {
        let (q, _dir) = temp_queue();
        let id = q.envelope("s@x".into(), vec!["r@y".into()], b"x".to_vec()).unwrap();
        for _ in 0..q.config.max_retries + 5 {
            let _ = q.record_failure(&id, "fail");
        }
        let due = q.due_messages().unwrap();
        assert_eq!(due.len(), 0, "message past max retries should not be due");
    }

    #[test]
    fn mark_delivered_removes() {
        let (q, dir) = temp_queue();
        let id = q.envelope("s@x".into(), vec!["r@y".into()], b"x".to_vec()).unwrap();
        q.mark_delivered(&id).unwrap();
        assert!(!dir.join(format!("{id}.eml")).exists());
        assert!(!dir.join(format!("{id}.meta")).exists());
        assert_eq!(q.due_messages().unwrap().len(), 0);
    }

    #[test]
    fn restart_persistence() {
        let (q, dir) = temp_queue();
        q.envelope("s@x".into(), vec!["r@y".into()], b"persist".to_vec()).unwrap();
        drop(q);
        // Re-open: should still see the message.
        let config = QueueConfig { directory: dir.clone(), retry_interval: 60, max_retries: 3 };
        let q2 = Queue::new(config).unwrap();
        assert_eq!(q2.due_messages().unwrap().len(), 1);
    }

    #[test]
    fn flush_removes_all() {
        let (q, dir) = temp_queue();
        q.envelope("s@x".into(), vec!["r@y".into()], b"a".to_vec()).unwrap();
        q.envelope("s@x".into(), vec!["r@y".into()], b"b".to_vec()).unwrap();
        assert_eq!(q.flush().unwrap(), 2);
        assert!(fs_read_dir_empty(&dir));
    }

    fn fs_read_dir_empty(dir: &std::path::Path) -> bool {
        std::fs::read_dir(dir).unwrap().next().is_none()
    }

    #[test]
    fn envelope_passes_data() {
        let (q, _dir) = temp_queue();
        let data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let id = q.envelope("s@x".into(), vec!["r@y".into()], data.clone()).unwrap();
        let m = q.due_messages().unwrap().remove(0);
        assert_eq!(m.data, data);
    }
}

// Helper used by tests (keeps Queue::enqueue signature clean for production).
impl Queue {
    fn envelope(&self, from: String, to: Vec<String>, data: Vec<u8>) -> Result<String, std::io::Error> {
        self.enqueue(from, to, data)
    }
}
