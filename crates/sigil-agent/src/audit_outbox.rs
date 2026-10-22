use std::{
    collections::VecDeque,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sigil_proto::backend::v1::AgentAuditEvent;
use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::{Layer, layer::Context as SubscriberContext};

use crate::secure_path::{self, ProtectedFileMode};

pub const MAX_OUTBOX_EVENTS: usize = 100_000;

static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedAuditEvent {
    pub sequence: u64,
    pub occurred_at_unix_ms: i64,
    pub rpc: String,
    pub operation: String,
    pub device_id: String,
    pub token_serial: String,
    pub caller_os_user: String,
    pub caller_session_id: u32,
    pub outcome: String,
    pub code: String,
    pub grant_id: String,
    pub rotation_id: String,
}

impl QueuedAuditEvent {
    fn from_proto(event: AgentAuditEvent, sequence: u64) -> Self {
        Self {
            sequence,
            occurred_at_unix_ms: event.occurred_at_unix_ms,
            rpc: event.rpc,
            operation: event.operation,
            device_id: event.device_id,
            token_serial: event.token_serial,
            caller_os_user: event.caller_os_user,
            caller_session_id: event.caller_session_id,
            outcome: event.outcome,
            code: event.code,
            grant_id: event.grant_id,
            rotation_id: event.rotation_id,
        }
    }

    fn to_proto(&self) -> AgentAuditEvent {
        AgentAuditEvent {
            sequence: self.sequence,
            occurred_at_unix_ms: self.occurred_at_unix_ms,
            rpc: self.rpc.clone(),
            operation: self.operation.clone(),
            device_id: self.device_id.clone(),
            token_serial: self.token_serial.clone(),
            caller_os_user: self.caller_os_user.clone(),
            caller_session_id: self.caller_session_id,
            outcome: self.outcome.clone(),
            code: self.code.clone(),
            grant_id: self.grant_id.clone(),
            rotation_id: self.rotation_id.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingCompletion {
    pub rotation_id: String,
    pub applied: bool,
    pub created_at_unix_ms: i64,
}

#[derive(Serialize, Deserialize)]
struct OutboxCursor {
    next_sequence: u64,
    acknowledged_through: u64,
    #[serde(default)]
    dropped_events: u64,
}

struct OutboxState {
    cursor: OutboxCursor,
    events: VecDeque<QueuedAuditEvent>,
    overflow_logged: bool,
}

pub struct AuditOutbox {
    directory: PathBuf,
    queue_file: PathBuf,
    cursor_file: PathBuf,
    completions_file: PathBuf,
    max_events: usize,
    state: Mutex<OutboxState>,
}

impl AuditOutbox {
    pub fn open(directory: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_capacity(directory, MAX_OUTBOX_EVENTS)
    }

    pub fn open_with_capacity(directory: impl AsRef<Path>, max_events: usize) -> Result<Self> {
        if max_events < 2 {
            bail!("audit outbox capacity must be at least two events");
        }
        let directory = directory.as_ref().to_owned();
        let queue_file = directory.join("queue.jsonl");
        let cursor_file = directory.join("state.json");
        let completions_file = directory.join("pending-completions.json");
        let mut cursor = read_cursor(&cursor_file)?.unwrap_or_else(|| OutboxCursor {
            next_sequence: unix_time_micros(),
            acknowledged_through: 0,
            dropped_events: 0,
        });
        let mut events = read_events(&queue_file, cursor.acknowledged_through)?;
        if let Some(last_sequence) = events.back().map(|event| event.sequence) {
            cursor.next_sequence = cursor
                .next_sequence
                .max(last_sequence.saturating_add(1))
                .max(unix_time_micros());
        }
        cursor.next_sequence = cursor.next_sequence.max(
            cursor
                .acknowledged_through
                .saturating_add(1)
                .max(unix_time_micros()),
        );
        let excess_events = events.len().saturating_sub(max_events);
        for _ in 0..excess_events {
            events.pop_back();
        }
        cursor.dropped_events = cursor.dropped_events.saturating_add(excess_events as u64);
        let outbox = Self {
            directory,
            queue_file,
            cursor_file,
            completions_file,
            max_events,
            state: Mutex::new(OutboxState {
                cursor,
                events,
                overflow_logged: false,
            }),
        };
        {
            let state = outbox
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("audit outbox lock poisoned"))?;
            if excess_events > 0 {
                outbox.write_events(&state.events)?;
            }
            outbox.write_cursor(&state.cursor)?;
        }
        Ok(outbox)
    }

    pub fn enqueue(&self, event: AgentAuditEvent) -> Result<()> {
        let mut should_log_overflow = false;
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("audit outbox lock poisoned"))?;
            if state.events.len() >= self.max_events {
                state.cursor.dropped_events = state.cursor.dropped_events.saturating_add(1);
                should_log_overflow = !state.overflow_logged;
                state.overflow_logged = true;
                self.write_cursor(&state.cursor)?;
            } else {
                self.append_overflow_event(&mut state)?;
                if state.events.len() >= self.max_events {
                    state.cursor.dropped_events = state.cursor.dropped_events.saturating_add(1);
                    should_log_overflow = !state.overflow_logged;
                    state.overflow_logged = true;
                    self.write_cursor(&state.cursor)?;
                } else {
                    let sequence = take_sequence(&mut state.cursor);
                    let queued = QueuedAuditEvent::from_proto(event, sequence);
                    self.append_event(&queued)?;
                    state.events.push_back(queued);
                    self.write_cursor(&state.cursor)?;
                }
            }
        }
        if should_log_overflow {
            tracing::error!(
                target: "sigil::agent",
                dropped = "audit outbox reached its capacity",
                "agent audit outbox overflowed"
            );
        }
        Ok(())
    }

    pub fn batch(&self, limit: usize) -> Result<Vec<AgentAuditEvent>> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("audit outbox lock poisoned"))?;
        Ok(state
            .events
            .iter()
            .take(limit)
            .map(QueuedAuditEvent::to_proto)
            .collect())
    }

    pub fn ack(&self, accepted_through: u64) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("audit outbox lock poisoned"))?;
        state.cursor.acknowledged_through = state.cursor.acknowledged_through.max(accepted_through);
        while state
            .events
            .front()
            .is_some_and(|event| event.sequence <= state.cursor.acknowledged_through)
        {
            state.events.pop_front();
        }
        self.append_overflow_event(&mut state)?;
        self.write_events(&state.events)?;
        self.write_cursor(&state.cursor)
    }

    pub fn enqueue_completion(&self, completion: PendingCompletion) -> Result<()> {
        let mut completions = self.pending_completions()?;
        if !completions
            .iter()
            .any(|pending| pending.rotation_id == completion.rotation_id)
        {
            completions.push(completion);
            self.write_json_atomic(&self.completions_file, &completions)?;
        }
        Ok(())
    }

    pub fn pending_completions(&self) -> Result<Vec<PendingCompletion>> {
        read_json_file(&self.completions_file)
    }

    pub fn remove_completion(&self, rotation_id: &str) -> Result<()> {
        let mut completions = self.pending_completions()?;
        completions.retain(|completion| completion.rotation_id != rotation_id);
        self.write_json_atomic(&self.completions_file, &completions)
    }

    fn append_event(&self, event: &QueuedAuditEvent) -> Result<()> {
        let mut file =
            secure_path::open_protected_file(&self.queue_file, ProtectedFileMode::Append)?;
        serde_json::to_writer(&mut file, event)?;
        file.write_all(b"\n")?;
        file.sync_data()?;
        #[cfg(unix)]
        if let Some(parent) = self.queue_file.parent() {
            fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    }

    fn append_overflow_event(&self, state: &mut OutboxState) -> Result<()> {
        if state.cursor.dropped_events == 0 || state.events.len() >= self.max_events {
            return Ok(());
        }
        let dropped = state.cursor.dropped_events;
        let event = QueuedAuditEvent {
            sequence: take_sequence(&mut state.cursor),
            occurred_at_unix_ms: unix_time_millis(),
            rpc: "AuditOverflow".into(),
            operation: String::new(),
            device_id: String::new(),
            token_serial: String::new(),
            caller_os_user: String::new(),
            caller_session_id: 0,
            outcome: "error".into(),
            code: dropped.to_string(),
            grant_id: String::new(),
            rotation_id: String::new(),
        };
        self.append_event(&event)?;
        state.events.push_back(event);
        state.cursor.dropped_events = 0;
        if !state.overflow_logged {
            state.overflow_logged = true;
            tracing::error!(
                target: "sigil::agent",
                dropped,
                "agent audit outbox overflowed"
            );
        }
        Ok(())
    }

    fn write_events(&self, events: &VecDeque<QueuedAuditEvent>) -> Result<()> {
        self.write_atomic(&self.queue_file, |file| {
            for event in events {
                serde_json::to_writer(&mut *file, event)?;
                file.write_all(b"\n")?;
            }
            Ok(())
        })
    }

    fn write_cursor(&self, cursor: &OutboxCursor) -> Result<()> {
        self.write_json_atomic(&self.cursor_file, cursor)
    }

    fn write_json_atomic<T: Serialize>(&self, path: &Path, value: &T) -> Result<()> {
        self.write_atomic(path, |file| {
            serde_json::to_writer(&mut *file, value)?;
            file.write_all(b"\n")?;
            Ok(())
        })
    }

    fn write_atomic(
        &self,
        destination: &Path,
        write_contents: impl FnOnce(&mut fs::File) -> Result<()>,
    ) -> Result<()> {
        if destination.parent() != Some(self.directory.as_path()) {
            bail!("audit outbox files must stay inside the configured audit directory");
        }
        let suffix = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
        let temp = destination.with_extension(format!("tmp-{}-{suffix}", std::process::id()));
        let mut file = secure_path::open_protected_file(&temp, ProtectedFileMode::CreateNew)?;
        write_contents(&mut file)?;
        file.sync_all()?;
        drop(file);
        secure_path::replace_protected_file(&temp, destination)
    }
}

pub struct AuditOutboxLayer {
    outbox: std::sync::Arc<AuditOutbox>,
}

impl AuditOutboxLayer {
    pub fn new(outbox: std::sync::Arc<AuditOutbox>) -> Self {
        Self { outbox }
    }
}

impl<S: Subscriber> Layer<S> for AuditOutboxLayer {
    fn on_event(&self, event: &Event<'_>, _context: SubscriberContext<'_, S>) {
        if event.metadata().target() != "sigil::audit" {
            return;
        }
        let mut visitor = AuditVisitor::default();
        event.record(&mut visitor);
        let fields = visitor.fields;
        let rpc = field_string(&fields, "rpc");
        if rpc == "AuditOverflow" {
            return;
        }
        let outcome = match field_string(&fields, "outcome") {
            outcome if outcome.is_empty() => "error".to_owned(),
            outcome => outcome,
        };
        let session_text = field_string(&fields, "session_id");
        let session_id = session_text
            .strip_prefix("Some(")
            .and_then(|value| value.strip_suffix(')'))
            .unwrap_or(&session_text)
            .parse()
            .unwrap_or_default();
        let event = AgentAuditEvent {
            sequence: 0,
            occurred_at_unix_ms: unix_time_millis(),
            rpc: if rpc.is_empty() {
                "AgentEvent".into()
            } else {
                rpc
            },
            operation: field_string(&fields, "operation"),
            device_id: field_string(&fields, "device_id"),
            token_serial: {
                let serial = field_string(&fields, "token_serial");
                if serial.is_empty() {
                    field_string(&fields, "serial")
                } else {
                    serial
                }
            },
            caller_os_user: field_string(&fields, "caller_os_user"),
            caller_session_id: session_id,
            outcome,
            code: field_string(&fields, "code"),
            grant_id: field_string(&fields, "grant_id"),
            rotation_id: field_string(&fields, "rotation_id"),
        };
        let rpc = event.rpc.clone();
        let operation = event.operation.clone();
        if let Err(error) = self.outbox.enqueue(event) {
            tracing::warn!(
                target: "sigil::agent",
                error = %format_args!("{error:#}"),
                rpc = %rpc,
                operation = %operation,
                "could not persist agent audit event"
            );
        }
    }
}

#[derive(Default)]
struct AuditVisitor {
    fields: std::collections::HashMap<String, String>,
}

impl Visit for AuditVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.fields.insert(
            field.name().to_owned(),
            normalize_debug(&format!("{value:?}")),
        );
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.fields
            .insert(field.name().to_owned(), value.to_owned());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields
            .insert(field.name().to_owned(), value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields
            .insert(field.name().to_owned(), value.to_string());
    }
}

fn field_string(fields: &std::collections::HashMap<String, String>, name: &str) -> String {
    fields.get(name).cloned().unwrap_or_default()
}

fn normalize_debug(value: &str) -> String {
    if value == "None" {
        return String::new();
    }
    if let Some(value) = value
        .strip_prefix("Some(")
        .and_then(|value| value.strip_suffix(')'))
    {
        return value.to_owned();
    }
    if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        return value[1..value.len() - 1].to_owned();
    }
    value.to_owned()
}

fn take_sequence(cursor: &mut OutboxCursor) -> u64 {
    let sequence = cursor.next_sequence.max(1);
    cursor.next_sequence = sequence.saturating_add(1);
    sequence
}

fn read_cursor(path: &Path) -> Result<Option<OutboxCursor>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("could not inspect {}", path.display()));
        }
        Ok(_) => {}
    }
    let mut file = secure_path::open_protected_file(path, ProtectedFileMode::Read)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(Some(serde_json::from_str(&contents).with_context(
        || format!("could not parse audit outbox state {}", path.display()),
    )?))
}

fn read_events(path: &Path, acknowledged_through: u64) -> Result<VecDeque<QueuedAuditEvent>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(VecDeque::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("could not inspect {}", path.display()));
        }
        Ok(_) => {}
    }
    let mut file = secure_path::open_protected_file(path, ProtectedFileMode::Read)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let mut events = VecDeque::new();
    let mut previous_sequence = 0;
    for line in contents.lines().filter(|line| !line.trim().is_empty()) {
        let event: QueuedAuditEvent = serde_json::from_str(line)
            .with_context(|| format!("could not parse audit outbox event in {}", path.display()))?;
        if event.sequence <= previous_sequence {
            bail!("audit outbox sequences are not strictly increasing");
        }
        previous_sequence = event.sequence;
        if event.sequence > acknowledged_through {
            events.push_back(event);
        }
    }
    Ok(events)
}

fn read_json_file<T: for<'de> Deserialize<'de> + Default>(path: &Path) -> Result<T> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(T::default()),
        Err(error) => {
            return Err(error).with_context(|| format!("could not inspect {}", path.display()));
        }
        Ok(_) => {}
    }
    let mut file = secure_path::open_protected_file(path, ProtectedFileMode::Read)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    serde_json::from_str(&contents)
        .with_context(|| format!("could not parse protected file {}", path.display()))
}

fn unix_time_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_micros().min(u64::MAX as u128) as u64)
        .unwrap_or(1)
}

fn unix_time_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(rpc: &str) -> AgentAuditEvent {
        AgentAuditEvent {
            sequence: 0,
            occurred_at_unix_ms: 10,
            rpc: rpc.into(),
            operation: "PIV_GENERATE_KEY".into(),
            device_id: "mock".into(),
            token_serial: "12345678".into(),
            caller_os_user: "test-user".into(),
            caller_session_id: 1,
            outcome: "success".into(),
            code: String::new(),
            grant_id: String::new(),
            rotation_id: String::new(),
        }
    }

    #[test]
    fn outbox_sequences_survive_reopen_and_ack_compacts() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let first_sequence = unix_time_micros();
        let outbox = AuditOutbox::open(directory.path()).expect("open outbox");
        outbox.enqueue(event("First")).expect("enqueue first event");
        outbox
            .enqueue(event("Second"))
            .expect("enqueue second event");
        let first_batch = outbox.batch(10).expect("read first batch");
        assert_eq!(first_batch.len(), 2);
        assert!(first_batch[0].sequence >= first_sequence);
        assert!(first_batch[1].sequence > first_batch[0].sequence);
        let acknowledged = first_batch[0].sequence;
        drop(outbox);

        let outbox = AuditOutbox::open(directory.path()).expect("reopen outbox");
        let pending = outbox.batch(10).expect("read reopened batch");
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].sequence, first_batch[0].sequence);
        assert_eq!(pending[1].sequence, first_batch[1].sequence);
        outbox.ack(acknowledged).expect("ack first event");
        let compacted = outbox.batch(10).expect("read compacted batch");
        assert_eq!(compacted.len(), 1);
        assert_eq!(compacted[0].sequence, first_batch[1].sequence);
    }

    #[test]
    fn fresh_outbox_starts_at_unix_microseconds() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let before = unix_time_micros();
        let outbox = AuditOutbox::open(directory.path()).expect("open outbox");
        outbox.enqueue(event("Fresh")).expect("enqueue event");
        let sequence = outbox.batch(1).unwrap()[0].sequence;
        assert!(sequence >= before);
    }

    #[test]
    fn overflow_drops_new_events_and_emits_one_audit_event_after_space_frees() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let outbox = AuditOutbox::open_with_capacity(directory.path(), 3).expect("open outbox");
        outbox.enqueue(event("First")).unwrap();
        outbox.enqueue(event("Second")).unwrap();
        outbox.enqueue(event("Third")).unwrap();
        outbox.enqueue(event("Fourth")).unwrap();
        outbox.enqueue(event("Fifth")).unwrap();
        let full = outbox.batch(10).unwrap();
        assert_eq!(
            full.iter()
                .map(|event| event.rpc.as_str())
                .collect::<Vec<_>>(),
            vec!["First", "Second", "Third"]
        );
        outbox.ack(full[0].sequence).unwrap();
        let batch = outbox.batch(10).unwrap();
        assert_eq!(batch.len(), 3);
        assert_eq!(batch[0].rpc, "Second");
        assert_eq!(batch[1].rpc, "Third");
        assert_eq!(batch[2].rpc, "AuditOverflow");
        assert_eq!(batch[2].code, "2");
    }
}
