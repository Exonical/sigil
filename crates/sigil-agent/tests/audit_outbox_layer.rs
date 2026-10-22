use std::{
    io::Write,
    sync::{Arc, Mutex},
};

use sigil_agent::audit_outbox::{AuditOutbox, AuditOutboxLayer};
use tracing_subscriber::prelude::*;

#[derive(Clone, Default)]
struct CapturedLog(Arc<Mutex<Vec<u8>>>);

impl Write for CapturedLog {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// The agent installs its subscriber globally. A scoped subscriber would drop the
// layer's own warning, because tracing does not re-enter a scoped dispatcher.
#[test]
fn enqueue_failure_logs_cause_and_event_identity() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let outbox_directory = directory.path().join("audit");
    std::fs::create_dir(&outbox_directory).expect("create outbox directory");
    let outbox = Arc::new(AuditOutbox::open(&outbox_directory).expect("open outbox"));
    std::fs::remove_dir_all(&outbox_directory).expect("remove outbox directory");

    let log = CapturedLog::default();
    let writer = log.clone();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(move || writer.clone()),
        )
        .with(AuditOutboxLayer::new(outbox))
        .try_init()
        .expect("install global subscriber");

    tracing::info!(
        target: "sigil::audit",
        rpc = "GenerateKey",
        operation = "PIV_GENERATE_KEY",
        outcome = "success",
        "audited"
    );

    let output = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    let warning = output
        .lines()
        .find(|line| line.contains("could not persist agent audit event"))
        .unwrap_or_else(|| panic!("persistence failure warning missing:\n{output}"));
    assert!(warning.contains("error="), "{warning}");
    assert!(warning.contains("rpc=GenerateKey"), "{warning}");
    assert!(warning.contains("operation=PIV_GENERATE_KEY"), "{warning}");
}
