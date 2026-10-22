//! Typed agent audit events.
//!
//! Every agent audit event is built as an [`AuditRecord`] and emitted through [`emit`], which writes one
//! `sigil::audit` tracing event whose field names match `AgentAuditEvent`. [`decode`] is the only reader of
//! those fields; the audit outbox layer uses it to rebuild the queued event.

use std::fmt;

use sigil_proto::backend::v1::AgentAuditEvent;
use tracing::{
    Event,
    field::{Field, Visit},
};

use crate::caller::CallerIdentity;

pub const TARGET: &str = "sigil::audit";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditOutcome {
    Success,
    Denied,
    Error,
    RotationOutcomeUnknown,
}

impl AuditOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Denied => "denied",
            Self::Error => "error",
            Self::RotationOutcomeUnknown => "rotation_outcome_unknown",
        }
    }
}

/// One agent audit event. Empty strings and `None` mean the field does not apply.
#[derive(Clone, Copy, Debug)]
pub struct AuditRecord<'a> {
    pub rpc: &'a str,
    pub operation: &'a str,
    pub device_id: &'a str,
    pub token_serial: &'a str,
    /// Logged only; the backend audit event does not carry the slot.
    pub piv_slot: Option<u8>,
    pub caller: Option<&'a CallerIdentity>,
    pub outcome: AuditOutcome,
    pub code: &'a str,
    pub grant_id: &'a str,
    pub rotation_id: &'a str,
}

/// Writes the human-readable audit line and, through the audit outbox layer when it is installed, queues the
/// event for the backend.
pub fn emit(record: &AuditRecord<'_>) {
    macro_rules! audit_event {
        ($level:ident) => {
            tracing::event!(
                target: TARGET,
                tracing::Level::$level,
                rpc = record.rpc,
                operation = record.operation,
                device_id = record.device_id,
                token_serial = record.token_serial,
                piv_slot = record.piv_slot,
                caller_os_user = record.caller.map(|caller| caller.os_user.as_str()),
                caller_session_id = record.caller.and_then(|caller| caller.session_id),
                pid = record.caller.map(|caller| caller.pid),
                outcome = record.outcome.as_str(),
                code = record.code,
                grant_id = record.grant_id,
                rotation_id = record.rotation_id,
            )
        };
    }
    match record.outcome {
        AuditOutcome::RotationOutcomeUnknown => audit_event!(ERROR),
        AuditOutcome::Success | AuditOutcome::Denied | AuditOutcome::Error => audit_event!(INFO),
    }
}

/// Rebuilds the backend audit event from a `sigil::audit` tracing event written by [`emit`]. The sequence is
/// assigned by the outbox and the timestamp by the caller.
pub fn decode(event: &Event<'_>) -> AgentAuditEvent {
    let mut visitor = AuditVisitor(AgentAuditEvent::default());
    event.record(&mut visitor);
    visitor.0
}

struct AuditVisitor(AgentAuditEvent);

impl AuditVisitor {
    fn text_field(&mut self, field: &Field) -> Option<&mut String> {
        let event = &mut self.0;
        Some(match field.name() {
            "rpc" => &mut event.rpc,
            "operation" => &mut event.operation,
            "device_id" => &mut event.device_id,
            "token_serial" => &mut event.token_serial,
            "caller_os_user" => &mut event.caller_os_user,
            "outcome" => &mut event.outcome,
            "code" => &mut event.code,
            "grant_id" => &mut event.grant_id,
            "rotation_id" => &mut event.rotation_id,
            _ => return None,
        })
    }
}

impl Visit for AuditVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if let Some(text) = self.text_field(field) {
            value.clone_into(text);
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "caller_session_id" {
            self.0.caller_session_id = u32::try_from(value).unwrap_or_default();
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if let Some(text) = self.text_field(field) {
            *text = format!("{value:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tracing_subscriber::prelude::*;

    use super::*;
    use crate::audit_outbox::{AuditOutbox, AuditOutboxLayer};

    fn queued(records: &[AuditRecord<'_>]) -> Vec<AgentAuditEvent> {
        let directory = tempfile::tempdir().expect("audit directory");
        let outbox = Arc::new(AuditOutbox::open(directory.path()).expect("open outbox"));
        let subscriber = tracing::Dispatch::new(
            tracing_subscriber::registry().with(AuditOutboxLayer::new(Arc::clone(&outbox))),
        );
        tracing::dispatcher::with_default(&subscriber, || records.iter().for_each(emit));
        outbox.batch(records.len() + 1).expect("read audit events")
    }

    #[test]
    fn emitted_record_reaches_outbox_field_for_field() {
        let caller = CallerIdentity {
            os_user: "test-user".into(),
            session_id: Some(7),
            pid: 42,
        };
        let events = queued(&[AuditRecord {
            rpc: "RotateManagedPivSecret",
            operation: "PIV_MANAGED_ROTATE",
            device_id: "mock-device",
            token_serial: "12345678",
            piv_slot: Some(0x9a),
            caller: Some(&caller),
            outcome: AuditOutcome::Denied,
            code: "OPERATION_UNAUTHORIZED",
            grant_id: "grant-id",
            rotation_id: "rotation-id",
        }]);
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert!(event.sequence > 0);
        assert!(event.occurred_at_unix_ms > 0);
        assert_eq!(
            event,
            &AgentAuditEvent {
                sequence: event.sequence,
                occurred_at_unix_ms: event.occurred_at_unix_ms,
                rpc: "RotateManagedPivSecret".into(),
                operation: "PIV_MANAGED_ROTATE".into(),
                device_id: "mock-device".into(),
                token_serial: "12345678".into(),
                caller_os_user: "test-user".into(),
                caller_session_id: 7,
                outcome: "denied".into(),
                code: "OPERATION_UNAUTHORIZED".into(),
                grant_id: "grant-id".into(),
                rotation_id: "rotation-id".into(),
            }
        );
    }

    #[test]
    fn absent_caller_and_fields_stay_empty() {
        let events = queued(&[AuditRecord {
            rpc: "CompleteRotation",
            operation: "rotation_completion",
            device_id: "",
            token_serial: "",
            piv_slot: None,
            caller: None,
            outcome: AuditOutcome::Error,
            code: "completion_expired",
            grant_id: "",
            rotation_id: "rotation-id",
        }]);
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.caller_os_user, "");
        assert_eq!(event.caller_session_id, 0);
        assert_eq!(event.device_id, "");
        assert_eq!(event.token_serial, "");
        assert_eq!(event.grant_id, "");
        assert_eq!(event.outcome, "error");
        assert_eq!(event.rotation_id, "rotation-id");
    }

    #[test]
    fn outcomes_use_backend_names() {
        let caller = CallerIdentity {
            os_user: "test-user".into(),
            session_id: None,
            pid: 42,
        };
        let outcomes = [
            AuditOutcome::Success,
            AuditOutcome::Denied,
            AuditOutcome::Error,
            AuditOutcome::RotationOutcomeUnknown,
        ];
        let records: Vec<_> = outcomes
            .iter()
            .map(|&outcome| AuditRecord {
                rpc: "ChangePivPin",
                operation: "PIV_CHANGE_PIN",
                device_id: "mock-device",
                token_serial: "12345678",
                piv_slot: None,
                caller: Some(&caller),
                outcome,
                code: "",
                grant_id: "",
                rotation_id: "",
            })
            .collect();
        let events = queued(&records);
        assert_eq!(
            events
                .iter()
                .map(|event| (event.outcome.as_str(), event.caller_session_id))
                .collect::<Vec<_>>(),
            [
                ("success", 0),
                ("denied", 0),
                ("error", 0),
                ("rotation_outcome_unknown", 0)
            ]
        );
    }
}
