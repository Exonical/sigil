CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer text NOT NULL,
    subject text NOT NULL,
    email text NOT NULL DEFAULT '',
    display_name text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (issuer, subject)
);

CREATE TABLE stations (
    id text PRIMARY KEY,
    display_name text NOT NULL,
    mode text NOT NULL CHECK (mode IN ('station', 'user')),
    cert_spki_sha256 bytea NOT NULL UNIQUE,
    status text NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (octet_length(cert_spki_sha256) = 32)
);

CREATE TABLE tokens (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vendor text NOT NULL,
    model text NOT NULL DEFAULT '',
    serial text NOT NULL,
    firmware text NOT NULL DEFAULT '',
    form_factor text NOT NULL DEFAULT '',
    nickname text,
    assigned_user_id uuid REFERENCES users(id),
    status text NOT NULL DEFAULT 'unassigned'
        CHECK (status IN ('unassigned', 'active', 'lost', 'retired')),
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    last_station_id text REFERENCES stations(id),
    UNIQUE (vendor, serial)
);

CREATE UNIQUE INDEX tokens_assigned_nickname_unique
    ON tokens (assigned_user_id, nickname)
    WHERE assigned_user_id IS NOT NULL AND nickname IS NOT NULL;

CREATE TABLE grants (
    grant_id text PRIMARY KEY,
    operation text NOT NULL,
    user_id uuid NOT NULL REFERENCES users(id),
    station_id text NOT NULL REFERENCES stations(id),
    token_serial text NOT NULL,
    piv_slot integer NOT NULL DEFAULT 0 CHECK (piv_slot BETWEEN 0 AND 255),
    caller_os_user text NOT NULL DEFAULT '',
    not_before timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    key_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_events (
    seq bigserial PRIMARY KEY,
    occurred_at timestamptz NOT NULL,
    actor_type text NOT NULL CHECK (actor_type IN ('user', 'station', 'system')),
    actor_id text NOT NULL,
    action text NOT NULL,
    target_type text NOT NULL,
    target_id text NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('success', 'denied', 'error')),
    detail jsonb NOT NULL,
    prev_hash bytea NOT NULL CHECK (octet_length(prev_hash) = 32),
    hash bytea NOT NULL CHECK (octet_length(hash) = 32)
);

CREATE FUNCTION reject_audit_event_mutation() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only';
END;
$$;

CREATE TRIGGER audit_events_reject_update_delete
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION reject_audit_event_mutation();

CREATE TRIGGER audit_events_reject_truncate
    BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_event_mutation();
