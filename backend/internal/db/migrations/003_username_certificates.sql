ALTER TABLE users ADD COLUMN username text NOT NULL DEFAULT '';

CREATE TABLE certificates (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_id uuid NOT NULL REFERENCES tokens(id),
    slot text NOT NULL,
    profile text NOT NULL,
    user_id uuid NOT NULL REFERENCES users(id),
    serial_number text NOT NULL,
    subject text NOT NULL,
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    status text NOT NULL CHECK (status IN ('active', 'revoked', 'superseded')),
    issued_by_station text NOT NULL REFERENCES stations(id),
    issued_at timestamptz NOT NULL DEFAULT now(),
    der bytea NOT NULL,
    UNIQUE (serial_number)
);

CREATE UNIQUE INDEX certificates_one_active_per_token_slot
    ON certificates(token_id, slot) WHERE status = 'active';
