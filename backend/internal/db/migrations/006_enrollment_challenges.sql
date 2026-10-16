CREATE TABLE enrollment_challenges (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_id uuid NOT NULL REFERENCES tokens(id),
    profile text NOT NULL,
    user_id uuid NOT NULL REFERENCES users(id),
    station_id text NOT NULL REFERENCES stations(id),
    principal_user_id uuid NOT NULL REFERENCES users(id),
    challenge_sha256 bytea NOT NULL UNIQUE,
    csr_spki bytea,
    state text NOT NULL CHECK (state IN ('issued', 'submitted', 'consumed')),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    submitted_at timestamptz,
    consumed_at timestamptz
);
