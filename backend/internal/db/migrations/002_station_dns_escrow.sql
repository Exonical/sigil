ALTER TABLE stations ADD COLUMN dns_name text;
UPDATE stations SET dns_name = lower(id);
ALTER TABLE stations ALTER COLUMN dns_name SET NOT NULL;
ALTER TABLE stations ADD CONSTRAINT stations_dns_name_lowercase CHECK (dns_name = lower(dns_name));
CREATE UNIQUE INDEX stations_dns_name_unique ON stations(dns_name);
ALTER TABLE stations DROP CONSTRAINT stations_cert_spki_sha256_key;
ALTER TABLE stations ALTER COLUMN cert_spki_sha256 DROP NOT NULL;

CREATE TABLE escrowed_secrets (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_id uuid NOT NULL REFERENCES tokens(id),
    kind text NOT NULL CHECK (kind IN ('puk', 'management_key')),
    algorithm text NOT NULL DEFAULT '',
    version integer NOT NULL CHECK (version > 0),
    state text NOT NULL CHECK (state IN ('pending', 'active', 'superseded', 'abandoned', 'unconfirmed')),
    kek_id text NOT NULL,
    dek_nonce bytea NOT NULL,
    wrapped_dek bytea NOT NULL,
    nonce bytea NOT NULL,
    ciphertext bytea NOT NULL,
    grant_id text NOT NULL REFERENCES grants(grant_id),
    station_id text NOT NULL REFERENCES stations(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    activated_at timestamptz,
    UNIQUE (token_id, kind, version)
);

CREATE UNIQUE INDEX escrowed_secrets_one_active
    ON escrowed_secrets(token_id, kind)
    WHERE state = 'active';

CREATE UNIQUE INDEX escrowed_secrets_one_pending
    ON escrowed_secrets(token_id, kind)
    WHERE state = 'pending';

CREATE TABLE station_audit_cursor (
    station_id text PRIMARY KEY REFERENCES stations(id),
    last_sequence bigint NOT NULL DEFAULT 0 CHECK (last_sequence >= 0)
);
