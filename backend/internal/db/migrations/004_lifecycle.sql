ALTER TABLE tokens ADD COLUMN lost_at timestamptz;

ALTER TABLE certificates ADD COLUMN revoked_at timestamptz;
ALTER TABLE certificates ADD COLUMN revocation_reason text NOT NULL DEFAULT '';
