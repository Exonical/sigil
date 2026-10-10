ALTER TABLE certificates ADD COLUMN attestation_der bytea;
ALTER TABLE certificates ADD COLUMN attestation_intermediate_der bytea;
ALTER TABLE certificates ADD COLUMN attested_firmware text;
ALTER TABLE certificates ADD COLUMN attestation_root text;
