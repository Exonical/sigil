//! Standards-based PIV application operations.

use std::io::Read;

use const_oid::ObjectIdentifier;
use der::Decode;
use flate2::read::GzDecoder;
use pkcs1::{RsaPublicKey, der::Decode as Pkcs1Decode};
use sha2::{Digest, Sha256};
use sigil_core::{
    CertificateFormat, CertificateSummary, CredentialError, PivAlgorithm, PivSlot, Result,
};
use x509_cert::Certificate;

pub mod management;
pub mod tlv;

const MAX_RESPONSE_SIZE: usize = 16 * 1024;
const PIV_AID_SELECT: &[u8] = &[0x00, 0xa4, 0x04, 0x00, 0x05, 0xa0, 0x00, 0x00, 0x03, 0x08];
const GET_RESPONSE_PREFIX: &[u8] = &[0x00, 0xc0, 0x00, 0x00];
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const OID_X25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.110");

/// Provider-internal seam for exchanging APDUs with a PIV card. This must never
/// be exposed through sigil-app, the CLI, GUI, or any remote protocol.
pub trait CardTransport {
    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>>;
}

pub fn transceive<T: CardTransport>(transport: &mut T, command: &[u8]) -> Result<(Vec<u8>, u16)> {
    let mut response = transport.transmit(command)?;
    let mut collected = Vec::new();
    let mut exchanges = 0;
    loop {
        if response.len() < 2 {
            return Err(CredentialError::SmartCardOperation(
                "card response omitted status bytes".into(),
            ));
        }
        let data_end = response.len() - 2;
        if data_end > MAX_RESPONSE_SIZE.saturating_sub(collected.len()) {
            return Err(CredentialError::SmartCardOperation(
                "card response exceeded 16 KiB".into(),
            ));
        }
        collected.extend_from_slice(&response[..data_end]);
        let sw = u16::from_be_bytes([response[data_end], response[data_end + 1]]);
        if sw >> 8 != 0x61 {
            return Ok((collected, sw));
        }
        if exchanges == 256 {
            return Err(CredentialError::SmartCardOperation(
                "too many chained card responses".into(),
            ));
        }
        exchanges += 1;
        let mut get_response = GET_RESPONSE_PREFIX.to_vec();
        get_response.push(sw as u8);
        response = transport.transmit(&get_response)?;
    }
}

pub fn select<T: CardTransport>(transport: &mut T) -> Result<()> {
    let (_, sw) = transceive(transport, PIV_AID_SELECT)?;
    match sw {
        0x9000 => Ok(()),
        0x6a82 | 0x6a81 => Err(CredentialError::PivUnavailable),
        other => Err(CredentialError::CardStatus(other)),
    }
}

pub fn data_object_tag(slot: PivSlot) -> [u8; 3] {
    match slot.byte() {
        0x9a => [0x5f, 0xc1, 0x05],
        0x9c => [0x5f, 0xc1, 0x0a],
        0x9d => [0x5f, 0xc1, 0x0b],
        0x9e => [0x5f, 0xc1, 0x01],
        retired @ 0x82..=0x95 => [0x5f, 0xc1, retired - 0x82 + 0x0d],
        0xf9 => [0x5f, 0xff, 0x01],
        _ => unreachable!("PivSlot only represents valid slot values"),
    }
}

pub fn read_certificate<T: CardTransport>(
    transport: &mut T,
    slot: PivSlot,
) -> Result<Option<Vec<u8>>> {
    let tag = data_object_tag(slot);
    let command = [
        0x00, 0xcb, 0x3f, 0xff, 0x05, 0x5c, 0x03, tag[0], tag[1], tag[2], 0x00,
    ];
    let (data, sw) = transceive(transport, &command)?;
    if sw == 0x6a82 || sw == 0x6a88 {
        return Ok(None);
    }
    if sw != 0x9000 {
        return Err(CredentialError::CardStatus(sw));
    }
    let outer = tlv::parse(&data).map_err(certificate_parse)?;
    let Some((_, template)) = outer.iter().find(|(tag, _)| *tag == 0x53) else {
        return Err(CredentialError::CertificateParse(
            "certificate template 53 was not present".into(),
        ));
    };
    let fields = tlv::parse(template).map_err(certificate_parse)?;
    let mut certificate = fields
        .iter()
        .find(|(tag, _)| *tag == 0x70)
        .map(|(_, value)| value.clone())
        .unwrap_or_default();
    if certificate.is_empty() {
        return Ok(None);
    }
    if fields
        .iter()
        .find(|(tag, _)| *tag == 0x71)
        .is_some_and(|(_, info)| info.first() == Some(&0x01))
    {
        let decoder = GzDecoder::new(certificate.as_slice());
        let mut decompressed = Vec::new();
        decoder
            .take((MAX_RESPONSE_SIZE + 1) as u64)
            .read_to_end(&mut decompressed)
            .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
        if decompressed.len() > MAX_RESPONSE_SIZE {
            return Err(CredentialError::CertificateParse(
                "decompressed certificate exceeded 16 KiB".into(),
            ));
        }
        certificate = decompressed;
    }
    Ok((!certificate.is_empty()).then_some(certificate))
}

pub fn pin_retries<T: CardTransport>(transport: &mut T) -> Result<Option<u8>> {
    let (_, sw) = transceive(transport, &[0x00, 0x20, 0x00, 0x80])?;
    match sw {
        0x9000 => Ok(None),
        0x6983 => Ok(Some(0)),
        value if value & 0xfff0 == 0x63c0 => Ok(Some((value & 0x000f) as u8)),
        other => Err(CredentialError::CardStatus(other)),
    }
}

pub fn summarize_certificate(der: &[u8]) -> Result<CertificateSummary> {
    let certificate = Certificate::from_der(der)
        .map_err(|error| CredentialError::CertificateParse(error.to_string()))?;
    let tbs = certificate.tbs_certificate();
    let spki = tbs.subject_public_key_info();
    let algorithm_oid = spki.algorithm.oid;
    let public_key_algorithm = if algorithm_oid == OID_RSA_ENCRYPTION {
        spki.subject_public_key
            .as_bytes()
            .and_then(|bytes| RsaPublicKey::from_der(bytes).ok())
            .and_then(|key| {
                let modulus = key.modulus.as_bytes();
                let leading_bits = modulus
                    .first()
                    .map(|byte| 8 - byte.leading_zeros() as usize)?;
                let bits = modulus.len().saturating_sub(1) * 8 + leading_bits;
                match bits {
                    1024 => Some(PivAlgorithm::Rsa1024),
                    2048 => Some(PivAlgorithm::Rsa2048),
                    3072 => Some(PivAlgorithm::Rsa3072),
                    4096 => Some(PivAlgorithm::Rsa4096),
                    _ => None,
                }
            })
    } else if algorithm_oid == OID_EC_PUBLIC_KEY {
        spki.algorithm
            .parameters
            .as_ref()
            .and_then(|parameters| parameters.decode_as::<ObjectIdentifier>().ok())
            .and_then(|curve| {
                if curve == OID_P256 {
                    Some(PivAlgorithm::EccP256)
                } else if curve == OID_P384 {
                    Some(PivAlgorithm::EccP384)
                } else {
                    None
                }
            })
    } else if algorithm_oid == OID_ED25519 {
        Some(PivAlgorithm::Ed25519)
    } else if algorithm_oid == OID_X25519 {
        Some(PivAlgorithm::X25519)
    } else {
        None
    };
    let digest = Sha256::digest(der);
    Ok(CertificateSummary {
        // x509-cert renders names per RFC 4514 (last encoded RDN first).
        subject: tbs.subject().to_string(),
        issuer: tbs.issuer().to_string(),
        serial: hex(tbs.serial_number().as_bytes()),
        not_before: tbs.validity().not_before.to_string(),
        not_after: tbs.validity().not_after.to_string(),
        public_key_algorithm,
        sha256_fingerprint: hex(&digest),
    })
}

pub fn encode_certificate(der: &[u8], format: CertificateFormat) -> Vec<u8> {
    match format {
        CertificateFormat::Der => der.to_vec(),
        CertificateFormat::Pem => {
            der::pem::encode_string("CERTIFICATE", der::pem::LineEnding::LF, der)
                .expect("certificate PEM label and DER length are valid")
                .into_bytes()
        }
    }
}

fn certificate_parse(error: CredentialError) -> CredentialError {
    CredentialError::CertificateParse(error.to_string())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, io::Write};

    use flate2::{Compression, write::GzEncoder};
    use sigil_core::{CertificateFormat, PivAlgorithm, PivSlot};
    use x509_cert::der::{DecodePem, Encode};

    use super::*;

    const P256_CERT: &[u8] = include_bytes!("../../sigil-mock/fixtures/piv-9a-p256.der");
    const RSA_CERT: &[u8] = include_bytes!("../../sigil-mock/fixtures/piv-9d-rsa2048.der");

    struct ScriptedTransport(VecDeque<(Vec<u8>, Vec<u8>)>);

    impl ScriptedTransport {
        fn new(steps: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>) -> Self {
            Self(steps.into_iter().collect())
        }
    }

    impl CardTransport for ScriptedTransport {
        fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>> {
            let (expected, response) = self.0.pop_front().expect("unexpected APDU");
            assert_eq!(command, expected);
            Ok(response)
        }
    }

    fn response(data: &[u8], sw: u16) -> Vec<u8> {
        [data, &sw.to_be_bytes()].concat()
    }

    fn encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut encoded = vec![tag];
        if value.len() < 0x80 {
            encoded.push(value.len() as u8);
        } else if value.len() <= 0xff {
            encoded.extend_from_slice(&[0x81, value.len() as u8]);
        } else {
            encoded.extend_from_slice(&[0x82, (value.len() >> 8) as u8, value.len() as u8]);
        }
        encoded.extend_from_slice(value);
        encoded
    }

    fn certificate_template(certificate: &[u8], info: &[u8]) -> Vec<u8> {
        let mut inner = encode_tlv(0x70, certificate);
        if !info.is_empty() {
            inner.extend_from_slice(&encode_tlv(0x71, info));
        }
        encode_tlv(0x53, &inner)
    }

    #[test]
    fn select_distinguishes_piv_unavailable() {
        let mut ok = ScriptedTransport::new([(
            vec![0x00, 0xa4, 0x04, 0x00, 0x05, 0xa0, 0x00, 0x00, 0x03, 0x08],
            vec![0x90, 0x00],
        )]);
        select(&mut ok).expect("selected");
        let mut missing = ScriptedTransport::new([(
            vec![0x00, 0xa4, 0x04, 0x00, 0x05, 0xa0, 0x00, 0x00, 0x03, 0x08],
            vec![0x6a, 0x82],
        )]);
        assert_eq!(select(&mut missing), Err(CredentialError::PivUnavailable));
        let mut reference_not_found = ScriptedTransport::new([(
            vec![0x00, 0xa4, 0x04, 0x00, 0x05, 0xa0, 0x00, 0x00, 0x03, 0x08],
            vec![0x6a, 0x88],
        )]);
        assert_eq!(
            select(&mut reference_not_found),
            Err(CredentialError::CardStatus(0x6a88))
        );
    }

    #[test]
    fn read_certificate_chains_and_returns_none_for_missing_object() {
        let command = vec![
            0x00, 0xcb, 0x3f, 0xff, 0x05, 0x5c, 0x03, 0x5f, 0xc1, 0x05, 0x00,
        ];
        let encoded = certificate_template(P256_CERT, &[]);
        let split = encoded.len() / 2;
        let mut transport = ScriptedTransport::new([
            (command.clone(), response(&encoded[..split], 0x6100)),
            (
                vec![0x00, 0xc0, 0x00, 0x00, 0x00],
                response(&encoded[split..], 0x9000),
            ),
        ]);
        assert_eq!(
            read_certificate(&mut transport, PivSlot::AUTHENTICATION).unwrap(),
            Some(P256_CERT.to_vec())
        );
        for status in [0x6a82u16, 0x6a88] {
            let mut missing = ScriptedTransport::new([(command.clone(), response(&[], status))]);
            assert_eq!(
                read_certificate(&mut missing, PivSlot::AUTHENTICATION).unwrap(),
                None
            );
        }
    }

    #[test]
    fn decompresses_certinfo_and_rejects_garbage() {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(P256_CERT).unwrap();
        let zipped = encoder.finish().unwrap();
        let command = vec![
            0x00, 0xcb, 0x3f, 0xff, 0x05, 0x5c, 0x03, 0x5f, 0xc1, 0x05, 0x00,
        ];
        let mut transport = ScriptedTransport::new([(
            command.clone(),
            response(&certificate_template(&zipped, &[1]), 0x9000),
        )]);
        assert_eq!(
            read_certificate(&mut transport, PivSlot::AUTHENTICATION).unwrap(),
            Some(P256_CERT.to_vec())
        );
        let mut invalid = ScriptedTransport::new([(
            command,
            response(&certificate_template(b"garbage", &[]), 0x9000),
        )]);
        let der = read_certificate(&mut invalid, PivSlot::AUTHENTICATION)
            .unwrap()
            .unwrap();
        assert!(matches!(
            summarize_certificate(&der),
            Err(CredentialError::CertificateParse(_))
        ));
    }

    #[test]
    fn pin_retry_statuses_are_read_only() {
        for (sw, expected) in [(0x63c3u16, Some(3u8)), (0x6983, Some(0)), (0x9000, None)] {
            let mut transport =
                ScriptedTransport::new([(vec![0x00, 0x20, 0x00, 0x80], sw.to_be_bytes().to_vec())]);
            assert_eq!(pin_retries(&mut transport).unwrap(), expected);
        }
    }

    #[test]
    fn tags_cover_all_valid_slots() {
        assert_eq!(data_object_tag(PivSlot::AUTHENTICATION), [0x5f, 0xc1, 0x05]);
        assert_eq!(data_object_tag(PivSlot::SIGNATURE), [0x5f, 0xc1, 0x0a]);
        assert_eq!(data_object_tag(PivSlot::KEY_MANAGEMENT), [0x5f, 0xc1, 0x0b]);
        assert_eq!(
            data_object_tag(PivSlot::CARD_AUTHENTICATION),
            [0x5f, 0xc1, 0x01]
        );
        for (index, slot) in PivSlot::retired_slots().enumerate() {
            assert_eq!(data_object_tag(slot), [0x5f, 0xc1, 0x0d + index as u8]);
        }
        assert_eq!(data_object_tag(PivSlot::ATTESTATION), [0x5f, 0xff, 0x01]);
    }

    #[test]
    fn summarizes_rsa_and_p256_and_encodes_pem() {
        for (der, algorithm, subject) in [
            (
                P256_CERT,
                Some(PivAlgorithm::EccP256),
                "Simulated PIV Authentication",
            ),
            (
                RSA_CERT,
                Some(PivAlgorithm::Rsa2048),
                "Simulated PIV Key Management",
            ),
        ] {
            let summary = summarize_certificate(der).unwrap();
            assert!(summary.subject.contains(subject));
            assert!(!summary.issuer.is_empty());
            assert!(!summary.serial.is_empty());
            assert!(summary.not_before.ends_with('Z'));
            assert!(summary.not_after.ends_with('Z'));
            assert_eq!(summary.public_key_algorithm, algorithm);
            assert_eq!(summary.sha256_fingerprint.len(), 64);
        }
        let p256_summary = summarize_certificate(P256_CERT).unwrap();
        assert_eq!(
            p256_summary.subject,
            "O=Sigil Test Fixture,CN=Simulated PIV Authentication"
        );
        assert_eq!(
            p256_summary.issuer,
            "O=Sigil Test Fixture,CN=Simulated PIV Authentication"
        );
        let pem = encode_certificate(P256_CERT, CertificateFormat::Pem);
        let pem_text = std::str::from_utf8(&pem).unwrap();
        assert!(pem_text.starts_with("-----BEGIN CERTIFICATE-----\n"));
        let parsed = Certificate::from_pem(pem_text.as_bytes()).unwrap();
        assert_eq!(parsed.to_der().unwrap(), P256_CERT);
    }
}
