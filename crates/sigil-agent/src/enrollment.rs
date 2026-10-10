//! Pure helpers for PIV certificate enrollment: profile mapping and issued-chain verification.

use sigil_proto::{backend::v1 as backendv1, v1};
use tonic::Status;
use x509_parser::{certificate::X509Certificate, prelude::FromDer};

/// Maximum number of certificates walked from the leaf to a trusted root.
const MAX_CHAIN_DEPTH: usize = 8;

/// Converts a backend profile into the agent's profile message, mapping policy names to enums.
pub fn profile_message(
    profile: &backendv1::CertificateProfile,
) -> Result<v1::CertificateProfile, Status> {
    let algorithm = key_algorithm_name(&profile.algorithm)?;
    Ok(v1::CertificateProfile {
        name: profile.name.clone(),
        display_name: profile.display_name.clone(),
        slot_byte: profile.piv_slot,
        algorithm: algorithm.as_str_name().to_owned(),
        pin_policy: profile.pin_policy.clone(),
        touch_policy: profile.touch_policy.clone(),
        expected_subject: profile.expected_subject.clone(),
    })
}

/// Maps a backend algorithm name (`p256` or `p384`) to the PIV key generation enum.
pub fn key_algorithm_name(name: &str) -> Result<v1::PivKeyGenerationAlgorithm, Status> {
    match name {
        "p256" => Ok(v1::PivKeyGenerationAlgorithm::PivKeyGenerationEccP256),
        "p384" => Ok(v1::PivKeyGenerationAlgorithm::PivKeyGenerationEccP384),
        _ => Err(Status::failed_precondition(
            "the certificate profile names an unsupported key algorithm",
        )),
    }
}

/// Maps a backend PIN policy name to the protobuf enum.
pub fn pin_policy_name(name: &str) -> Result<v1::PinPolicy, Status> {
    match name {
        "once" => Ok(v1::PinPolicy::Once),
        "always" => Ok(v1::PinPolicy::Always),
        "never" => Ok(v1::PinPolicy::Never),
        _ => Err(Status::failed_precondition(
            "the certificate profile names an unsupported PIN policy",
        )),
    }
}

/// Maps a backend touch policy name to the protobuf enum.
pub fn touch_policy_name(name: &str) -> Result<v1::TouchPolicy, Status> {
    match name {
        "never" => Ok(v1::TouchPolicy::Never),
        "always" => Ok(v1::TouchPolicy::Always),
        "cached" => Ok(v1::TouchPolicy::Cached),
        _ => Err(Status::failed_precondition(
            "the certificate profile names an unsupported touch policy",
        )),
    }
}

/// Verifies that `chain[0]` is a certificate for `expected_spki` (the key generated on the token), that
/// every signature in the chain verifies, that every certificate is valid at `now_unix`, and that the chain
/// ends at one of `trusted_roots` (DER). Intermediates come from the rest of `chain`.
pub fn verify_issued_chain(
    chain: &[Vec<u8>],
    trusted_roots: &[Vec<u8>],
    expected_spki: &[u8],
    now_unix: i64,
) -> Result<(), &'static str> {
    let leaf_der = chain.first().ok_or("the CA returned no certificate")?;
    let (_, leaf) = X509Certificate::from_der(leaf_der)
        .map_err(|_| "the issued certificate is not valid DER")?;
    if leaf.public_key().raw != expected_spki {
        return Err("the issued certificate does not certify the key on the token");
    }

    let mut current = leaf;
    for _ in 0..MAX_CHAIN_DEPTH {
        check_validity(&current, now_unix)?;
        let issuer_name = current.issuer().as_raw().to_vec();
        if let Some(root_der) = trusted_roots
            .iter()
            .find(|der| matches_issuer(der, &issuer_name, &current))
        {
            let (_, root) = X509Certificate::from_der(root_der)
                .map_err(|_| "a configured issuing CA is not valid DER")?;
            check_validity(&root, now_unix)?;
            return Ok(());
        }
        let Some(intermediate_der) = chain
            .iter()
            .skip(1)
            .find(|der| matches_issuer(der, &issuer_name, &current))
        else {
            return Err("the issued certificate does not chain to a configured issuing CA");
        };
        let (_, intermediate) = X509Certificate::from_der(intermediate_der)
            .map_err(|_| "the CA chain contains an invalid certificate")?;
        current = intermediate;
    }
    Err("the issued certificate chain is too deep")
}

fn matches_issuer(candidate_der: &[u8], issuer_name: &[u8], child: &X509Certificate<'_>) -> bool {
    let Ok((_, candidate)) = X509Certificate::from_der(candidate_der) else {
        return false;
    };
    candidate.subject().as_raw() == issuer_name
        && child.verify_signature(Some(candidate.public_key())).is_ok()
}

fn check_validity(certificate: &X509Certificate<'_>, now_unix: i64) -> Result<(), &'static str> {
    let validity = certificate.validity();
    if now_unix < validity.not_before.timestamp() || now_unix > validity.not_after.timestamp() {
        return Err("an issued certificate in the chain is not valid now");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

    struct Hierarchy {
        root_der: Vec<u8>,
        intermediate_der: Vec<u8>,
        intermediate: rcgen::Certificate,
        intermediate_key: KeyPair,
    }

    fn hierarchy() -> Hierarchy {
        let root_key = KeyPair::generate().unwrap();
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Test Root");
        let root = root_params.self_signed(&root_key).unwrap();

        let intermediate_key = KeyPair::generate().unwrap();
        let mut intermediate_params = CertificateParams::default();
        intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        intermediate_params
            .distinguished_name
            .push(DnType::CommonName, "Test Issuing CA");
        let intermediate = intermediate_params
            .signed_by(&intermediate_key, &root, &root_key)
            .unwrap();
        Hierarchy {
            root_der: root.der().to_vec(),
            intermediate_der: intermediate.der().to_vec(),
            intermediate,
            intermediate_key,
        }
    }

    fn leaf_for(hierarchy: &Hierarchy, key: &KeyPair) -> Vec<u8> {
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, "alice");
        params
            .signed_by(key, &hierarchy.intermediate, &hierarchy.intermediate_key)
            .unwrap()
            .der()
            .to_vec()
    }

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    #[test]
    fn accepts_a_leaf_for_the_token_key_that_chains_to_a_configured_root() {
        let h = hierarchy();
        let key = KeyPair::generate().unwrap();
        let leaf = leaf_for(&h, &key);
        let chain = vec![leaf, h.intermediate_der.clone()];
        verify_issued_chain(
            &chain,
            std::slice::from_ref(&h.root_der),
            &key.public_key_der(),
            now(),
        )
        .unwrap();
    }

    #[test]
    fn rejects_a_certificate_for_a_different_key() {
        let h = hierarchy();
        let key = KeyPair::generate().unwrap();
        let other = KeyPair::generate().unwrap();
        let chain = vec![leaf_for(&h, &key), h.intermediate_der.clone()];
        let result = verify_issued_chain(
            &chain,
            std::slice::from_ref(&h.root_der),
            &other.public_key_der(),
            now(),
        );
        assert_eq!(
            result,
            Err("the issued certificate does not certify the key on the token")
        );
    }

    #[test]
    fn rejects_a_chain_to_a_root_that_is_not_configured() {
        let h = hierarchy();
        let other = hierarchy();
        let key = KeyPair::generate().unwrap();
        let chain = vec![leaf_for(&h, &key), h.intermediate_der.clone()];
        let result = verify_issued_chain(
            &chain,
            std::slice::from_ref(&other.root_der),
            &key.public_key_der(),
            now(),
        );
        assert_eq!(
            result,
            Err("the issued certificate does not chain to a configured issuing CA")
        );
    }

    #[test]
    fn rejects_a_chain_outside_its_validity_period() {
        let h = hierarchy();
        let key = KeyPair::generate().unwrap();
        let chain = vec![leaf_for(&h, &key), h.intermediate_der.clone()];
        let before_issue = 0;
        let result = verify_issued_chain(
            &chain,
            std::slice::from_ref(&h.root_der),
            &key.public_key_der(),
            before_issue,
        );
        assert_eq!(
            result,
            Err("an issued certificate in the chain is not valid now")
        );
    }

    #[test]
    fn rejects_a_leaf_with_no_chain_to_its_issuer() {
        let h = hierarchy();
        let key = KeyPair::generate().unwrap();
        let chain = vec![leaf_for(&h, &key)];
        assert!(
            verify_issued_chain(
                &chain,
                std::slice::from_ref(&h.root_der),
                &key.public_key_der(),
                now()
            )
            .is_err()
        );
    }

    #[test]
    fn maps_profile_names_to_enums_and_rejects_unknown_names() {
        assert_eq!(
            key_algorithm_name("p256").unwrap(),
            v1::PivKeyGenerationAlgorithm::PivKeyGenerationEccP256
        );
        assert_eq!(
            key_algorithm_name("p384").unwrap(),
            v1::PivKeyGenerationAlgorithm::PivKeyGenerationEccP384
        );
        assert!(key_algorithm_name("rsa2048").is_err());
        assert_eq!(pin_policy_name("once").unwrap(), v1::PinPolicy::Once);
        assert!(pin_policy_name("default").is_err());
        assert_eq!(
            touch_policy_name("cached").unwrap(),
            v1::TouchPolicy::Cached
        );
        assert!(touch_policy_name("sometimes").is_err());
    }
}
