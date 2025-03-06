use rcgen::{
    BasicConstraints, CertificateParams, CertifiedKey, DnType, DnValue::PrintableString,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::{DigitallySignedStruct, SignatureScheme};
use time::{Duration, OffsetDateTime};

/// Creates a dummy CA certificate and key.
pub(crate) fn generate_ca() -> CertifiedKey {
    let mut params =
        CertificateParams::new(Vec::default()).expect("empty subject alt name can't produce error");
    let (yesterday, tomorrow) = validity_period();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(
        DnType::CountryName,
        PrintableString("BG".try_into().unwrap()),
    );
    params
        .distinguished_name
        .push(DnType::OrganizationName, "htapod");
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);

    params.not_before = yesterday;
    params.not_after = tomorrow;

    let key_pair = KeyPair::generate().unwrap();
    CertifiedKey {
        cert: params.self_signed(&key_pair).unwrap(),
        key_pair,
    }
}

/// Creates a leaf certificate and key for the given SAN, signed with the given root CA.
pub(crate) fn generate_mock_leaf(root_ca: &CertifiedKey, alt_name: rcgen::SanType) -> CertifiedKey {
    let common_name = "htapod";
    let mut params =
        CertificateParams::new(vec![common_name.into()]).expect("we know the name is valid");

    let (yesterday, tomorrow) = validity_period();

    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.use_authority_key_identifier_extension = true;
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    params.not_before = yesterday;
    params.not_after = tomorrow;
    params.subject_alt_names = vec![alt_name];

    let key_pair = KeyPair::generate().unwrap();
    let cert = params
        .signed_by(&key_pair, &root_ca.cert, &root_ca.key_pair)
        .unwrap();

    CertifiedKey { cert, key_pair }
}

/// Creates a fixed certificate validity period from yesterday until tomorrow.
#[doc(hidden)]
fn validity_period() -> (OffsetDateTime, OffsetDateTime) {
    let day = Duration::new(86400, 0);
    let yesterday = OffsetDateTime::now_utc().checked_sub(day).unwrap();
    let tomorrow = OffsetDateTime::now_utc().checked_add(day).unwrap();
    (yesterday, tomorrow)
}

// Shamelessly copied from reqwest's tls.rs.
#[derive(Debug)]
pub(crate) struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer,
        _intermediates: &[rustls_pki_types::CertificateDer],
        _server_name: &rustls_pki_types::ServerName,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validity_period() {
        let (yesterday, tomorrow) = validity_period();
        let now = OffsetDateTime::now_utc();
        // Test validity end is after now.
        assert!(tomorrow - now > Duration::hours(23));
        // Test validity start is before now.
        assert!(now - yesterday > Duration::hours(23));
    }

    #[test]
    fn test_generate_ca() {
        let _ = generate_ca();
    }

    #[test]
    fn test_generate_mock_leaf() {
        let ca = generate_ca();
        let ip_san = rcgen::SanType::IpAddress("10.10.10.10".parse::<std::net::IpAddr>().unwrap());
        let leaf = generate_mock_leaf(&ca, ip_san.clone());
        assert!(leaf.cert.params().subject_alt_names.contains(&ip_san));

        let dns_san = rcgen::SanType::DnsName("htapod.dev".try_into().unwrap());
        let leaf = generate_mock_leaf(&ca, dns_san.clone());
        assert!(leaf.cert.params().subject_alt_names.contains(&dns_san));
    }
}
