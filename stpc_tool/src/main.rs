use stpc_certs::{TbsCertificate, Certificate, Validity, DistinguishedName, CertSerializable};
use stpc_core::{CertificateVersion, SignatureAlgorithm, StpcError};

fn main() -> Result<(), StpcError> {
    // === Создаем пример DistinguishedName для issuer и subject ===
    let issuer = DistinguishedName::new(
        "Issuer CN".to_string(),
        Some("Issuer Org".to_string()),
        Some("Issuer Dept".to_string()),
        Some("US".to_string()),
        Some("California".to_string()),
        Some("San Francisco".to_string()),
        Some("issuer@example.com".to_string()),
    );

    let subject = DistinguishedName::new(
        "Subject CN".to_string(),
        Some("Subject Org".to_string()),
        None,
        Some("US".to_string()),
        None,
        Some("Los Angeles".to_string()),
        Some("subject@example.com".to_string()),
    );

    // === Создаем пример Validity ===
    let validity = Validity::new(1_700_000_000, 1_800_000_000);

    // === Создаем TbsCertificate ===
    let tbs = TbsCertificate::new(
        CertificateVersion::V1,
        SignatureAlgorithm::Ed25519,
        issuer,
        validity,
        subject,
        vec![0xAA; 32], // пример публичного ключа
        "http://ocsp.example.com".to_string(),
    );

    let cert = Certificate::new(tbs.clone(), SignatureAlgorithm::Ed25519, vec![0xBB; 64]); // пример подписи

    // === Сериализация ===
    let serialized = cert.serialize()?;
    println!("Serialized Certificate: {:?}", serialized);

    // === Десериализация ===
    let deserialized = Certificate::deserialize(&serialized)?;
    println!("Deserialized Certificate:\n{:?}", deserialized);

    Ok(())
}