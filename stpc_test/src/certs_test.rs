use stpc_certs::{TbsCertificate, Validity, DistinguishedName, CertSerializable};
use stpc_core::{CertificateVersion, SignatureAlgorithm, StpcError};

#[cfg(test)]
mod tests {
    use super::*;
    use stpc_crypto::{Ed25519, Falcon512, Falcon1024};
    use stpc_core::SigningOperands;

    fn test_algorithm<A: SigningOperands>() {
        // Генерация ключей
        let (priv_key, pub_key) = A::keypair().expect("Keypair generation failed");

        let message = b"Hello, STPC!";

        // Подпись
        let signature = A::sign(message, &priv_key).expect("Signing failed");

        // Проверка
        let verified = A::verify(message, &pub_key, &signature).expect("Verification failed");
        assert!(verified, "Signature should be valid");

        // Проверка на изменение сообщения
        let tampered = b"Hello, STPC?";
        let verified = A::verify(tampered, &pub_key, &signature).unwrap_or(false);
        assert!(!verified, "Tampered message should not verify");
    }

    #[test]
    fn test_ed25519() {
        test_algorithm::<Ed25519>();
    }

    #[test]
    fn test_falcon512() {
        test_algorithm::<Falcon512>();
    }

    #[test]
    fn test_falcon1024() {
        test_algorithm::<Falcon1024>();
    }

    #[test]
    fn test_cert_serialization() -> Result<(), StpcError> {
        let dn = DistinguishedName::new(
            "CN".to_string(),
            None, None, None, None, None, None
        );
        let val = Validity::new(0, 1000);
        let tbs = TbsCertificate::new(
            CertificateVersion::V1,
            SignatureAlgorithm::Ed25519,
            dn.clone(),
            val.clone(),
            dn,
            vec![1,2,3,4],
            "http://ocsp.example.com".to_string()
        );

        let serialized = tbs.serialize()?;
        let deserialized = TbsCertificate::deserialize(&serialized)?;

        // Сравниваем ключевые поля
        assert_eq!(deserialized.serial_number, tbs.serial_number);
        assert_eq!(deserialized.subject_public_key, tbs.subject_public_key);
        assert_eq!(deserialized.ocsp_url, tbs.ocsp_url);

        Ok(())
    }
}