use stpc_core::{SigningOperands};
use stpc_crypto::{Ed25519, Falcon512, Falcon1024};

#[cfg(test)]
mod tests {
    use super::*;

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
}
