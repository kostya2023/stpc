use stpc_core::{PrivateKey, PublicKey};
use stpc_core::Key;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_key_length() {
        let pk = PrivateKey::new(32);
        assert_eq!(pk.as_bytes().len(), 32);
    }

    #[test]
    fn test_public_key_dummy() {
        let pk = PublicKey::from_bytes(&[1u8; 32]);
        assert_eq!(pk.as_bytes().len(), 32);
    }
}
