use rand::rngs::OsRng;

use ed25519_dalek::SigningKey;
use ed25519_dalek::VerifyingKey;
use ed25519_dalek::Signer;
use ed25519_dalek::Verifier;
use ed25519_dalek::Signature as EdSignature;

use std::convert::TryInto;

use stpc_core::Key;
use stpc_core::Signature;
use stpc_core::SigningOperands;
use stpc_core::PrivateKey;
use stpc_core::PublicKey;
use stpc_core::StpcError;

use pqcrypto_falcon::falcon512;
use pqcrypto_falcon::falcon512::DetachedSignature as DetachedSignature512;
use pqcrypto_falcon::falcon1024::DetachedSignature as DetachedSignature1024;
use pqcrypto_falcon::falcon1024;
use pqcrypto_traits::sign::SecretKey;
use pqcrypto_traits::sign::PublicKey as FalconPublicKey;
use pqcrypto_traits::sign::DetachedSignature as FalconDetachedSignature;



// Sign classes (обязательное наследование от trait SigningOperands):
pub struct Ed25519 {}
pub struct Falcon512 {}
pub struct Falcon1024 {}


impl SigningOperands for Ed25519 {
    fn keypair() -> Result<(PrivateKey, PublicKey), StpcError> {

        let mut csprng = OsRng;

        let private: SigningKey = SigningKey::generate(&mut csprng);
        let public: VerifyingKey = private.verifying_key();

        let private = PrivateKey::from_bytes(&private.to_bytes());
        let public = PublicKey::from_bytes(&public.to_bytes());

        Ok((private, public))
    }

    fn sign(message: &[u8], private_key: &PrivateKey) -> Result<Signature, StpcError> {

        let key_bytes: [u8; 32] = private_key.as_bytes()
            .try_into()
            .map_err(|_| StpcError::KeyGenerationError("Private key must be 32 bytes".into()))?;

        let signing_key = SigningKey::from_bytes(&key_bytes);

        let sig = signing_key.sign(message);

        Ok(Signature::from_bytes(&sig.to_bytes()))
    }


    fn verify(message: &[u8], public_key: &PublicKey, signature: &Signature) -> Result<bool, StpcError> {


        // Преобразуем public key в [u8; 32]
        let key_bytes: [u8; 32] = public_key.as_bytes()
            .try_into()
            .map_err(|_| StpcError::KeyGenerationError("Public key must be 32 bytes".into()))?;

        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| StpcError::KeyGenerationError("Invalid public key bytes".into()))?;

        // Преобразуем signature в [u8; 64] и потом в EdSignature
        let sig_bytes: [u8; 64] = signature.as_bytes()
            .try_into()
            .map_err(|_| StpcError::SignatureVerifyError)?;
        let sig = EdSignature::from_bytes(&sig_bytes);

        // Проверяем подпись
        match verifying_key.verify(message, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Err(StpcError::SignatureVerifyError),
        }
    }

}




impl SigningOperands for Falcon512 {
    fn keypair() -> Result<(PrivateKey, PublicKey), StpcError> {

        let (public, private) = falcon512::keypair();

        let public = PublicKey::from_bytes(public.as_bytes());
        let private = PrivateKey::from_bytes(private.as_bytes());
        Ok((private, public))
    }

    fn sign(message: &[u8], private_key: &PrivateKey) -> Result<Signature, StpcError> {

        let private_key = SecretKey::from_bytes(private_key.as_bytes())
            .map_err(|_| StpcError::KeyGenerationError("Invalid Falcon512 private key".into()))?;

        let sig = falcon512::detached_sign(message, &private_key);

        Ok(Signature::from_bytes(sig.as_bytes()))
    }


    fn verify(message: &[u8], public_key: &PublicKey, signature: &Signature) -> Result<bool, StpcError> {
        
        let public_key = FalconPublicKey::from_bytes(public_key.as_bytes())
            .map_err(|_| StpcError::KeyGenerationError("Invalid Falcon512 public key".into()))?;

        let signature = DetachedSignature512::from_bytes(signature.as_bytes())
            .map_err(|_| StpcError::SignatureVerifyError)?;

        match falcon512::verify_detached_signature(&signature, message, &public_key) {
            Ok(()) => Ok(true),
            Err(_) => Err(StpcError::SignatureVerifyError),
        }

    }
}



impl SigningOperands for Falcon1024 {
    fn keypair() -> Result<(PrivateKey, PublicKey), StpcError> {

        let (public, private) = falcon1024::keypair();

        let public = PublicKey::from_bytes(public.as_bytes());
        let private = PrivateKey::from_bytes(private.as_bytes());
        Ok((private, public))
    }

    fn sign(message: &[u8], private_key: &PrivateKey) -> Result<Signature, StpcError> {

        let private_key = SecretKey::from_bytes(private_key.as_bytes())
            .map_err(|_| StpcError::KeyGenerationError("Invalid Falcon1024 private key".into()))?;

        let sig = falcon1024::detached_sign(message, &private_key);

        Ok(Signature::from_bytes(sig.as_bytes()))
    }


    fn verify(message: &[u8], public_key: &PublicKey, signature: &Signature) -> Result<bool, StpcError> {
        
        let public_key = FalconPublicKey::from_bytes(public_key.as_bytes())
            .map_err(|_| StpcError::KeyGenerationError("Invalid Falcon1024 public key".into()))?;

        let signature = DetachedSignature1024::from_bytes(signature.as_bytes())
            .map_err(|_| StpcError::SignatureVerifyError)?;

        match falcon1024::verify_detached_signature(&signature, message, &public_key) {
            Ok(()) => Ok(true),
            Err(_) => Err(StpcError::SignatureVerifyError),
        }

    }
}

