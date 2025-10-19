use core::str;

use zeroize::{Zeroize, Zeroizing};
use thiserror::Error;




// Errors:
#[derive(Error, Debug)]
pub enum StpcError {
    #[error("Key generation error: {0}")]
    KeyGenerationError(String),

    #[error("Signature computing error: {0}")]
    SignatureComputingError(String),

    #[error("Signature verification error")]
    SignatureVerifyError,

    #[error("Time Service error: {0}")]
    TimeServiceError(String),

    #[error("Packet TLV error: {0}")]
    InvalidPacketError(String),

    #[error("Time cert validating error: {0}")]
    TimeCertValidError(String),

    #[error("Serilizate error: {0}")]
    SerilizateError(String),

    #[error("Deserilizate error: {0}")]
    DeserilizateError(String),
}


// NTP Servers:
#[derive(Debug, Clone, Copy)]
pub enum NtpServers {
    TimeGoogleCom,
    PoolNtpOrg,
    TimeWindowsCom,
    TimeAppleCom,
    TimeCloudflareCom,
}

impl NtpServers {
    pub fn address(&self) -> &'static str {
        match self {
            NtpServers::TimeGoogleCom     => "time.google.com:123",      // 216.239.35.0:123
            NtpServers::PoolNtpOrg        => "pool.ntp.org:123",         // 151.0.2.53:123
            NtpServers::TimeWindowsCom    => "time.windows.com:123",     // 20.101.57.9:123
            NtpServers::TimeAppleCom      => "time.apple.com:123",       // 17.253.38.43:123
            NtpServers::TimeCloudflareCom => "time.cloudflare.com:123",  // 162.159.200.1:123
        }
    }

    pub fn all() -> &'static [NtpServers] {
        &[
            NtpServers::TimeGoogleCom,
            NtpServers::PoolNtpOrg,
            NtpServers::TimeWindowsCom,
            NtpServers::TimeAppleCom,
            NtpServers::TimeCloudflareCom,
        ]
    }
}


// Enums

//Enum: CertificateVersion
#[derive(Debug, Clone)]
pub enum CertificateVersion{
    V1,
} 

// Enum: Signature Algorithm
#[derive(Debug, Clone)]
pub enum SignatureAlgorithm {
    Ed25519,
    Falcon512,
    Falcon1024,
}


// Traits:
pub trait Key {
    fn as_bytes(&self) -> &[u8];
    fn zeroize(&mut self);
}

pub trait SigningOperands {
    fn keypair() -> Result<(PrivateKey, PublicKey), StpcError>;
    fn sign(message: &[u8], private_key: &PrivateKey) -> Result<Signature, StpcError>;
    fn verify(message: &[u8], public_key: &PublicKey, signature: &Signature) -> Result<bool, StpcError>;
}





// Types:

// Type: PrivateKey
#[derive(Debug)]
pub struct PrivateKey(Zeroizing<Vec<u8>>);
impl PrivateKey {
    /// Create exemplar
    pub fn new(slice: usize) -> Self {
        Self(Zeroizing::new(vec![0u8; slice]))
    }

    /// Create exemplar from [u8] bytes
    pub fn from_bytes(slice: &[u8]) -> Self {
        Self(Zeroizing::new(slice.to_vec()))
    }
}
impl Key for PrivateKey {
    /// Get PrivateKey for view
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Manually zeroize 
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

// Type: Signature
#[derive(Debug)]
pub struct Signature(Zeroizing<Vec<u8>>);

impl Signature {
    pub fn from_bytes(slice: &[u8]) -> Self {
        Self(Zeroizing::new(slice.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

//Type: PublicKey
#[derive(Debug)]
pub struct PublicKey(Zeroizing<Vec<u8>>);
impl PublicKey {
    pub fn new(slice: usize) -> Self {
        Self(Zeroizing::new(vec![0u8; slice]))
    }

    /// Create exemplar from [u8] bytes
    pub fn from_bytes(slice: &[u8]) -> Self {
        Self(Zeroizing::new(slice.to_vec()))
    }
}
impl Key for PublicKey {
    /// Get PrivateKey for view
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Manually zeroize 
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}




// Drops:

// Drop: PrivateKey
impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// Drop: PublicKey
impl Drop for PublicKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}