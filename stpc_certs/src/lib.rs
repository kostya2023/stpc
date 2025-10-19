use stpc_core::{StpcError, CertificateVersion, SignatureAlgorithm};
use stpc_encoding::{TLVParser, TLV};
use rand::{rngs::OsRng, RngCore};

// === TYPES ===

// Validity
#[derive(Debug, Clone)]
pub struct Validity {
    pub not_before: u64,
    pub not_after:  u64,
}

// DistinguishedName
#[derive(Debug, Clone)]
pub struct DistinguishedName {
    pub common_name:    String,
    pub organization:   Option<String>,
    pub department:     Option<String>,
    pub country:        Option<String>,
    pub state:          Option<String>,
    pub locality:       Option<String>,
    pub email_address:  Option<String>,
}

// TbsCertificate
#[derive(Debug, Clone)]
pub struct TbsCertificate {
    pub version:             CertificateVersion,
    pub serial_number:       [u8; 8],
    pub signature_algorithm:  SignatureAlgorithm,
    pub issuser:             DistinguishedName,
    pub validity:            Validity,
    pub subject:             DistinguishedName,
    pub subject_public_key:  Vec<u8>,
    pub ocsp_url:            String,
}

// Certificate
#[derive(Debug, Clone)]
pub struct Certificate {
    pub tbs_certificate:      TbsCertificate,
    pub signature_algorithm:  SignatureAlgorithm,
    pub signature_value:      Vec<u8>,
}


// === TRAIT ===

pub trait CertSerializable {
    fn serialize(&self) -> Result<Vec<u8>, StpcError>;
    fn deserialize(data: &[u8]) -> Result<Self, StpcError>
    where
        Self: Sized;
}

// === VALIDITY ===

impl CertSerializable for Validity {
    fn serialize(&self) -> Result<Vec<u8>, StpcError> {
        let blocks_vec = [
            (1u8, self.not_after.to_be_bytes().to_vec()),
            (2u8, self.not_before.to_be_bytes().to_vec()),
        ];

        let blocks: Vec<(u8, &[u8])> = blocks_vec
            .iter()
            .map(|(tag, val)| (*tag, val.as_slice()))
            .collect();

        TLVParser::pack(&blocks)
    }

    fn deserialize(data: &[u8]) -> Result<Self, StpcError> {
        let mut blocks = TLVParser::unpack(data)?;

        let (tag, not_after_bytes) = blocks.remove(0);
        if tag != 1 {
            return Err(StpcError::DeserilizateError("Tag not_after != 1".into()));
        }
        let not_after = u64::from_be_bytes(
            not_after_bytes
                .as_slice()
                .try_into()
                .map_err(|_| StpcError::DeserilizateError("Invalid not_after length".into()))?,
        );

        let (tag, not_before_bytes) = blocks.remove(0);
        if tag != 2 {
            return Err(StpcError::DeserilizateError("Tag not_before != 2".into()));
        }
        let not_before = u64::from_be_bytes(
            not_before_bytes
                .as_slice()
                .try_into()
                .map_err(|_| StpcError::DeserilizateError("Invalid not_before length".into()))?,
        );

        Ok(Self { not_before, not_after })
    }
}

impl Validity {
    pub fn new(not_before: u64, not_after: u64) -> Self {
        Self { not_before, not_after }
    }

    pub fn check_validity(&self, now: u64) -> Result<bool, StpcError> {
        if self.not_before <= now && now <= self.not_after {
            Ok(true)
        } else {
            Err(StpcError::TimeCertValidError(
                "Certificate expired/didn't start acting".into(),
            ))
        }
    }
}

// === DISTINGUISHED NAME ===

impl DistinguishedName {
    pub fn new(
        common_name:    String,
        organization:   Option<String>,
        department:     Option<String>,
        country:        Option<String>,
        state:          Option<String>,
        locality:       Option<String>,
        email_address:  Option<String>,
    ) -> Self {
        Self {
            common_name,
            organization,
            department,
            country,
            state,
            locality,
            email_address,
        }
    }
}

impl CertSerializable for DistinguishedName {
    fn serialize(&self) -> Result<Vec<u8>, StpcError> {
        let mut temp: Vec<(u8, Vec<u8>)> = Vec::new();
        temp.push((1, self.common_name.as_bytes().to_vec()));

        if let Some(org) = &self.organization {
            temp.push((2, org.as_bytes().to_vec()));
        }
        if let Some(dep) = &self.department {
            temp.push((3, dep.as_bytes().to_vec()));
        }
        if let Some(country) = &self.country {
            temp.push((4, country.as_bytes().to_vec()));
        }
        if let Some(state) = &self.state {
            temp.push((5, state.as_bytes().to_vec()));
        }
        if let Some(locality) = &self.locality {
            temp.push((6, locality.as_bytes().to_vec()));
        }
        if let Some(email) = &self.email_address {
            temp.push((7, email.as_bytes().to_vec()));
        }

        let blocks: Vec<(u8, &[u8])> = temp
            .iter()
            .map(|(tag, val)| (*tag, val.as_slice()))
            .collect();

        TLVParser::pack(&blocks)
    }

    fn deserialize(data: &[u8]) -> Result<Self, StpcError> {
        let blocks = TLVParser::unpack(data)?;
        let mut dn = Self {
            common_name: String::new(),
            organization: None,
            department: None,
            country: None,
            state: None,
            locality: None,
            email_address: None,
        };

        for (tag, value) in blocks {
            let s = String::from_utf8(value).map_err(|_| {
                StpcError::DeserilizateError("Invalid UTF-8 in DistinguishedName".into())
            })?;
            match tag {
                1 => dn.common_name = s,
                2 => dn.organization = Some(s),
                3 => dn.department = Some(s),
                4 => dn.country = Some(s),
                5 => dn.state = Some(s),
                6 => dn.locality = Some(s),
                7 => dn.email_address = Some(s),
                _ => {}
            }
        }

        Ok(dn)
    }
}

// === TBS CERTIFICATE ===

impl TbsCertificate {
    pub fn new(
        version:             CertificateVersion,
        signature_algorithm:  SignatureAlgorithm,
        issuser:             DistinguishedName,
        validity:            Validity,
        subject:             DistinguishedName,
        subject_public_key:  Vec<u8>,
        ocsp_url:            String,
    ) -> Self {
        let mut csprng = OsRng;
        let mut serial_number: [u8; 8] = [0; 8];
        csprng.fill_bytes(&mut serial_number);

        Self {
            version,
            serial_number,
            signature_algorithm,
            issuser,
            validity,
            subject,
            subject_public_key,
            ocsp_url,
        }
    }
}

impl CertSerializable for TbsCertificate {
    fn serialize(&self) -> Result<Vec<u8>, StpcError> {
        let mut temp: Vec<(u8, Vec<u8>)> = Vec::new();

        temp.push((
            1,
            vec![match self.version {
                CertificateVersion::V1 => 1,
            }],
        ));
        temp.push((2, self.serial_number.to_vec()));

        let sig_alg = match self.signature_algorithm {
            SignatureAlgorithm::Ed25519 => 1,
            SignatureAlgorithm::Falcon512 => 2,
            SignatureAlgorithm::Falcon1024 => 3,
        };
        temp.push((3, vec![sig_alg]));

        temp.push((4, self.issuser.serialize()?));
        temp.push((5, self.validity.serialize()?));
        temp.push((6, self.subject.serialize()?));
        temp.push((7, self.subject_public_key.clone()));
        temp.push((8, self.ocsp_url.as_bytes().to_vec()));

        let blocks: Vec<(u8, &[u8])> = temp
            .iter()
            .map(|(tag, val)| (*tag, val.as_slice()))
            .collect();

        TLVParser::pack(&blocks)
    }

    fn deserialize(data: &[u8]) -> Result<Self, StpcError> {
        let mut blocks = TLVParser::unpack(data)?;

        let version = match blocks.remove(0).1[0] {
            1 => CertificateVersion::V1,
            _ => {
                return Err(StpcError::DeserilizateError("Unknown certificate version".into()))
            }
        };

        let serial_number: [u8; 8] = blocks
            .remove(0)
            .1
            .try_into()
            .map_err(|_| StpcError::DeserilizateError("Invalid serial_number length".into()))?;

        let signature_algorithm = match blocks.remove(0).1[0] {
            1 => SignatureAlgorithm::Ed25519,
            2 => SignatureAlgorithm::Falcon512,
            3 => SignatureAlgorithm::Falcon1024,
            _ => {
                return Err(StpcError::DeserilizateError("Unknown signature algorithm".into()))
            }
        };

        let issuser = DistinguishedName::deserialize(&blocks.remove(0).1)?;
        let validity = Validity::deserialize(&blocks.remove(0).1)?;
        let subject = DistinguishedName::deserialize(&blocks.remove(0).1)?;
        let subject_public_key = blocks.remove(0).1;
        let ocsp_url = String::from_utf8(blocks.remove(0).1)
            .map_err(|_| StpcError::DeserilizateError("Invalid UTF-8 in ocsp_url".into()))?;

        Ok(Self {
            version,
            serial_number,
            signature_algorithm,
            issuser,
            validity,
            subject,
            subject_public_key,
            ocsp_url,
        })
    }
}


// === CERTFICATE ===
impl Certificate {
    pub fn new(
        tbs_certificate: TbsCertificate,
        signature_algorithm: SignatureAlgorithm,
        signature_value: Vec<u8>,
    ) -> Self {
        Self {
            tbs_certificate,
            signature_algorithm,
            signature_value,
        }
    }
}


impl CertSerializable for Certificate {
    fn serialize(&self) -> Result<Vec<u8>, StpcError> {
        let mut temp: Vec<(u8, Vec<u8>)> = Vec::new();

        // tbs
        temp.push((1, self.tbs_certificate.serialize()?));

        // signature algorithm
        let sig_alg = match self.signature_algorithm {
            SignatureAlgorithm::Ed25519 => 1u8,
            SignatureAlgorithm::Falcon512 => 2u8,
            SignatureAlgorithm::Falcon1024 => 3u8,
        };
        temp.push((2, vec![sig_alg]));

        // signature value
        temp.push((3, self.signature_value.clone()));

        // теперь собираем безопасно
        let blocks: Vec<(u8, &[u8])> = temp
            .iter()
            .map(|(tag, data)| (*tag, data.as_slice()))
            .collect();

        TLVParser::pack(&blocks)
    }

    fn deserialize(data: &[u8]) -> Result<Self, StpcError> {
        let mut blocks = TLVParser::unpack(data)?;

        let tbs_certificate = TbsCertificate::deserialize(&blocks.remove(0).1)?;

        let sig_alg = match blocks.remove(0).1[0] {
            1 => SignatureAlgorithm::Ed25519,
            2 => SignatureAlgorithm::Falcon512,
            3 => SignatureAlgorithm::Falcon1024,
            _ => return Err(StpcError::DeserilizateError("Unknown signature algorithm".into())),
        };

        let signature_value = blocks.remove(0).1;

        Ok(Self {
            tbs_certificate,
            signature_algorithm: sig_alg,
            signature_value,
        })
    }
}

