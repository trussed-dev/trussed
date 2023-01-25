use flexiber::{
    Encodable, EncodableHeapless, Encoder, Length as BerLength, Result as BerResult, Tag,
    TaggedSlice, TaggedValue,
};
use hex_literal::hex;
use rand_core::RngCore;

use crate::{
    api::{reply::Attest as AttestReply, request, request::Attest as AttestRequest},
    error::Error,
    key, mechanisms,
    service::{DeriveKey, SerializeKey, Sign},
    store::certstore::Certstore,
    store::keystore::Keystore,
    types::{
        KeyId, KeySerialization, Location, Mechanism, Message, SignatureSerialization,
        StorageAttributes,
    },
};

#[cfg(not(feature = "test-attestation-cert-ids"))]
pub const ED255_ATTN_KEY: KeyId = KeyId::from_special(1);
#[cfg(feature = "test-attestation-cert-ids")]
pub const ED255_ATTN_KEY: KeyId = KeyId(crate::types::Id(u128::from_be_bytes([
    0x12, 0xd2, 0xa7, 0xe4, 0x03, 0x55, 0x21, 0x42, 0x99, 0xf1, 0x57, 0x34, 0xc5, 0xd7, 0xd0, 0xe7,
])));
#[cfg(not(feature = "test-attestation-cert-ids"))]
pub const P256_ATTN_KEY: KeyId = KeyId::from_special(2);
#[cfg(feature = "test-attestation-cert-ids")]
pub const P256_ATTN_KEY: KeyId = KeyId(crate::types::Id(u128::from_be_bytes([
    0xc8, 0xd6, 0x77, 0xa3, 0x93, 0x46, 0xc9, 0x8f, 0xc8, 0x5a, 0xb0, 0x5d, 0x29, 0xc5, 0x75, 0x32,
])));

#[inline(never)]
pub fn try_attest(
    attn_keystore: &mut impl Keystore,
    certstore: &mut impl Certstore,
    keystore: &mut impl Keystore,
    request: &AttestRequest,
) -> Result<AttestReply, Error> {
    let signature_algorithm = SignatureAlgorithm::try_from(request.signing_mechanism)?;

    // 1. Construct the TBS Certificate

    let mut serial = [0u8; 20];
    keystore.rng().fill_bytes(&mut serial);

    enum KeyAlgorithm {
        Ed255,
        P256,
    }

    let key_algorithm = match keystore.key_info(key::Secrecy::Secret, &request.private_key) {
        None => return Err(Error::NoSuchKey),
        Some(info) => {
            if !info.flags.contains(key::Flags::LOCAL) {
                return Err(Error::InvalidSerializedKey);
            }

            match info.kind {
                key::Kind::P256 => KeyAlgorithm::P256,
                key::Kind::Ed255 => KeyAlgorithm::Ed255,
                _ => return Err(Error::NoSuchKey),
            }
        }
    };

    let spki = match key_algorithm {
        KeyAlgorithm::Ed255 => {
            let public_key = mechanisms::Ed255::derive_key(
                keystore,
                &request::DeriveKey {
                    mechanism: Mechanism::Ed255,
                    base_key: request.private_key,
                    additional_data: None,
                    attributes: StorageAttributes::new().set_persistence(Location::Volatile),
                },
            )?
            .key;
            let serialized_key = mechanisms::Ed255::serialize_key(
                keystore,
                &request::SerializeKey {
                    mechanism: Mechanism::Ed255,
                    key: public_key,
                    format: KeySerialization::Raw,
                },
            )
            .unwrap()
            .serialized_key;
            keystore.delete_key(&public_key);

            SerializedSubjectPublicKey::Ed255(
                serialized_key
                    .as_ref()
                    .try_into()
                    .map_err(|_| Error::ImplementationError)?,
            )
        }

        KeyAlgorithm::P256 => {
            let public_key = mechanisms::P256::derive_key(
                keystore,
                &request::DeriveKey {
                    mechanism: Mechanism::P256,
                    base_key: request.private_key,
                    additional_data: None,
                    attributes: StorageAttributes::new().set_persistence(Location::Volatile),
                },
            )?
            .key;
            let serialized_key = mechanisms::P256::serialize_key(
                keystore,
                &request::SerializeKey {
                    mechanism: Mechanism::P256,
                    key: public_key,
                    format: KeySerialization::Sec1,
                },
            )
            .unwrap()
            .serialized_key;
            keystore.delete_key(&public_key);

            SerializedSubjectPublicKey::P256(
                serialized_key
                    .as_ref()
                    .try_into()
                    .map_err(|_| Error::ImplementationError)?,
            )
        }
    };

    let to_be_signed_certificate = TbsCertificate {
        version: Version::V3,
        serial: BigEndianInteger(serial.as_ref()),
        signature_algorithm,
        issuer: Name::default()
            .with_country(b"CH")
            .with_organization("Trussed")
            .with_state("Zurich"),
        // validity: Validity { start: Datetime(b"20210313120000Z"), end: None },
        validity: Validity {
            start: Datetime(b"20210313120000Z"),
            end: None,
        },
        // subject: Name::default(),
        subject: Name::default(), //.with_country(b"CH").with_organization("Trussed").with_state("Zurich"),
        subject_public_key_info: spki,
    };

    let message = Message::from(
        TaggedValue::new(Tag::SEQUENCE, &to_be_signed_certificate)
            .to_heapless_vec()
            .map_err(|_| Error::InternalError)?,
    );

    // 2. sign the TBS Cert
    let signature = match signature_algorithm {
        SignatureAlgorithm::Ed255 => {
            let signature = mechanisms::Ed255::sign(
                attn_keystore,
                &request::Sign {
                    mechanism: Mechanism::Ed255,
                    key: ED255_ATTN_KEY,
                    message,
                    format: SignatureSerialization::Raw,
                },
            )
            .unwrap()
            .signature;
            SerializedSignature::Ed255(signature.as_ref().try_into().unwrap())
        }
        SignatureAlgorithm::P256 => SerializedSignature::P256(
            heapless_bytes::Bytes::from_slice(
                mechanisms::P256::sign(
                    attn_keystore,
                    &request::Sign {
                        mechanism: Mechanism::P256,
                        key: P256_ATTN_KEY,
                        message,
                        format: SignatureSerialization::Asn1Der,
                    },
                )
                .unwrap()
                .signature
                .as_ref(),
            )
            .unwrap(),
        ),
    };

    let mut leading_zero_signature = [0u8; 80];
    let l = signature.as_ref().len();
    leading_zero_signature[1..][..l].copy_from_slice(signature.as_ref());

    // 3. construct the entire DER-serialized cert
    let certificate = Message::from(
        Certificate {
            tbs_certificate: to_be_signed_certificate,
            signature_algorithm,
            signature: &leading_zero_signature[..l + 1],
        }
        .to_heapless_vec()
        .map_err(|_| Error::ImplementationError)?,
    );

    let id = certstore.write_certificate(Location::Internal, &certificate)?;

    Ok(AttestReply { certificate: id })
}

#[derive(Clone, Copy, Encodable, Eq, PartialEq)]
pub struct TbsCertificate<'l> {
    // this is "EXPLICIT [0]", where 0 translates to 0x00 and EXPLICIT to constructed|context
    #[tlv(constructed, context, number = "0x0")]
    version: Version,
    #[tlv(number = "0x2")] // INTEGER
    serial: BigEndianInteger<'l>,
    #[tlv(constructed, number = "0x10")] // SEQUENCE
    signature_algorithm: SignatureAlgorithm,
    /// TODO: This MUST be non-empty. Maybe just put O=Trussed
    #[tlv(constructed, number = "0x10")] // SEQUENCE
    issuer: Name<'l>,
    #[tlv(constructed, number = "0x10")] // SEQUENCE
    validity: Validity<'l>,
    /// This one seems optional
    #[tlv(constructed, number = "0x10")] // SEQUENCE
    subject: Name<'l>,
    #[tlv(constructed, number = "0x10")] // SEQUENCE
    subject_public_key_info: SerializedSubjectPublicKey,
    // optional
    // extensions: Extensions
}

#[derive(Clone, Encodable, Eq, PartialEq)]
#[tlv(constructed, number = "0x10")] // SEQUENCE
pub struct Certificate<'l> {
    #[tlv(constructed, number = "0x10")] // SEQUENCE
    tbs_certificate: TbsCertificate<'l>,
    #[tlv(constructed, number = "0x10")] // SEQUENCE
    signature_algorithm: SignatureAlgorithm,
    #[tlv(number = "0x3", slice)] // BIT-STRING
    signature: &'l [u8], //SerializedSignature,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SerializedSignature {
    Ed255([u8; 64]),
    // This is the DER version with leading '04'
    P256(heapless_bytes::Bytes<72>),
}

impl AsRef<[u8]> for SerializedSignature {
    fn as_ref(&self) -> &[u8] {
        use SerializedSignature::*;
        match self {
            Ed255(array) => array.as_ref(),
            P256(bytes) => bytes.as_slice(),
        }
    }
}

// impl Encodable for SerializedSignature {
//     fn encoded_length(&self) -> BerResult<BerLength> {
//         // a leading '00' byte to say that we have no unused bits
//         Ok((match self {
//             SerializedSignature::Ed255(_) => 65,
//             SerializedSignature::P256(signature) => signature.len() as u16 + 1
//         } as u8).into())
//     }

//     fn encode(&self, encoder: &mut Encoder<'_>) -> BerResult<()> {
//         // NB: BIT-STRING needs to have number of "unused bits" in first byte (we have none)
//         match self {
//             SerializedSignature::Ed255(signature) => {
//                 let mut leading_zero = [0u8; 65];
//                 leading_zero[1..].copy_from_slice(signature.as_ref());
//                 // encoder.encode(&leading_zero)
//                 encoder.encode(&TaggedSlice::from(
//                     Tag::BIT_STRING,
//                     &leading_zero,
//                 )?)

//                 // encoder.encode(&flexiber
//             }
//             SerializedSignature::P256(signature) => {
//                 encoder.encode(&TaggedSlice::from(
//                     Tag::SEQUENCE,
//                     P256_OID_ENCODING,
//                 )?)?;
//                 let mut leading_zero = [0u8; 73];
//                 let l = signature.len() + 1;
//                 leading_zero[1..][..signature.len()].copy_from_slice(signature.as_ref());
//                 encoder.encode(&TaggedSlice::from(
//                     Tag::BIT_STRING,
//                     &leading_zero[..l],
//                 )?)
//             }
//         }
//     }
// }

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Version {
    /// Encode as INTEGER 2
    V3,
}

impl Version {
    // const ENCODING: &'static [u8] = &[0xA0, 0x03, 0x02, 0x01, 0x02];
    const ENCODING: &'static [u8] = &[0x02, 0x01, 0x02];
}

impl Encodable for Version {
    fn encoded_length(&self) -> BerResult<BerLength> {
        Ok((Self::ENCODING.len() as u8).into())
    }

    fn encode(&self, encoder: &mut Encoder<'_>) -> BerResult<()> {
        encoder.encode(&Self::ENCODING)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
/// NB: This is not a full INTEGER implementation, needs the leading tag + length.
/// We do it this way because the flexiber derive macro currently expects fields to be tagged.
pub struct BigEndianInteger<'a>(pub &'a [u8]);

impl Encodable for BigEndianInteger<'_> {
    fn encoded_length(&self) -> BerResult<BerLength> {
        let mut num = self.0;
        // leading zeros must be trimmed (except zero, see below)
        while !num.is_empty() && num[0] == 0 {
            num = &num[1..];
        }
        let mut l = num.len();
        // leading bit of unsigned integer must be zero
        if num.is_empty() || num[0] >= 0x80 {
            l += 1;
        }
        Ok((l as u16).into())
    }

    fn encode(&self, encoder: &mut Encoder<'_>) -> BerResult<()> {
        let mut num = self.0;
        while !num.is_empty() && num[0] == 0 {
            num = &num[1..];
        }
        if num.is_empty() || num[0] >= 0x80 {
            encoder.encode(&[0])?;
        }
        encoder.encode(&num)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum SignatureAlgorithm {
    Ed255,
    P256,
}

impl TryFrom<Mechanism> for SignatureAlgorithm {
    type Error = Error;
    fn try_from(mechanism: Mechanism) -> Result<Self, Error> {
        Ok(match mechanism {
            Mechanism::Ed255 => SignatureAlgorithm::Ed255,
            Mechanism::P256 => SignatureAlgorithm::P256,
            _ => return Err(Error::MechanismNotAvailable),
        })
    }
}

// 1.2.840.10045.4.3.2 ecdsaWithSHA256 (ANSI X9.62 ECDSA algorithm with SHA256))
const P256_OID_ENCODING: &[u8] = &hex!("06 08  2A 86 48 CE 3D 04 03 02");
const P256_PUB_ENCODING: &[u8] =
    &hex!("06 07 2A 86 48 CE 3D 02 01   06 08 2A 86 48 CE  3D 03 01 07");
// 1.3.101.112 curveEd25519 (EdDSA 25519 signature algorithm)
const ED255_OID_ENCODING: &[u8] = &hex!("06 03  2B 65 70");

impl Encodable for SignatureAlgorithm {
    fn encoded_length(&self) -> BerResult<BerLength> {
        Ok((match self {
            SignatureAlgorithm::Ed255 => ED255_OID_ENCODING.len(),
            SignatureAlgorithm::P256 => P256_OID_ENCODING.len(),
        } as u8)
            .into())
    }

    fn encode(&self, encoder: &mut Encoder<'_>) -> BerResult<()> {
        encoder.encode(match self {
            SignatureAlgorithm::Ed255 => &ED255_OID_ENCODING,
            SignatureAlgorithm::P256 => &P256_OID_ENCODING,
        })
    }
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct Name<'l> {
    /// this should be an ISO-code (in particular, "printable characters")
    /// TODO: enforce
    country: Option<[u8; 2]>,
    organization: Option<&'l str>,
    state: Option<&'l str>,
}

#[derive(Clone, Copy, Encodable, Eq, PartialEq)]
#[tlv(constructed, number = "0x10")] // SEQUENCE = 0x10
struct EncodedPart<'l> {
    #[tlv(number = "0x6")] // OBJECT_IDENTIFIER
    oid: &'l [u8],
    #[tlv(number = "0xC")] // UTF8_STRING
    part: &'l [u8],
}

impl<'l> Name<'l> {
    pub fn with_country(self, country: &[u8; 2]) -> Self {
        Self {
            country: Some(*country),
            ..self
        }
    }
    pub fn with_organization(self, organization: &'l str) -> Self {
        Self {
            organization: Some(organization),
            ..self
        }
    }
    pub fn with_state(self, state: &'l str) -> Self {
        Self {
            state: Some(state),
            ..self
        }
    }
}

impl Encodable for Name<'_> {
    fn encoded_length(&self) -> BerResult<BerLength> {
        let mut l = 0u16;
        if self.country.is_some() {
            l += 0xD;
        }
        if let Some(organization) = self.organization {
            l += 11 + organization.as_bytes().len() as u16;
        }
        if let Some(state) = self.state {
            l += 11 + state.as_bytes().len() as u16;
        }
        Ok(l.into())
    }

    fn encode(&self, encoder: &mut Encoder<'_>) -> BerResult<()> {
        // Order by OID for good measure
        if let Some(country) = self.country {
            // "31 0B 30 09 06 03 55  04 06 13 02 43 48"
            let mut encoding: [u8; 0xB] = hex!("30 09 06 03 55  04 06 13 02 00 00");
            encoding[9..].copy_from_slice(&country);
            encoder.encode(&TaggedSlice::from(Tag::SET, &encoding)?)?;
        }
        if let Some(state) = self.state {
            let encoded_state = EncodedPart {
                oid: &hex!("55 04 08"),
                part: state.as_bytes(),
            };
            encoder.encode(&TaggedValue::new(Tag::SET, &encoded_state))?;
        }
        if let Some(organization) = self.organization {
            let encoded_organization = EncodedPart {
                oid: &hex!("55 04 0A"),
                part: organization.as_bytes(),
            };
            encoder.encode(&TaggedValue::new(Tag::SET, &encoded_organization))?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
/// Currently unconstructable.
pub enum Extension {}

#[derive(Clone, Copy, Eq, PartialEq)]
/// Only empty slices possible currently.
pub struct Extensions<'l>(&'l [Extension]);

impl Encodable for Extensions<'_> {
    fn encoded_length(&self) -> BerResult<BerLength> {
        Ok(0u8.into())
    }
    fn encode(&self, _encoder: &mut Encoder<'_>) -> BerResult<()> {
        Ok(())
    }
}

pub struct ParsedDatetime {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
}

impl ParsedDatetime {
    pub fn new(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Option<Self> {
        let valid = [
            year >= 2000,
            year <= 9999,
            month >= 1,
            month <= 12,
            day >= 1,
            day <= 31,
            hour <= 23,
            minute <= 59,
            second <= 59,
        ]
        .iter()
        .all(|b| *b);

        if valid {
            Some(Self {
                year,
                month,
                day,
                hour,
                minute,
                second,
            })
        } else {
            None
        }
    }

    pub fn to_bytes(&self) -> [u8; 15] {
        let mut buffer: heapless::Vec<u8, 15> = Default::default();
        buffer.resize_default(15).unwrap();
        core::fmt::write(
            &mut buffer,
            format_args!(
                "{}{:02}{:02}{:02}{:02}{:02}Z",
                self.year, self.month, self.day, self.hour, self.minute, self.second
            ),
        )
        .unwrap();
        let mut array = [0u8; 15];
        array.copy_from_slice(&buffer);
        array
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
/// Encoded as "YYYYMMDDHHMMSSZ", encoding takes care of truncating YYYY to YY if necessary.
pub struct Datetime<'l>(&'l [u8]);

impl Encodable for Datetime<'_> {
    fn encoded_length(&self) -> BerResult<BerLength> {
        // before 2050: UtcTime -> truncate YYYY to YY
        Ok(if &self.0[..4] < b"2050" {
            0xFu8
        // starting 2050: GeneralizedTime -> keep YYYY
        } else {
            0x11u8
        }
        .into())
    }
    fn encode(&self, encoder: &mut Encoder<'_>) -> BerResult<()> {
        let tagged_slice = if &self.0[..4] < b"2050" {
            TaggedSlice::from(Tag::UTC_TIME, &self.0[2..])?
        } else {
            TaggedSlice::from(Tag::GENERALIZED_TIME, self.0)?
        };
        encoder.encode(&tagged_slice)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Validity<'l> {
    /// Encoded as "YYYYMMDDHHMMSSZ", encoding takes care of truncating YYYY to YY if necessary.
    start: Datetime<'l>,
    /// defaults to 9999-12-31T23:59:59Z
    end: Option<Datetime<'l>>,
}

impl Encodable for Validity<'_> {
    fn encoded_length(&self) -> BerResult<BerLength> {
        // before 2050: UtcTime -> truncate YYYY to YY
        self.start.encoded_length()?
            + self
                .end
                .unwrap_or(Datetime(b"99991231235959Z"))
                .encoded_length()?
    }

    fn encode(&self, encoder: &mut Encoder<'_>) -> BerResult<()> {
        encoder.encode(&self.start)?;
        encoder.encode(&self.end.unwrap_or(Datetime(b"99991231235959Z")))
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum SerializedSubjectPublicKey {
    Ed255([u8; 32]),
    // This is the DER version with leading '04'
    P256([u8; 33]),
}

impl Encodable for SerializedSubjectPublicKey {
    fn encoded_length(&self) -> BerResult<BerLength> {
        Ok((match self {
            SerializedSubjectPublicKey::Ed255(_) => 0x2A,
            SerializedSubjectPublicKey::P256(_) => 0x39,
        } as u8)
            .into())
    }

    fn encode(&self, encoder: &mut Encoder<'_>) -> BerResult<()> {
        // NB: BIT-STRING needs to have number of "unused bits" in first byte (we have none)
        match self {
            SerializedSubjectPublicKey::Ed255(pub_key) => {
                encoder.encode(&TaggedSlice::from(Tag::SEQUENCE, ED255_OID_ENCODING)?)?;
                let mut leading_zero = [0u8; 33];
                leading_zero[1..].copy_from_slice(pub_key.as_ref());
                encoder.encode(&TaggedSlice::from(Tag::BIT_STRING, &leading_zero)?)

                // encoder.encode(&flexiber
            }
            SerializedSubjectPublicKey::P256(pub_key) => {
                encoder.encode(&TaggedSlice::from(Tag::SEQUENCE, P256_PUB_ENCODING)?)?;
                let mut leading_zero = [0u8; 34];
                leading_zero[1..].copy_from_slice(pub_key.as_ref());
                encoder.encode(&TaggedSlice::from(Tag::BIT_STRING, &leading_zero)?)
            }
        }
    }
}

//use der::{Any, Encodable, Decodable, Message, ObjectIdentifier};

//use crate::types::Id;

//// - key_id: ObjectHandle
//// - key_mechanism: Mechanism
//// - attestation_mechanism: Mechanism
//// - attestation_location: Location

//const MAX_CERT_SIZE: ArrayLength<u8> = consts::U2048;

//pub fn attest_key() -> Id {

//    // 1. verify key exists, is local, and is suitable as X509 SPKI
//    //    (for now: either P256, Ed255 or X255)

//    // 2. construct "to-be-signed" certificate
//    let tbs_certificate = TbsCertificate::from(

//    let encoded_tbs_certificate: Bytes<MAX_CERT_SIZE> = tbs_certificate().to_heapless_bytes();

//    let public_key_id = match key_mechanism {
//        Ed255 | X255 => {
//            Ed255::derive_key(client_keystore, DeriveKey {
//                mechanism: Ed255,
//                base_key: key_id,
//                attributes: Volatile,
//            })?.object_id
//        }
//        P256 => {
//            P256::derive_key(client_keystore, DeriveKey {
//                mechanism: P256,
//                base_key: key_id,
//                attributes: Volatile,
//            })?.object_id
//        }
//        _ => todo!(),
//    };

//    let public_key_bytes = match key_mechanism {
//        Ed255 | X255 => {
//            Ed255::serialize_key(client_keystore, DeriveKey {
//                mechanism: Ed255, key: public_key_id, format: Der
//            }?.serialized_key
//        }
//        P256 => {
//            P256::serialize_key(client_keystore, DeriveKey {
//                mechanism: P256, key: public_key_id, format: Der
//            }?.serialized_key
//        }
//        _ => todo!(),
//    }

//    // 3. sign the TBS Certificate, using one of the available attn keys
//    let attestation_key_id = match attestation_mechanism {
//        Ed255 => Id(1),
//        P256 => Id(2),
//        _ => todo!(),
//    };

//    // TODO: delete the temporary public key handle

//    // 4. construct the actual certificate

//    // TODO: delete the temporary attn key handle
//    todo!();

//    // 5. store the certificate and return its ID
//    todo!();

//}

//// From [RFC 5280](https://tools.ietf.org/html/rfc5280#section-4.1):
////
//// Certificate  ::=  SEQUENCE  {
////      tbsCertificate       TBSCertificate,
////      signatureAlgorithm   AlgorithmIdentifier,
////      signatureValue       BIT STRING  }

//// TBSCertificate  ::=  SEQUENCE  {
////      version         [0]  EXPLICIT Version DEFAULT v1,
////      serialNumber         CertificateSerialNumber,
////      signature            AlgorithmIdentifier,
////      issuer               Name,
////      validity             Validity,
////      subject              Name,
////      subjectPublicKeyInfo SubjectPublicKeyInfo,
////      issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
////                           -- If present, version MUST be v2 or v3
////      subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
////                           -- If present, version MUST be v2 or v3
////      extensions      [3]  EXPLICIT Extensions OPTIONAL
////                           -- If present, version MUST be v3
////      }

//// Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }

//// CertificateSerialNumber  ::=  INTEGER

//// Validity ::= SEQUENCE {
////      notBefore      Time,
////      notAfter       Time }

//// Time ::= CHOICE {
////      utcTime        UTCTime,
////      generalTime    GeneralizedTime }

//// UniqueIdentifier  ::=  BIT STRING

//// SubjectPublicKeyInfo  ::=  SEQUENCE  {
////      algorithm            AlgorithmIdentifier,
////      subjectPublicKey     BIT STRING  }

//// Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension

//// Extension  ::=  SEQUENCE  {
////      extnID      OBJECT IDENTIFIER,
////      critical    BOOLEAN DEFAULT FALSE,
////      extnValue   OCTET STRING
////                  -- contains the DER encoding of an ASN.1 value
////                  -- corresponding to the extension type identified
////                  -- by extnID
////      }

//#[derive(Copy, Clone, Debug, Eq, PartialEq, Message)] // NOTE: added `Message`
//pub struct AlgorithmIdentifier<'a> {
//    /// This field contains an ASN.1 `OBJECT IDENTIFIER`, a.k.a. OID.
//    pub algorithm: ObjectIdentifier,

//    /// This field is `OPTIONAL` and contains the ASN.1 `ANY` type, which
//    /// in this example allows arbitrary algorithm-defined parameters.
//    pub parameters: Option<Any<'a>>
//}

//    This is from docs.rs/x509 (version 0.2.0)

//    pub fn tbs_certificate<'a, W: Write + 'a, Alg, PKI, O: Oid + 'a, N: heapless::ArrayLength<u8> + 'a>(
//        serial_number: &'a [u8],
//        signature: &'a Alg,
//        issuer: &'a [RelativeName<'a>],
//        not_before: &'a str,
//        not_after: Option<&'a str>,
//        subject: &'a [RelativeName<'a>],
//        subject_pki: &'a PKI,
//        exts: &'a [Extension<'a, O>],
//    ) -> impl SerializeFn<W> + 'a
//    where
//        Alg: AlgorithmIdentifier,
//        PKI: SubjectPublicKeyInfo,
//    {
//        assert!(serial_number.len() <= 20);

//        der_sequence::<_, _, N>((
//            version::<_, N>(Version::V3),
//            der_integer::<_, N>(serial_number),
//            algorithm_identifier::<_, _, N>(signature),
//            name::<_, N>(issuer),
//            validity::<_, N>(not_before, not_after),
//            name::<_, N>(subject),
//            subject_public_key_info::<_, _, N>(subject_pki),
//            extensions::<_, _, N>(exts),
//        ))
//    }
