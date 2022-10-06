use crate::api::*;
use crate::error::Error;
use crate::service::*;

// code copied from https://github.com/avacariu/rust-oath

const DIGITS: u32 = 6;
const TOTP_KEY_SIZE: usize = 20;

// https://tools.ietf.org/html/rfc4226#section-5.3

#[inline(never)]
fn hotp_raw(key: &[u8], counter: u64, digits: u32) -> u64 {
    hmac_and_truncate(key, &counter.to_be_bytes(), digits)
}

#[inline(never)]
fn hmac_and_truncate(key: &[u8], message: &[u8], digits: u32) -> u64 {
    use hmac::{Hmac, Mac};
    // let mut hmac = Hmac::<D>::new(GenericArray::from_slice(key));
    let mut hmac = Hmac::<sha1::Sha1>::new_from_slice(key).unwrap();
    hmac.update(message);
    let result = hmac.finalize();

    // output of `.code()` is GenericArray<u8, OutputSize>, again 20B
    // crypto-mac docs warn: "Be very careful using this method,
    // since incorrect use of the code material may permit timing attacks
    // which defeat the security provided by the Mac trait."
    let hs = result.into_bytes();

    dynamic_truncation(&hs) % 10_u64.pow(digits)
}

#[inline]
fn dynamic_truncation(hs: &[u8]) -> u64 {
    // low-order bits of byte 19 (last) of the 20B output
    let offset_bits = (*hs.last().unwrap() & 0xf) as usize;

    let p = u32::from_be_bytes(hs[offset_bits..][..4].try_into().unwrap()) as u64;

    // zero highest bit, avoids signed/unsigned "ambiguity"
    p & 0x7fff_ffff
}

#[cfg(feature = "totp")]
impl Sign for super::Totp {
    #[inline(never)]
    fn sign(keystore: &mut impl Keystore, request: &request::Sign) -> Result<reply::Sign, Error> {
        let key_id = request.key;

        let key = keystore.load_key(key::Secrecy::Secret, None, &key_id)?;

        if !matches!(
            key.kind,
            key::Kind::Symmetric(TOTP_KEY_SIZE) | key::Kind::Shared(TOTP_KEY_SIZE)
        ) {
            return Err(Error::WrongKeyKind);
        }

        let secret = key.material;

        if request.message.len() != 8 {
            return Err(Error::InternalError);
        }
        let timestamp_as_le_bytes = request.message[..].try_into().unwrap();
        let timestamp = u64::from_le_bytes(timestamp_as_le_bytes);
        let totp_material: u64 = hotp_raw(&secret, timestamp, DIGITS);

        // return signature (encode as LE)
        Ok(reply::Sign {
            signature: crate::Bytes::from_slice(totp_material.to_le_bytes().as_ref()).unwrap(),
        })
    }
}

#[cfg(feature = "totp")]
impl Exists for super::Totp {
    #[inline(never)]
    fn exists(
        keystore: &mut impl Keystore,
        request: &request::Exists,
    ) -> Result<reply::Exists, Error> {
        let key_id = request.key;

        let exists = keystore.exists_key(
            key::Secrecy::Secret,
            Some(key::Kind::Symmetric(20)),
            &key_id,
        );
        Ok(reply::Exists { exists })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hotp() {
        assert_eq!(hotp_raw(b"\xff", 23, 6), 330795);

        // test materials from RFC 4226
        assert_eq!(hotp_raw(b"12345678901234567890", 0, 6), 755224);
        assert_eq!(hotp_raw(b"12345678901234567890", 1, 6), 287082);
        assert_ne!(hotp_raw(b"12345678901234567890", 1, 6), 287081);
    }
}
