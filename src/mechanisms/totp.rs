use core::convert::TryInto;

use cortex_m_semihosting::hprintln;

use crate::api::*;
use crate::error::Error;
use crate::service::*;
use crate::store::Store;
use crate::types::*;

// code copied from https://github.com/avacariu/rust-oath

const DIGITS: u32 = 6;

// https://tools.ietf.org/html/rfc4226#section-5.3

fn hotp_raw(key: &[u8], counter: u64, digits: u32) -> u64 {
    hmac_and_truncate(key, &counter.to_be_bytes(), digits)
}

fn hmac_and_truncate(key: &[u8], message: &[u8], digits: u32) -> u64 {
    use hmac::{Hmac, Mac};
    // let mut hmac = Hmac::<D>::new(GenericArray::from_slice(key));
    hprintln!("1").ok();
    let mut hmac = Hmac::<sha1::Sha1>::new_varkey(key).unwrap();
    hprintln!("2").ok();
    hmac.input(message);
    hprintln!("3").ok();
    let result = hmac.result();
    hprintln!("4").ok();

    // output of `.code()` is GenericArray<u8, OutputSize>, again 20B
    // crypto-mac docs warn: "Be very careful using this method, 
    // since incorrect use of the code value may permit timing attacks 
    // which defeat the security provided by the Mac trait."
    let hs = result.code();
    hprintln!("5").ok();

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
impl<R: RngRead, S: Store>
UnsafeInjectKey<R, S> for super::Totp
{
    fn unsafe_inject_key(resources: &mut ServiceResources<R, S>, request: request::UnsafeInjectKey)
        -> Result<reply::UnsafeInjectKey, Error>
    {
        // in usual format, secret is a 32B Base32 encoding of 20B actual secret bytes
        hprintln!("a").ok();
        if request.raw_key.len() != 20 {
            hprintln!("{}B: {:X?}", request.raw_key.len(), &request.raw_key).ok();
            return Err(Error::WrongMessageLength);
        }

        hprintln!("b").ok();
        // store it
        let key_id = resources.store_key(
            request.attributes.persistence,
            KeyType::Secret,
            KeyKind::Symmetric20,
            &request.raw_key,
        )?;

        Ok(reply::UnsafeInjectKey { key: ObjectHandle { object_id: key_id } })
    }
}

#[cfg(feature = "totp")]
impl<R: RngRead, S: Store>
Sign<R, S> for super::Totp
{
    fn sign(resources: &mut ServiceResources<R, S>, request: request::Sign)
        -> Result<reply::Sign, Error>
    {
        let key_id = request.key.object_id;

        let secret: [u8; 20] = resources
            .load_key(KeyType::Secret, None, &key_id)?
            .value.as_slice().try_into()
            .map_err(|_| Error::InternalError)?;

        if request.message.len() != 8 {
            return Err(Error::InternalError);
        }
        let timestamp_as_le_bytes = request.message[..].try_into().unwrap();
        let timestamp = u64::from_le_bytes(timestamp_as_le_bytes);
        let totp_value: u64 = hotp_raw(&secret, timestamp, DIGITS);

        // return signature (encode as LE)
        Ok(reply::Sign { signature: totp_value.to_le_bytes().as_ref().try_into().unwrap() })
    }
}

#[cfg(feature = "totp")]
impl<R: RngRead, S: Store>
Exists<R, S> for super::Totp
{
    fn exists(resources: &mut ServiceResources<R, S>, request: request::Exists)
        -> Result<reply::Exists, Error>
    {
        let key_id = request.key.object_id;

        let exists = resources.exists_key(KeyType::Secret, Some(KeyKind::Symmetric20), &key_id);
        Ok(reply::Exists { exists })
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hotp() {
        assert_eq!(hotp_raw(b"\xff", 23, 6), 330795);

        // test values from RFC 4226
        assert_eq!(hotp_raw(b"12345678901234567890", 0, 6), 755224);
        assert_eq!(hotp_raw(b"12345678901234567890", 1, 6), 287082);
        assert_ne!(hotp_raw(b"12345678901234567890", 1, 6), 287081);
    }
}
