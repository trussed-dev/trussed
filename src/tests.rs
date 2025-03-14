#![allow(static_mut_refs)]

use chacha20::ChaCha20;
use entropy::shannon_entropy;
use generic_array::GenericArray;
use littlefs2::const_ram_storage;
use littlefs2::fs::{Allocation, Filesystem};
use littlefs2_core::path;
use rand_core::{CryptoRng, RngCore};

#[cfg(any(feature = "p256", feature = "p384", feature = "p521",))]
use crate::types::{Mechanism, SignatureSerialization, StorageAttributes};

use crate::client::{CryptoClient as _, FilesystemClient as _};
use crate::types::{consent, reboot, ui, Bytes, Location, PathBuf};
use crate::{api, block, platform, store, Error};

pub struct MockRng(ChaCha20);

impl MockRng {
    pub fn new() -> Self {
        use chacha20::cipher::KeyIvInit;

        let key = GenericArray::from_slice(b"an example very very secret key.");
        let nonce = GenericArray::from_slice(b"secret nonce");
        Self(ChaCha20::new(key, nonce))
    }
}

impl CryptoRng for MockRng {}

impl RngCore for MockRng {
    fn fill_bytes(&mut self, buf: &mut [u8]) {
        use chacha20::cipher::StreamCipher;
        self.0.apply_keystream(buf);
    }

    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

#[derive(Default)]
pub struct UserInterface {}

impl crate::platform::UserInterface for UserInterface {
    fn check_user_presence(&mut self) -> consent::Level {
        consent::Level::Normal
    }

    fn set_status(&mut self, status: ui::Status) {
        println!("Set status: {:?}", status);
    }

    fn refresh(&mut self) {}

    fn uptime(&mut self) -> core::time::Duration {
        core::time::Duration::from_millis(1000)
    }

    fn reboot(&mut self, to: reboot::To) -> ! {
        println!("Restart!  ({:?})", to);
        std::process::exit(25);
    }

    fn wink(&mut self, _duration: core::time::Duration) {}
}

const_ram_storage!(InternalStorage, 4096 * 10);
const_ram_storage!(ExternalStorage, 4096 * 10);
const_ram_storage!(VolatileStorage, 4096 * 10);

// Using macro to avoid maintaining the type declarations
macro_rules! create_memory {
    () => {{
        let filesystem = InternalStorage::new();
        static mut INTERNAL_STORAGE: Option<InternalStorage> = None;
        unsafe {
            INTERNAL_STORAGE = Some(filesystem);
        }
        static mut INTERNAL_FS_ALLOC: Option<Allocation<InternalStorage>> = None;
        unsafe {
            INTERNAL_FS_ALLOC = Some(Filesystem::allocate());
        }

        static mut EXTERNAL_STORAGE: ExternalStorage = ExternalStorage::new();
        static mut EXTERNAL_FS_ALLOC: Option<Allocation<ExternalStorage>> = None;
        unsafe {
            EXTERNAL_FS_ALLOC = Some(Filesystem::allocate());
        }

        static mut VOLATILE_STORAGE: VolatileStorage = VolatileStorage::new();
        static mut VOLATILE_FS_ALLOC: Option<Allocation<VolatileStorage>> = None;
        unsafe {
            VOLATILE_FS_ALLOC = Some(Filesystem::allocate());
        }

        (
            unsafe { INTERNAL_FS_ALLOC.as_mut().unwrap() },
            unsafe { INTERNAL_STORAGE.as_mut().unwrap() },
            unsafe { EXTERNAL_FS_ALLOC.as_mut().unwrap() },
            unsafe { &mut EXTERNAL_STORAGE },
            unsafe { VOLATILE_FS_ALLOC.as_mut().unwrap() },
            unsafe { &mut VOLATILE_STORAGE },
        )
    }};
}

type Memory = (
    &'static mut littlefs2::fs::Allocation<InternalStorage>,
    &'static mut InternalStorage,
    &'static mut littlefs2::fs::Allocation<ExternalStorage>,
    &'static mut ExternalStorage,
    &'static mut littlefs2::fs::Allocation<VolatileStorage>,
    &'static mut VolatileStorage,
);

struct ServiceSyscall<'a, P: platform::Platform> {
    service: crate::Service<P>,
    ep: crate::pipe::ServiceEndpoint<'a, crate::backend::NoId, crate::types::NoData>,
}

impl<P: platform::Platform> platform::Syscall for ServiceSyscall<'_, P> {
    fn syscall(&mut self) {
        self.service.process(core::slice::from_mut(&mut self.ep));
    }
}

/// Create a "copy" of a store
unsafe fn copy_memory(memory: &Memory) -> Memory {
    unsafe {
        (
            &mut *(memory.0 as *const _ as *mut _),
            &mut *(memory.1 as *const _ as *mut _),
            &mut *(memory.2 as *const _ as *mut _),
            &mut *(memory.3 as *const _ as *mut _),
            &mut *(memory.4 as *const _ as *mut _),
            &mut *(memory.5 as *const _ as *mut _),
        )
    }
}

// TODO: what's going on here? Duplicates code in `tests/client/mod.rs`.
// Might make sense as a trussed::fixture submodule activated via feature flag.
macro_rules! setup {
    ($client:ident) => {
        let memory = create_memory!();
        setup!($client, Store, Platform, memory, [0u8; 32], true);
    };
    ($client:ident, $store:ident, $platform: ident, $memory:expr, $seed:expr, $reformat: expr) => {
        #[derive(Copy, Clone)]
        pub struct $store {
            ifs: &'static dyn littlefs2_core::DynFilesystem,
            efs: &'static dyn littlefs2_core::DynFilesystem,
            vfs: &'static dyn littlefs2_core::DynFilesystem,
            __: core::marker::PhantomData<*mut ()>,
        }

        impl $store {
            pub fn claim(memory: Memory, format: bool) -> Option<Self> {
                use core::mem::MaybeUninit;
                use core::sync::atomic::{AtomicBool, Ordering};
                use littlefs2::fs::Filesystem;

                static CLAIMED: AtomicBool = AtomicBool::new(false);
                static mut IFS: MaybeUninit<Filesystem<'static, InternalStorage>> =
                    MaybeUninit::uninit();
                static mut EFS: MaybeUninit<Filesystem<'static, ExternalStorage>> =
                    MaybeUninit::uninit();
                static mut VFS: MaybeUninit<Filesystem<'static, VolatileStorage>> =
                    MaybeUninit::uninit();

                if CLAIMED
                    .compare_exchange_weak(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {

                    let (ifs_alloc, ifs_storage, efs_alloc, efs_storage, vfs_alloc, vfs_storage) = memory;

                    // always need to format RAM
                    Filesystem::format(vfs_storage).expect("can format");
                    // this is currently a RAM fs too...
                    Filesystem::format(efs_storage).expect("can format");

                    if format {
                        Filesystem::format(ifs_storage).expect("can format");
                    }

                    let ifs = Filesystem::mount(ifs_alloc, ifs_storage).expect("failed to mount IFS");
                    let efs = Filesystem::mount(efs_alloc, efs_storage).expect("failed to mount EFS");
                    let vfs = Filesystem::mount(vfs_alloc, vfs_storage).expect("failed to mount VFS");

                    let (ifs, efs, vfs) = unsafe {
                        (IFS.write(ifs), EFS.write(efs), VFS.write(vfs))
                    };

                    Some(Self {
                        ifs,
                        efs,
                        vfs,
                        __: Default::default(),
                    })
                } else {
                    None
                }
            }
        }

        impl store::Store for $store {
            fn ifs(&self) -> &dyn littlefs2_core::DynFilesystem {
                self.ifs
            }

            fn efs(&self) -> &dyn littlefs2_core::DynFilesystem {
                self.efs
            }

            fn vfs(&self) -> &dyn littlefs2_core::DynFilesystem {
                self.vfs
            }
        }

        platform!($platform, R: MockRng, S: $store, UI: UserInterface,);

        let store = $store::claim($memory, $reformat).unwrap();
        let rng = MockRng::new();
        let pc_interface: UserInterface = Default::default();

        let platform = $platform::new(rng, store, pc_interface);
        let mut trussed: crate::Service<$platform> = crate::service::Service::new(platform);

        let channel = crate::pipe::TrussedChannel::new();
        let (test_trussed_requester, test_trussed_responder) = channel
            .split()
            .expect("could not setup TEST TrussedInterchange");
        let test_client_id = path!("TEST");
        let context = crate::types::CoreContext::new(test_client_id.into());
        let ep = crate::pipe::ServiceEndpoint::new(test_trussed_responder, context, &[]);

        trussed.set_seed_if_uninitialized(&$seed);
        let syscall = ServiceSyscall {
            service: trussed,
            ep,
        };
        let mut $client = crate::ClientImplementation::<_>::new(test_trussed_requester, syscall, None);
    };
}

#[test]
#[serial]
fn dummy() {
    setup!(_client);
}

#[cfg(feature = "ed255")]
#[test]
#[serial]
fn sign_ed255() {
    // let mut client = setup!();
    setup!(client);

    use crate::client::mechanisms::{Ed255, P256};
    let future = client
        .generate_ed255_private_key(Location::Internal)
        .expect("no client error");
    println!("submitted gen ed255");
    let reply = block!(future);
    let private_key = reply.expect("no errors, never").key;
    println!("got a private key {:?}", &private_key);

    let public_key = block!(client
        .derive_ed255_public_key(private_key, Location::Volatile)
        .expect("no client error"))
    .expect("no issues")
    .key;
    println!("got a public key {:?}", &public_key);

    assert!(block!(client
        .derive_ed255_public_key(private_key, Location::Volatile)
        .expect("no client error wot"))
    .is_ok());
    assert!(block!(client
        .derive_p256_public_key(private_key, Location::Volatile)
        .expect("no client error wot"))
    .is_err());

    let message = [1u8, 2u8, 3u8];
    let future = client
        .sign_ed255(private_key, &message)
        .expect("no client error post err");
    let reply: Result<api::reply::Sign, _> = block!(future);
    let signature = reply.expect("good signature").signature;
    println!("got a signature: {:?}", &signature);

    let future = client
        .verify_ed255(public_key, &message, &signature)
        .expect("no client error");
    let reply = block!(future);
    let valid = reply.expect("good signature").valid;
    assert!(valid);

    let future = client
        .verify_ed255(public_key, &message, &[1u8, 2, 3])
        .expect("no client error");
    let reply = block!(future);
    assert_eq!(Err(Error::WrongSignatureLength), reply);
}

#[cfg(feature = "p256")]
#[test]
#[serial]
fn sign_p256() {
    use crate::client::mechanisms::P256 as _;
    // let mut client = setup!();
    setup!(client);
    let private_key = block!(client
        .generate_p256_private_key(Location::External)
        .expect("no client error"))
    .expect("no errors")
    .key;
    println!("got a public key {:?}", &private_key);
    let public_key = block!(client
        .derive_p256_public_key(private_key, Location::Volatile)
        .expect("no client error"))
    .expect("no errors")
    .key;
    println!("got a public key {:?}", &public_key);

    let message = [1u8, 2u8, 3u8];
    let signature = block!(client
        .sign_p256(private_key, &message, SignatureSerialization::Raw)
        .expect("no client error"))
    .expect("good signature")
    .signature;

    // use core::convert::AsMut;
    // let sig = signature.0.as_mut()[0] = 0;
    let future = client.verify_p256(public_key, &message, &signature);
    let future = future.expect("no client error");
    let result = block!(future);
    if result.is_err() {
        println!("error: {:?}", result);
    }
    let reply = result.expect("valid signature");
    let valid = reply.valid;
    assert!(valid);
}

#[cfg(feature = "p256")]
#[test]
#[serial]
fn agree_p256() {
    // let mut client = setup!();
    use crate::client::mechanisms::P256;
    setup!(client);
    let plat_private_key = block!(client
        .generate_p256_private_key(Location::Volatile)
        .expect("no client error"))
    .expect("no errors")
    .key;
    println!("got a public key {:?}", &plat_private_key);
    let plat_public_key = block!(client
        .derive_p256_public_key(plat_private_key, Location::Volatile)
        .expect("no client error"))
    .expect("no errors")
    .key;
    println!("got a public key {:?}", &plat_public_key);

    let auth_private_key = block!(client
        .generate_p256_private_key(Location::Volatile)
        .expect("no client error"))
    .expect("no errors")
    .key;
    println!("got a public key {:?}", &auth_private_key);
    let auth_public_key = block!(client
        .derive_p256_public_key(auth_private_key, Location::Volatile)
        .expect("no client error"))
    .expect("no errors")
    .key;
    println!("got a public key {:?}", &auth_public_key);

    let shared_secret = block!(client
        .agree(
            Mechanism::P256,
            auth_private_key,
            plat_public_key,
            StorageAttributes::new().set_persistence(Location::Volatile)
        )
        .expect("no client error"))
    .expect("no errors")
    .shared_secret;

    let alt_shared_secret = block!(client
        .agree(
            Mechanism::P256,
            plat_private_key,
            auth_public_key,
            StorageAttributes::new().set_persistence(Location::Volatile)
        )
        .expect("no client error"))
    .expect("no errors")
    .shared_secret;

    // NB: we have no idea about the value of keys, these are just *different* handles
    assert_ne!(&shared_secret, &alt_shared_secret);

    let symmetric_key = block!(client
        .derive_key(
            Mechanism::Sha256,
            shared_secret,
            None,
            StorageAttributes::new().set_persistence(Location::Volatile)
        )
        .expect("no client error"))
    .expect("no errors")
    .key;

    let new_pin_enc = [1u8, 2, 3];

    let _tag = block!(client
        .sign(
            Mechanism::HmacSha256,
            symmetric_key,
            &new_pin_enc,
            SignatureSerialization::Raw
        )
        .expect("no client error"))
    .expect("no errors")
    .signature;
}

#[cfg(feature = "p384")]
#[test]
#[serial]
fn sign_p384() {
    use crate::client::mechanisms::P384 as _;
    // let mut client = setup!();
    setup!(client);
    let private_key = block!(client
        .generate_p384_private_key(Location::External)
        .expect("no client error"))
    .expect("no errors")
    .key;
    println!("got a public key {:?}", &private_key);
    let public_key = block!(client
        .derive_p384_public_key(private_key, Location::Volatile)
        .expect("no client error"))
    .expect("no errors")
    .key;
    println!("got a public key {:?}", &public_key);

    let message = [1u8, 2u8, 3u8];
    let signature = block!(client
        .sign_p384(private_key, &message, SignatureSerialization::Raw)
        .expect("no client error"))
    .expect("good signature")
    .signature;

    // use core::convert::AsMut;
    // let sig = signature.0.as_mut()[0] = 0;
    let future = client.verify_p384(public_key, &message, &signature);
    let future = future.expect("no client error");
    let result = block!(future);
    if result.is_err() {
        println!("error: {:?}", result);
    }
    let reply = result.expect("valid signature");
    let valid = reply.valid;
    assert!(valid);
}

#[cfg(feature = "p384")]
#[test]
#[serial]
fn agree_p384() {
    // let mut client = setup!();
    use crate::client::mechanisms::P384;
    setup!(client);
    let plat_private_key = block!(client
        .generate_p384_private_key(Location::Volatile)
        .expect("no client error"))
    .expect("no errors")
    .key;
    println!("got a public key {:?}", &plat_private_key);
    let plat_public_key = block!(client
        .derive_p384_public_key(plat_private_key, Location::Volatile)
        .expect("no client error"))
    .expect("no errors")
    .key;
    println!("got a public key {:?}", &plat_public_key);

    let auth_private_key = block!(client
        .generate_p384_private_key(Location::Volatile)
        .expect("no client error"))
    .expect("no errors")
    .key;
    println!("got a public key {:?}", &auth_private_key);
    let auth_public_key = block!(client
        .derive_p384_public_key(auth_private_key, Location::Volatile)
        .expect("no client error"))
    .expect("no errors")
    .key;
    println!("got a public key {:?}", &auth_public_key);

    let shared_secret = block!(client
        .agree(
            Mechanism::P384,
            auth_private_key,
            plat_public_key,
            StorageAttributes::new().set_persistence(Location::Volatile)
        )
        .expect("no client error"))
    .expect("no errors")
    .shared_secret;

    let alt_shared_secret = block!(client
        .agree(
            Mechanism::P384,
            plat_private_key,
            auth_public_key,
            StorageAttributes::new().set_persistence(Location::Volatile)
        )
        .expect("no client error"))
    .expect("no errors")
    .shared_secret;

    // NB: we have no idea about the value of keys, these are just *different* handles
    assert_ne!(&shared_secret, &alt_shared_secret);

    let symmetric_key = block!(client
        .derive_key(
            Mechanism::Sha256,
            shared_secret,
            None,
            StorageAttributes::new().set_persistence(Location::Volatile)
        )
        .expect("no client error"))
    .expect("no errors")
    .key;

    let new_pin_enc = [1u8, 2, 3];

    let _tag = block!(client
        .sign(
            Mechanism::HmacSha256,
            symmetric_key,
            &new_pin_enc,
            SignatureSerialization::Raw
        )
        .expect("no client error"))
    .expect("no errors")
    .signature;
}

#[cfg(feature = "p521")]
#[test]
#[serial]
fn sign_p521() {
    use crate::client::mechanisms::P521 as _;
    // let mut client = setup!();
    setup!(client);
    let private_key = block!(client
        .generate_p521_private_key(Location::External)
        .expect("no client error"))
    .expect("no errors")
    .key;
    println!("got a public key {:?}", &private_key);
    let public_key = block!(client
        .derive_p521_public_key(private_key, Location::Volatile)
        .expect("no client error"))
    .expect("no errors")
    .key;
    println!("got a public key {:?}", &public_key);

    let message = [1u8, 2u8, 3u8];
    let signature = block!(client
        .sign_p521(private_key, &message, SignatureSerialization::Raw)
        .expect("no client error"))
    .expect("good signature")
    .signature;

    // use core::convert::AsMut;
    // let sig = signature.0.as_mut()[0] = 0;
    let future = client.verify_p521(public_key, &message, &signature);
    let future = future.expect("no client error");
    let result = block!(future);
    if result.is_err() {
        println!("error: {:?}", result);
    }
    let reply = result.expect("valid signature");
    let valid = reply.valid;
    assert!(valid);
}

#[cfg(feature = "p521")]
#[test]
#[serial]
fn agree_p521() {
    // let mut client = setup!();
    use crate::client::mechanisms::P521;
    setup!(client);
    let plat_private_key = block!(client
        .generate_p521_private_key(Location::Volatile)
        .expect("no client error"))
    .expect("no errors")
    .key;
    println!("got a public key {:?}", &plat_private_key);
    let plat_public_key = block!(client
        .derive_p521_public_key(plat_private_key, Location::Volatile)
        .expect("no client error"))
    .expect("no errors")
    .key;
    println!("got a public key {:?}", &plat_public_key);

    let auth_private_key = block!(client
        .generate_p521_private_key(Location::Volatile)
        .expect("no client error"))
    .expect("no errors")
    .key;
    println!("got a public key {:?}", &auth_private_key);
    let auth_public_key = block!(client
        .derive_p521_public_key(auth_private_key, Location::Volatile)
        .expect("no client error"))
    .expect("no errors")
    .key;
    println!("got a public key {:?}", &auth_public_key);

    let shared_secret = block!(client
        .agree(
            Mechanism::P521,
            auth_private_key,
            plat_public_key,
            StorageAttributes::new().set_persistence(Location::Volatile)
        )
        .expect("no client error"))
    .expect("no errors")
    .shared_secret;

    let alt_shared_secret = block!(client
        .agree(
            Mechanism::P521,
            plat_private_key,
            auth_public_key,
            StorageAttributes::new().set_persistence(Location::Volatile)
        )
        .expect("no client error"))
    .expect("no errors")
    .shared_secret;

    // NB: we have no idea about the value of keys, these are just *different* handles
    assert_ne!(&shared_secret, &alt_shared_secret);

    let symmetric_key = block!(client
        .derive_key(
            Mechanism::Sha256,
            shared_secret,
            None,
            StorageAttributes::new().set_persistence(Location::Volatile)
        )
        .expect("no client error"))
    .expect("no errors")
    .key;

    let new_pin_enc = [1u8, 2, 3];

    let _tag = block!(client
        .sign(
            Mechanism::HmacSha256,
            symmetric_key,
            &new_pin_enc,
            SignatureSerialization::Raw
        )
        .expect("no client error"))
    .expect("no errors")
    .signature;
}

#[cfg(feature = "chacha8-poly1305")]
#[test]
#[serial]
fn aead_rng_nonce() {
    use crate::client::mechanisms::Chacha8Poly1305;
    setup!(client);
    let secret_key = block!(client
        .generate_secret_key(32, Location::Volatile)
        .expect("no client error"))
    .expect("no errors")
    .key;

    println!("got a key {:?}", &secret_key);

    let message = b"test message";
    let associated_data = b"solokeys.com";
    let api::reply::Encrypt {
        ciphertext,
        nonce,
        tag,
    } = block!(client
        .encrypt_chacha8poly1305(secret_key, message, associated_data, None)
        .expect("no client error"))
    .expect("no errors");

    let plaintext = block!(client
        .decrypt_chacha8poly1305(secret_key, &ciphertext, associated_data, &nonce, &tag,)
        .map_err(drop)
        .expect("no client error"))
    .map_err(drop)
    .expect("no errors")
    .plaintext;

    assert_ne!(&nonce, &[0; 12]);
    assert_eq!(&message[..], plaintext.unwrap().as_ref());
}

#[cfg(feature = "chacha8-poly1305")]
#[test]
#[serial]
fn aead_given_nonce() {
    use crate::client::mechanisms::Chacha8Poly1305;
    setup!(client);
    let secret_key = block!(client
        .generate_secret_key(32, Location::Volatile)
        .expect("no client error"))
    .expect("no errors")
    .key;

    println!("got a key {:?}", &secret_key);

    let message = b"test message";
    let associated_data = b"solokeys.com";
    let static_nonce = b"123456789012";
    let api::reply::Encrypt {
        ciphertext,
        nonce,
        tag,
    } = block!(client
        .encrypt_chacha8poly1305(secret_key, message, associated_data, Some(static_nonce))
        .expect("no client error"))
    .expect("no errors");
    assert_eq!(&*nonce, static_nonce);

    let plaintext = block!(client
        .decrypt_chacha8poly1305(secret_key, &ciphertext, associated_data, &nonce, &tag,)
        .map_err(drop)
        .expect("no client error"))
    .map_err(drop)
    .expect("no errors")
    .plaintext;

    assert_eq!(&message[..], plaintext.unwrap().as_ref());
}

// Same as before but key generated with a nonce
#[cfg(feature = "chacha8-poly1305")]
#[test]
#[serial]
fn aead_given_nonce_2() {
    use crate::client::mechanisms::Chacha8Poly1305;
    setup!(client);
    let secret_key = block!(client
        .generate_chacha8poly1305_key(Location::Volatile)
        .expect("no client error"))
    .expect("no errors")
    .key;

    println!("got a key {:?}", &secret_key);

    let message = b"test message";
    let associated_data = b"solokeys.com";
    let static_nonce = b"123456789012";
    let api::reply::Encrypt {
        ciphertext,
        nonce,
        tag,
    } = block!(client
        .encrypt_chacha8poly1305(secret_key, message, associated_data, Some(static_nonce))
        .expect("no client error"))
    .expect("no errors");
    assert_eq!(&*nonce, static_nonce);

    let plaintext = block!(client
        .decrypt_chacha8poly1305(secret_key, &ciphertext, associated_data, &nonce, &tag,)
        .map_err(drop)
        .expect("no client error"))
    .map_err(drop)
    .expect("no errors")
    .plaintext;

    assert_eq!(&message[..], plaintext.unwrap().as_ref());
}

#[cfg(feature = "chacha8-poly1305")]
#[test]
#[serial]
fn aead() {
    use crate::client::mechanisms::Chacha8Poly1305;
    setup!(client);
    let secret_key = block!(client
        .generate_chacha8poly1305_key(Location::Volatile)
        .expect("no client error"))
    .expect("no errors")
    .key;

    println!("got a key {:?}", &secret_key);

    let message = b"test message";
    let associated_data = b"solokeys.com";
    let api::reply::Encrypt {
        ciphertext,
        nonce,
        tag,
    } = block!(client
        .encrypt_chacha8poly1305(secret_key, message, associated_data, None)
        .expect("no client error"))
    .expect("no errors");

    let plaintext = block!(client
        .decrypt_chacha8poly1305(secret_key, &ciphertext, associated_data, &nonce, &tag,)
        .map_err(drop)
        .expect("no client error"))
    .map_err(drop)
    .expect("no errors")
    .plaintext;

    assert_eq!(&message[..], plaintext.unwrap().as_ref());
}

#[test]
#[serial]
fn rng() {
    macro_rules! gen_bytes {
        ($client:expr, $size: expr) => {{
            assert!(($size % 128) == 0);
            let mut rng_bytes = [0u8; $size];
            for x in (0..$size).step_by(128) {
                let rng_chunk = block!($client.random_bytes(128).expect("no client error"))
                    .expect("no errors")
                    .bytes;
                rng_bytes[x..x + 128].clone_from_slice(&rng_chunk);
            }
            rng_bytes
        }};
    }

    setup!(client1);
    let bytes = gen_bytes!(client1, 1024 * 100);
    let entropy = shannon_entropy(bytes);
    println!("got entropy of {} bytes: {}", bytes.len(), entropy);
    assert!(entropy > 7.99);

    // Since RNG is deterministic for these tests, we expect two clients with same seed
    // to have the same output.
    let mem1 = create_memory!();
    let mem2 = create_memory!();
    let mem3 = create_memory!();
    setup!(
        client_twin1,
        StoreTwin1,
        PlatformTwin1,
        mem1,
        [0x01u8; 32],
        true
    );
    setup!(
        client_twin2,
        StoreTwin2,
        PlatformTwin2,
        mem2,
        [0x01u8; 32],
        true
    );
    setup!(
        client_3,
        StoreTwin3,
        PlatformTwin3,
        mem3,
        [0x02u8; 32],
        true
    );
    let bytes_twin1 = gen_bytes!(client_twin1, 1024 * 100);
    let bytes_twin2 = gen_bytes!(client_twin2, 1024 * 100);
    let bytes_3 = gen_bytes!(client_3, 1024 * 100);

    for i in 0..bytes_twin2.len() {
        assert!(bytes_twin1[i] == bytes_twin2[i]);
    }
    for i in 0..bytes_twin2.len() {
        // bytes_3 was from different seed.
        if bytes_3[i] != bytes_twin2[i] {
            break;
        }
        assert!(i <= 200, "Changing seed did not change rng");
    }

    let mem = create_memory!();
    let mem_copy = unsafe { copy_memory(&mem) };

    // Trussed saves the RNG state so it cannot produce the same RNG on different boots.
    setup!(
        client_twin3,
        StoreTwin4,
        PlatformTwin4,
        mem,
        [0x01u8; 32],
        true
    );

    let first_128 = gen_bytes!(client_twin3, 128);

    // This time don't reformat the memory -- should pick up on last rng state.
    setup!(
        client_twin4,
        StoreTwin5,
        PlatformTwin5,
        mem_copy,
        [0x01u8; 32],
        false
    );

    let second_128 = gen_bytes!(client_twin4, 128);

    let mut mismatch_count = 0;
    for i in 0..128 {
        assert!(first_128[i] == bytes_twin2[i]);
        if first_128[i] != second_128[i] {
            mismatch_count += 1;
        }
    }
    assert!(mismatch_count > 100);
}

#[test]
#[serial]
fn filesystem() {
    let path = PathBuf::from(path!("test_file"));
    setup!(client);

    assert!(block!(client
        .entry_metadata(Location::Internal, path.clone())
        .expect("no client error"))
    .expect("no errors")
    .metadata
    .is_none(),);

    let data = Bytes::from_slice(&[0; 20]).unwrap();
    block!(client
        .write_file(Location::Internal, path.clone(), data.clone(), None,)
        .expect("no client error"))
    .expect("no errors");

    let recv_data = block!(client
        .read_file(Location::Internal, path.clone())
        .expect("no client error"))
    .expect("no errors")
    .data;
    assert_eq!(data, recv_data);

    let metadata = block!(client
        .entry_metadata(Location::Internal, path.clone())
        .expect("no client error"))
    .expect("no errors")
    .metadata
    .unwrap();
    assert!(metadata.is_file());

    // This returns an error because the name doesn't exist
    block!(client
        .remove_file(Location::Internal, path!("bad_name").into())
        .expect("no client error"))
    .ok();
    let metadata = block!(client
        .entry_metadata(Location::Internal, path.clone())
        .expect("no client error"))
    .expect("no errors")
    .metadata
    .unwrap();
    assert!(metadata.is_file());

    block!(client
        .remove_file(Location::Internal, path.clone())
        .expect("no client error"))
    .expect("no errors");
    assert!(block!(client
        .entry_metadata(Location::Internal, path.clone())
        .expect("no client error"))
    .expect("no errors")
    .metadata
    .is_none(),);
}
