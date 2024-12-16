//! This (incomplete!) API loosely follows [PKCS#11 v3][pkcs11-v3].
//!
//! For constants see [their headers][pkcs11-headers].
//!
//! [pkcs11-v3]: https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html
//! [pkcs11-headers]: https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/cs01/include/pkcs11-v3.0/

#[cfg(any(feature = "management-client", feature = "ui-client"))]
use core::time::Duration;

#[cfg(feature = "ui-client")]
use crate::types::consent;
#[cfg(feature = "management-client")]
use crate::types::reboot;
#[cfg(feature = "serde-extensions")]
use crate::types::Bytes;
#[cfg(any(feature = "certificate-client", feature = "crypto-client-attest"))]
use crate::types::CertId;
#[cfg(feature = "counter-client")]
use crate::types::CounterId;
#[cfg(any(
    feature = "certificate-client",
    feature = "counter-client",
    feature = "crypto-client",
    feature = "filesystem-client"
))]
use crate::types::Location;
#[cfg(any(
    feature = "certificate-client",
    feature = "crypto-client",
    feature = "filesystem-client"
))]
use crate::types::Message;
use crate::types::PathBuf;
#[cfg(feature = "filesystem-client")]
use crate::types::{DirEntry, UserAttribute};
#[cfg(feature = "crypto-client")]
use crate::types::{
    KeyId, KeySerialization, Mechanism, MediumData, SerializedKey, ShortData, Signature,
    SignatureSerialization, StorageAttributes,
};

#[macro_use]
mod macros;

// TODO: Ideally, we would not need to assign random numbers here
// The only use for them is to check that the reply type corresponds
// to the request type in the client.
//
// At minimum, we don't want to list the indices (may need proc-macro)

#[derive(Clone, Eq, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub enum NotBefore {
    /// Start iteration at the beginning of the directory
    None,
    /// Start iteration at an exact match with the provided filename
    Filename(PathBuf),
    /// Start iteration at the first path that is "after" the provided filename
    FilenamePart(PathBuf),
}

impl NotBefore {
    pub fn with_filename(value: Option<PathBuf>) -> Self {
        match value {
            None => Self::None,
            Some(p) => Self::Filename(p),
        }
    }

    pub fn with_filename_part(value: Option<PathBuf>) -> Self {
        match value {
            None => Self::None,
            Some(p) => Self::FilenamePart(p),
        }
    }
}

generate_enums! {

    ////////////
    // Crypto //
    ////////////

    #[cfg(feature = "crypto-client")]
    Agree: 1
    // CreateObject: 2
    // TODO: why do Decrypt and DeriveKey both have discriminant 3?!
    #[cfg(feature = "crypto-client")]
    Decrypt: 3
    #[cfg(feature = "crypto-client")]
    DeriveKey: 4
    #[cfg(feature = "crypto-client")]
    DeserializeKey: 5
    #[cfg(feature = "crypto-client")]
    Encrypt: 6
    #[cfg(feature = "crypto-client")]
    Delete: 7
    // Clear private data from the key
    // This will not always delete all metadata from storage.
    // Other backends can retain metadata required for `unwrap_key` to work properly
    // and delete this metadata only once `delete` is called.
    #[cfg(feature = "crypto-client")]
    Clear: 63
    #[cfg(feature = "crypto-client")]
    DeleteAllKeys: 25
    #[cfg(feature = "crypto-client")]
    Exists: 8
    // DeriveKeypair: 3
    // FindObjects: 9
    #[cfg(feature = "crypto-client")]
    GenerateKey: 10
    #[cfg(feature = "crypto-client")]
    GenerateSecretKey: 11
    // GenerateKeypair: 6
    #[cfg(feature = "crypto-client")]
    Hash: 12
    // TODO: add ReadDir{First,Next}, not loading data, if needed for efficiency
    #[cfg(feature = "filesystem-client")]
    ReadDirFilesFirst: 13
    #[cfg(feature = "filesystem-client")]
    ReadDirFilesNext: 14
    #[cfg(feature = "filesystem-client")]
    ReadFile: 15
    #[cfg(feature = "filesystem-client")]
    Metadata: 26
    #[cfg(feature = "filesystem-client")]
    Rename: 27
    // ReadCounter: 7
    #[cfg(feature = "crypto-client")]
    RandomBytes: 16
    #[cfg(feature = "crypto-client")]
    SerializeKey: 17
    #[cfg(feature = "crypto-client")]
    Sign: 18
    #[cfg(feature = "filesystem-client")]
    WriteFile: 19
    #[cfg(feature = "crypto-client")]
    UnsafeInjectKey: 20
    #[cfg(feature = "crypto-client")]
    UnsafeInjectSharedKey: 21
    #[cfg(feature = "crypto-client")]
    UnwrapKey: 22
    #[cfg(feature = "crypto-client")]
    Verify: 23
    #[cfg(feature = "crypto-client")]
    WrapKey: 24

    #[cfg(feature = "crypto-client-attest")]
    Attest: 0xFF

    /////////////
    // Storage //
    /////////////

    // // CreateDir,    <-- implied by WriteFile
    #[cfg(feature = "filesystem-client")]
    ReadDirFirst: 31 //      <-- gets Option<FileType> to restrict to just dir/file DirEntries,
    #[cfg(feature = "filesystem-client")]
    ReadDirNext: 32 //      <-- gets Option<FileType> to restrict to just dir/file DirEntries,
    //                   // returns simplified Metadata
    // // ReadDirFilesFirst: 23 // <-- returns contents
    // // ReadDirFilesNext: 24 // <-- returns contents
    // ReadFile: 25
    #[cfg(feature = "filesystem-client")]
    RemoveFile: 33
    #[cfg(feature = "filesystem-client")]
    RemoveDir: 36
    #[cfg(feature = "filesystem-client")]
    RemoveDirAll: 34
    // WriteFile: 29
    #[cfg(feature = "filesystem-client")]
    LocateFile: 35

    ////////
    // UI //
    ////////

    #[cfg(feature = "ui-client")]
    RequestUserConsent: 41
    #[cfg(feature = "management-client")]
    Reboot: 42
    #[cfg(feature = "management-client")]
    Uptime: 43
    #[cfg(feature = "ui-client")]
    Wink: 44
    #[cfg(feature = "ui-client")]
    SetCustomStatus: 45

    //////////////
    // Counters //
    //////////////

    #[cfg(feature = "counter-client")]
    CreateCounter: 50
    #[cfg(feature = "counter-client")]
    IncrementCounter: 51

    //////////////////
    // Certificates //
    //////////////////

    #[cfg(feature = "certificate-client")]
    DeleteCertificate: 60
    #[cfg(feature = "certificate-client")]
    ReadCertificate: 61
    #[cfg(feature = "certificate-client")]
    WriteCertificate: 62

    ///////////
    // Other //
    ///////////
    #[cfg(feature = "filesystem-client")]
    DebugDumpStore: 0x79

    #[cfg(feature = "serde-extensions")]
    SerdeExtension: 0x5E
}

pub trait RequestVariant: Into<Request> + TryFrom<Request, Error = crate::error::Error> {
    type Reply: ReplyVariant<Request = Self>;
}

pub trait ReplyVariant: Into<Reply> + TryFrom<Reply, Error = crate::error::Error> {
    type Request: RequestVariant<Reply = Self>;
}

pub mod request {
    #[allow(unused_imports)]
    use super::*;

    impl_request! {
        #[cfg(feature = "crypto-client")]
        Agree:
            - mechanism: Mechanism
            - private_key: KeyId
            - public_key: KeyId
            - attributes: StorageAttributes

        #[cfg(feature = "crypto-client-attest")]
        Attest:
            // only Ed255 + P256
            - signing_mechanism: Mechanism
            // only Ed255 + P256
            - private_key: KeyId

        // // examples:
        // // - store public keys from external source
        // // - store certificates
        // CreateObject:
        //     - attributes: Attributes

        #[cfg(feature = "filesystem-client")]
        DebugDumpStore:

        #[cfg(feature = "crypto-client")]
        Decrypt:
          - mechanism: Mechanism
          - key: KeyId
          - message: Message
          - associated_data: Message
          - nonce: ShortData
          - tag: ShortData

        #[cfg(feature = "crypto-client")]
        Delete:
          - key: KeyId

        #[cfg(feature = "crypto-client")]
        Clear:
          - key: KeyId

        #[cfg(feature = "crypto-client")]
        DeleteAllKeys:
          - location: Location

        // DeleteBlob:
        //   - prefix: Option<Letters>
        //   - name: ShortData

        // examples:
        // - public key from private key
        // - Diffie-Hellman
        // - hierarchical deterministic wallet stuff
        #[cfg(feature = "crypto-client")]
        DeriveKey:
            - mechanism: Mechanism
            - base_key: KeyId
            // - auxiliary_key: Option<ObjectHandle>
            - additional_data: Option<MediumData>
            // - attributes: KeyAttributes
            - attributes: StorageAttributes

        // DeriveKeypair:
        //     - mechanism: Mechanism
        //     - base_key: ObjectHandle
        //     // - additional_data: Message
        //     // - attributes: KeyAttributes

        #[cfg(feature = "crypto-client")]
        DeserializeKey:
          - mechanism: Mechanism
          - serialized_key: SerializedKey
          - format: KeySerialization
          - attributes: StorageAttributes

        #[cfg(feature = "crypto-client")]
        Encrypt:
          - mechanism: Mechanism
          - key: KeyId
          - message: Message
          - associated_data: ShortData
          - nonce: Option<ShortData>

        #[cfg(feature = "crypto-client")]
        Exists:
          - mechanism: Mechanism
          - key: KeyId

        // FindObjects:
        //     // - attributes: Attributes

        #[cfg(feature = "crypto-client")]
        GenerateKey:
            - mechanism: Mechanism        // -> implies key type
            // - attributes: KeyAttributes
            - attributes: StorageAttributes

        #[cfg(feature = "crypto-client")]
        GenerateSecretKey:
            - size: usize        // -> implies key type
            // - attributes: KeyAttributes
            - attributes: StorageAttributes

        // use GenerateKey + DeriveKey(public-from-private) instead
        // GenerateKeypair:
        //     - mechanism: Mechanism
        //     - attributes: KeyAttributes
        //     // private_key_template: PrivateKeyTemplate
        //     // public_key_template: PublicKeyTemplate

        // GetAttributes:
        //     - object: ObjectHandle
        //     - attributes: Attributes

        #[cfg(feature = "crypto-client")]
        Hash:
          - mechanism: Mechanism
          - message: Message

        #[cfg(feature = "filesystem-client")]
        LocateFile:
          - location: Location
          - dir: Option<PathBuf>
          - filename: PathBuf

        #[cfg(feature = "filesystem-client")]
        ReadDirFilesFirst:
          - location: Location
          - dir: PathBuf
          - user_attribute: Option<UserAttribute>

        #[cfg(feature = "filesystem-client")]
        ReadDirFilesNext:

        #[cfg(feature = "filesystem-client")]
        ReadDirFirst:
          - location: Location
          - dir: PathBuf
          - not_before: NotBefore

        #[cfg(feature = "filesystem-client")]
        ReadDirNext:

        #[cfg(feature = "filesystem-client")]
        ReadFile:
          - location: Location
          - path: PathBuf

        #[cfg(feature = "filesystem-client")]
        Metadata:
          - location: Location
          - path: PathBuf

        #[cfg(feature = "filesystem-client")]
        Rename:
          - location: Location
          - from: PathBuf
          - to: PathBuf

        #[cfg(feature = "filesystem-client")]
        RemoveFile:
          - location: Location
          - path: PathBuf

        #[cfg(feature = "filesystem-client")]
        RemoveDir:
          - location: Location
          - path: PathBuf

        #[cfg(feature = "filesystem-client")]
        RemoveDirAll:
          - location: Location
          - path: PathBuf

        // use GetAttribute(value) on counter instead
        // ReadCounter:
        //     - counter: ObjectHandle

        #[cfg(feature = "crypto-client")]
        RandomBytes:
          - count: usize

        #[cfg(feature = "crypto-client")]
        SerializeKey:
          - mechanism: Mechanism
          - key: KeyId
          - format: KeySerialization

        #[cfg(feature = "crypto-client")]
        Sign:
          - mechanism: Mechanism
          - key: KeyId
          - message: Message
          - format: SignatureSerialization

        #[cfg(feature = "filesystem-client")]
        WriteFile:
          - location: Location
          - path: PathBuf
          - data: Message
          - user_attribute: Option<UserAttribute>

        #[cfg(feature = "crypto-client")]
        UnsafeInjectKey:
          - mechanism: Mechanism        // -> implies key type
          - raw_key: SerializedKey
          - attributes: StorageAttributes
          - format: KeySerialization

        #[cfg(feature = "crypto-client")]
        UnsafeInjectSharedKey:
          - location: Location
          - raw_key: ShortData

        #[cfg(feature = "crypto-client")]
        UnwrapKey:
          - mechanism: Mechanism
          - wrapping_key: KeyId
          - wrapped_key: Message
          - associated_data: Message
          - nonce: ShortData
          - attributes: StorageAttributes

        #[cfg(feature = "crypto-client")]
        Verify:
          - mechanism: Mechanism
          - key: KeyId
          - message: Message
          - signature: Signature
          - format: SignatureSerialization

        // this should always be an AEAD algorithm
        #[cfg(feature = "crypto-client")]
        WrapKey:
          - mechanism: Mechanism
          - wrapping_key: KeyId
          - key: KeyId
          - associated_data: ShortData
          - nonce: Option<ShortData>

        #[cfg(feature = "ui-client")]
        RequestUserConsent:
          - level: consent::Level
          - timeout_milliseconds: u32

        #[cfg(feature = "management-client")]
        Reboot:
          - to: reboot::To

        #[cfg(feature = "management-client")]
        Uptime:

        #[cfg(feature = "ui-client")]
        Wink:
          - duration: Duration

        #[cfg(feature = "ui-client")]
        SetCustomStatus:
          - status: u8

        #[cfg(feature = "counter-client")]
        CreateCounter:
          - location: Location

        #[cfg(feature = "counter-client")]
        IncrementCounter:
          - id: CounterId

        #[cfg(feature = "certificate-client")]
        DeleteCertificate:
          - id: CertId

        #[cfg(feature = "certificate-client")]
        ReadCertificate:
          - id: CertId

        #[cfg(feature = "certificate-client")]
        WriteCertificate:
          - location: Location
          - der: Message

        #[cfg(feature = "serde-extensions")]
        SerdeExtension:
          - id: u8
          - request: Bytes<{ crate::config::SERDE_EXTENSION_REQUEST_LENGTH }>
    }
}

pub mod reply {
    #[allow(unused_imports)]
    use super::*;

    // type ObjectHandles = Vec<ObjectHandle, config::MAX_OBJECT_HANDLES>;

    impl_reply! {
        // could return either a SharedSecretXY or a SymmetricKeyXY,
        // depending on mechanism
        // e.g.: P256Raw -> SharedSecret32
        //       P256Sha256 -> SymmetricKey32
        #[cfg(feature = "crypto-client")]
        Agree:
            - shared_secret: KeyId

        #[cfg(feature = "crypto-client-attest")]
        Attest:
            - certificate: CertId

        // CreateObject:
        //     - object: ObjectHandle

        // FindObjects:
        //     - objects: Vec<ObjectHandle, config::MAX_OBJECT_HANDLES>
        //     // can be higher than capacity of vector
        //     - num_objects: usize

        #[cfg(feature = "filesystem-client")]
        DebugDumpStore:

        #[cfg(feature = "crypto-client")]
        Decrypt:
            - plaintext: Option<Message>

        #[cfg(feature = "crypto-client")]
        Delete:
            - success: bool

        #[cfg(feature = "crypto-client")]
        Clear:
            - success: bool

        #[cfg(feature = "crypto-client")]
        DeleteAllKeys:
            - count: usize

        #[cfg(feature = "crypto-client")]
        DeriveKey:
            - key: KeyId

        // DeriveKeypair:
        //     - private_key: ObjectHandle
        //     - public_key: ObjectHandle

        #[cfg(feature = "crypto-client")]
        DeserializeKey:
            - key: KeyId

        #[cfg(feature = "crypto-client")]
        Encrypt:
            - ciphertext: Message
            - nonce: ShortData
            - tag: ShortData

        #[cfg(feature = "crypto-client")]
        Exists:
            - exists: bool

        #[cfg(feature = "crypto-client")]
        GenerateKey:
            - key: KeyId

        #[cfg(feature = "crypto-client")]
        GenerateSecretKey:
            - key: KeyId

        // GenerateKeypair:
        //     - private_key: KeyId
        //     - public_key: KeyId

        #[cfg(feature = "crypto-client")]
        Hash:
          - hash: ShortData

        #[cfg(feature = "filesystem-client")]
        LocateFile:
          - path: Option<PathBuf>

        #[cfg(feature = "filesystem-client")]
        ReadDirFilesFirst:
          - data: Option<Message>

        #[cfg(feature = "filesystem-client")]
        ReadDirFilesNext:
          - data: Option<Message>

        #[cfg(feature = "filesystem-client")]
        ReadDirFirst:
          - entry: Option<DirEntry>

        #[cfg(feature = "filesystem-client")]
        ReadDirNext:
          - entry: Option<DirEntry>

        #[cfg(feature = "filesystem-client")]
        ReadFile:
          - data: Message

        #[cfg(feature = "filesystem-client")]
        Metadata:
          - metadata: Option<crate::types::Metadata>

        #[cfg(feature = "filesystem-client")]
        Rename:

        #[cfg(feature = "filesystem-client")]
        RemoveDir:

        #[cfg(feature = "filesystem-client")]
        RemoveDirAll:
          - count: usize

        #[cfg(feature = "filesystem-client")]
        RemoveFile:

        // ReadCounter:
        //     - counter: u32

        #[cfg(feature = "crypto-client")]
        RandomBytes:
            - bytes: Message

        #[cfg(feature = "crypto-client")]
        SerializeKey:
            - serialized_key: SerializedKey

        #[cfg(feature = "crypto-client")]
        Sign:
            - signature: Signature

        #[cfg(feature = "filesystem-client")]
        WriteFile:

        #[cfg(feature = "crypto-client")]
        Verify:
            - valid: bool

        #[cfg(feature = "crypto-client")]
        UnsafeInjectKey:
            - key: KeyId

        #[cfg(feature = "crypto-client")]
        UnsafeInjectSharedKey:
            - key: KeyId

        #[cfg(feature = "crypto-client")]
        UnwrapKey:
            - key: Option<KeyId>

        #[cfg(feature = "crypto-client")]
        WrapKey:
            - wrapped_key: Message

        // UI
        #[cfg(feature = "ui-client")]
        RequestUserConsent:
            - result: consent::Result

        #[cfg(feature = "management-client")]
        Reboot:

        #[cfg(feature = "management-client")]
        Uptime:
          - uptime: Duration

        #[cfg(feature = "ui-client")]
        Wink:

        #[cfg(feature = "ui-client")]
        SetCustomStatus:

        #[cfg(feature = "counter-client")]
        CreateCounter:
          - id: CounterId

        #[cfg(feature = "counter-client")]
        IncrementCounter:
          - counter: u128

        #[cfg(feature = "certificate-client")]
        DeleteCertificate:

        #[cfg(feature = "certificate-client")]
        ReadCertificate:
          - der: Message

        #[cfg(feature = "certificate-client")]
        WriteCertificate:
          - id: CertId

        #[cfg(feature = "serde-extensions")]
        SerdeExtension:
          - reply: Bytes<{ crate::config::SERDE_EXTENSION_REPLY_LENGTH }>
    }
}
