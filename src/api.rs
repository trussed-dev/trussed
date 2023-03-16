//! This (incomplete!) API loosely follows [PKCS#11 v3][pkcs11-v3].
//!
//! For constants see [their headers][pkcs11-headers].
//!
//! [pkcs11-v3]: https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html
//! [pkcs11-headers]: https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/cs01/include/pkcs11-v3.0/

use crate::types::*;
use core::time::Duration;

#[macro_use]
mod macros;

// TODO: Ideally, we would not need to assign random numbers here
// The only use for them is to check that the reply type corresponds
// to the request type in the client.
//
// At minimum, we don't want to list the indices (may need proc-macro)

generate_enums! {

    ////////////
    // Crypto //
    ////////////

    Agree: 1
    // CreateObject: 2
    // TODO: why do Decrypt and DeriveKey both have discriminant 3?!
    Decrypt: 3
    DeriveKey: 4
    DeserializeKey: 5
    Encrypt: 6
    Delete: 7
    DeleteAllKeys: 25
    Exists: 8
    // DeriveKeypair: 3
    // FindObjects: 9
    GenerateKey: 10
    GenerateSecretKey: 11
    // GenerateKeypair: 6
    Hash: 12
    // TODO: add ReadDir{First,Next}, not loading data, if needed for efficiency
    ReadDirFilesFirst: 13
    ReadDirFilesNext: 14
    ReadFile: 15
    Metadata: 26
    // ReadCounter: 7
    RandomBytes: 16
    SerializeKey: 17
    Sign: 18
    WriteFile: 19
    UnsafeInjectKey: 20
    UnsafeInjectSharedKey: 21
    UnwrapKey: 22
    Verify: 23
    WrapKey: 24

    Attest: 0xFF

    /////////////
    // Storage //
    /////////////

    // // CreateDir,    <-- implied by WriteFile
    ReadDirFirst: 31 //      <-- gets Option<FileType> to restrict to just dir/file DirEntries,
    ReadDirNext: 32 //      <-- gets Option<FileType> to restrict to just dir/file DirEntries,
    //                   // returns simplified Metadata
    // // ReadDirFilesFirst: 23 // <-- returns contents
    // // ReadDirFilesNext: 24 // <-- returns contents
    // ReadFile: 25
    RemoveFile: 33
    RemoveDir: 36
    RemoveDirAll: 34
    // WriteFile: 29
    LocateFile: 35

    ////////
    // UI //
    ////////

    RequestUserConsent: 41
    Reboot: 42
    Uptime: 43
    Wink: 44

    //////////////
    // Counters //
    //////////////

    CreateCounter: 50
    IncrementCounter: 51

    //////////////////
    // Certificates //
    //////////////////

    DeleteCertificate: 60
    ReadCertificate: 61
    WriteCertificate: 62

    ///////////
    // Other //
    ///////////
    DebugDumpStore: 0x79

    SerdeExtension: 0x5E
}

pub trait RequestVariant: Into<Request> + TryFrom<Request, Error = crate::Error> {
    type Reply: ReplyVariant<Request = Self>;
}

pub trait ReplyVariant: Into<Reply> + TryFrom<Reply, Error = crate::Error> {
    type Request: RequestVariant<Reply = Self>;
}

pub mod request {
    use super::*;

    impl_request! {
        Agree:
            - mechanism: Mechanism
            - private_key: KeyId
            - public_key: KeyId
            - attributes: StorageAttributes

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

        DebugDumpStore:

        Decrypt:
          - mechanism: Mechanism
          - key: KeyId
          - message: Message
          - associated_data: Message
          - nonce: ShortData
          - tag: ShortData

        Delete:
          - key: KeyId

        DeleteAllKeys:
          - location: Location

        // DeleteBlob:
        //   - prefix: Option<Letters>
        //   - name: ShortData

        // examples:
        // - public key from private key
        // - Diffie-Hellman
        // - hierarchical deterministic wallet stuff
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

        DeserializeKey:
          - mechanism: Mechanism
          - serialized_key: SerializedKey
          - format: KeySerialization
          - attributes: StorageAttributes

        Encrypt:
          - mechanism: Mechanism
          - key: KeyId
          - message: Message
          - associated_data: ShortData
          - nonce: Option<ShortData>

        Exists:
          - mechanism: Mechanism
          - key: KeyId

        // FindObjects:
        //     // - attributes: Attributes

        GenerateKey:
            - mechanism: Mechanism        // -> implies key type
            // - attributes: KeyAttributes
            - attributes: StorageAttributes

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

        Hash:
          - mechanism: Mechanism
          - message: Message

        LocateFile:
          - location: Location
          - dir: Option<PathBuf>
          - filename: PathBuf

        ReadDirFilesFirst:
          - location: Location
          - dir: PathBuf
          - user_attribute: Option<UserAttribute>

        ReadDirFilesNext:

        ReadDirFirst:
          - location: Location
          - dir: PathBuf
          - not_before_filename: Option<PathBuf>

        ReadDirNext:

        ReadFile:
          - location: Location
          - path: PathBuf

        Metadata:
          - location: Location
          - path: PathBuf

        RemoveFile:
          - location: Location
          - path: PathBuf

        RemoveDir:
          - location: Location
          - path: PathBuf

        RemoveDirAll:
          - location: Location
          - path: PathBuf

        // use GetAttribute(value) on counter instead
        // ReadCounter:
        //     - counter: ObjectHandle

        RandomBytes:
          - count: usize

        SerializeKey:
          - mechanism: Mechanism
          - key: KeyId
          - format: KeySerialization

        Sign:
          - mechanism: Mechanism
          - key: KeyId
          - message: Message
          - format: SignatureSerialization

        WriteFile:
          - location: Location
          - path: PathBuf
          - data: Message
          - user_attribute: Option<UserAttribute>

        UnsafeInjectKey:
          - mechanism: Mechanism        // -> implies key type
          - raw_key: SerializedKey
          - attributes: StorageAttributes
          - format: KeySerialization

        UnsafeInjectSharedKey:
          - location: Location
          - raw_key: ShortData

        UnwrapKey:
          - mechanism: Mechanism
          - wrapping_key: KeyId
          - wrapped_key: Message
          - associated_data: Message
          - attributes: StorageAttributes

        Verify:
          - mechanism: Mechanism
          - key: KeyId
          - message: Message
          - signature: Signature
          - format: SignatureSerialization

        // this should always be an AEAD algorithm
        WrapKey:
          - mechanism: Mechanism
          - wrapping_key: KeyId
          - key: KeyId
          - associated_data: ShortData

        RequestUserConsent:
          - level: consent::Level
          - timeout_milliseconds: u32

        Reboot:
          - to: reboot::To

        Uptime:

        Wink:
          - duration: core::time::Duration

        CreateCounter:
          - location: Location

        IncrementCounter:
          - id: CounterId

        DeleteCertificate:
          - id: CertId

        ReadCertificate:
          - id: CertId

        WriteCertificate:
          - location: Location
          - der: Message

        SerdeExtension:
          - id: u8
          - request: Bytes<{ crate::config::SERDE_EXTENSION_REQUEST_LENGTH }>
    }
}

pub mod reply {
    use super::*;

    // type ObjectHandles = Vec<ObjectHandle, config::MAX_OBJECT_HANDLES>;

    impl_reply! {
        // could return either a SharedSecretXY or a SymmetricKeyXY,
        // depending on mechanism
        // e.g.: P256Raw -> SharedSecret32
        //       P256Sha256 -> SymmetricKey32
        Agree:
            - shared_secret: KeyId

        Attest:
            - certificate: CertId

        // CreateObject:
        //     - object: ObjectHandle

        // FindObjects:
        //     - objects: Vec<ObjectHandle, config::MAX_OBJECT_HANDLES>
        //     // can be higher than capacity of vector
        //     - num_objects: usize

        DebugDumpStore:

        Decrypt:
            - plaintext: Option<Message>

        Delete:
            - success: bool

        DeleteAllKeys:
            - count: usize

        DeriveKey:
            - key: KeyId

        // DeriveKeypair:
        //     - private_key: ObjectHandle
        //     - public_key: ObjectHandle

        DeserializeKey:
            - key: KeyId

        Encrypt:
            - ciphertext: Message
            - nonce: ShortData
            - tag: ShortData

        Exists:
            - exists: bool

        GenerateKey:
            - key: KeyId

        GenerateSecretKey:
            - key: KeyId

        // GenerateKeypair:
        //     - private_key: KeyId
        //     - public_key: KeyId

        Hash:
          - hash: ShortData

        LocateFile:
          - path: Option<PathBuf>

        ReadDirFilesFirst:
          - data: Option<Message>

        ReadDirFilesNext:
          - data: Option<Message>

        ReadDirFirst:
          - entry: Option<DirEntry>

        ReadDirNext:
          - entry: Option<DirEntry>

        ReadFile:
          - data: Message

        Metadata:
          - metadata: Option<crate::types::Metadata>

        RemoveDir:

        RemoveDirAll:
          - count: usize

        RemoveFile:

        // ReadCounter:
        //     - counter: u32

        RandomBytes:
            - bytes: Message

        SerializeKey:
            - serialized_key: SerializedKey

        Sign:
            - signature: Signature

        WriteFile:

        Verify:
            - valid: bool

        UnsafeInjectKey:
            - key: KeyId

        UnsafeInjectSharedKey:
            - key: KeyId

        UnwrapKey:
            - key: Option<KeyId>

        WrapKey:
            - wrapped_key: Message

        // UI
        RequestUserConsent:
            - result: consent::Result

        Reboot:

        Uptime:
          - uptime: Duration

        Wink:

        CreateCounter:
          - id: CounterId

        IncrementCounter:
          - counter: u128

        DeleteCertificate:

        ReadCertificate:
          - der: Message

        WriteCertificate:
          - id: CertId

        SerdeExtension:
          - reply: Bytes<{ crate::config::SERDE_EXTENSION_REPLY_LENGTH }>
    }
}
