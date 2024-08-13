pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[repr(u32)]
#[non_exhaustive]
pub enum Error {
    // cryptoki errors
    HostMemory = 0x0000_0002,
    GeneralError = 0x0000_0005,
    FunctionFailed = 0x0000_0006,
    // supposed to support "stub" function for everything,
    // returning this error
    FunctionNotSupported = 0x0000_0054,
    // unknown, or cannot be used in this token with selected function
    MechanismInvalid = 0x0000_0070,
    MechanismParamInvalid = 0x0000_0071,
    ObjectHandleInvalid = 0x0000_0082,

    // our errors
    AeadError,
    CborError,
    ClientCountExceeded,
    EntropyMalfunction,
    FilesystemReadFailure,
    FilesystemWriteFailure,
    ImplementationError,
    InternalError,
    InvalidPath,
    InvalidSerializedKey,
    InvalidSerializedReply,
    InvalidSerializedRequest,
    InvalidSerializationFormat,
    MechanismNotAvailable,
    NonceOverflow,
    NoSuchCertificate,
    NoSuchKey,
    NotJustLetters,
    ReplySerializationFailure,
    RequestNotAvailable,
    SignDataTooLarge,
    WrongKeyKind,
    WrongMessageLength,
    WrongSignatureLength,
}
