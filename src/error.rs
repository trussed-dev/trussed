// use core::task::Poll;

// use crate::api::Reply;
// use crate::client::RawClient;

pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[repr(u32)]
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

// pub struct FutureResult<'a, 'c> {
//     c: &'c mut RawClient<'a>,
// }

// impl<'a, 'c> FutureResult<'a, 'c> {
//     pub fn new(client: &'c mut RawClient<'a>) -> Self {
//         Self { c: client }
//     }

//     pub fn poll(&mut self) -> Poll<core::result::Result<Reply, Error>> {
//         // pop request in channel
//         match self.c.ep.recv.dequeue() {
//             Some(reply) => {
//                 #[cfg(all(test, feature = "verbose-tests"))]
//                 println!("got a reply");
//                 Poll::Ready(reply)
//             },
//             _ => Poll::Pending
//         }
//     }
// }
