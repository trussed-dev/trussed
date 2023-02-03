macro_rules! generate_enums {
    ($($which:ident: $index:literal)*) => {

    #[derive(Clone, Eq, PartialEq, Debug)]
    #[allow(clippy::large_enum_variant)]
    pub enum Request {
        DummyRequest, // for testing
        $(
        $which(request::$which),
        )*
    }

    #[derive(Clone, Eq, PartialEq, Debug)]
    #[allow(clippy::large_enum_variant)]
    pub enum Reply {
        DummyReply, // for testing
        $(
        $which(reply::$which),
        )*
    }

    impl From<&Request> for u8 {
        fn from(request: &Request) -> u8 {
            match request {
                Request::DummyRequest => 0,
                $(
                Request::$which(_) => $index,
                )*
            }
        }
    }

    impl From<&Reply> for u8 {
        fn from(reply: &Reply) -> u8 {
            match reply {
                Reply::DummyReply => 0,
                $(
                Reply::$which(_) => $index,
                )*
            }
        }
    }

}}

macro_rules! impl_request {
    ($(
        $request:ident:
            $(- $name:tt: $type:path)*
    )*)
        => {$(
    #[derive(Clone, Eq, PartialEq, Debug, serde_indexed::DeserializeIndexed, serde_indexed::SerializeIndexed)]
    pub struct $request {
        $(
            pub $name: $type,
        )*
    }

    impl From<$request> for Request {
        fn from(request: $request) -> Self {
            Self::$request(request)
        }
    }
    impl core::convert::TryFrom<Request> for $request {
        type Error = crate::Error;
        fn try_from(request: Request) -> Result<request::$request, Self::Error> {
            match request {
                Request::$request(request) => Ok(request),
                _ => Err(crate::Error::InternalError),
            }
        }
    }

    impl RequestVariant for $request {
        type Reply = reply::$request;
    }

    )*}
}

macro_rules! impl_reply {
    ($(
        $reply:ident:
            $(- $name:tt: $type:ty)*
    )*)
        => {$(

    #[derive(Clone, Eq, PartialEq, Debug, serde_indexed::DeserializeIndexed, serde_indexed::SerializeIndexed)]
    pub struct $reply {
        $(
            pub $name: $type,
        )*
    }

    impl core::convert::TryFrom<Reply> for $reply {
        type Error = crate::Error;
        fn try_from(reply: Reply) -> Result<reply::$reply, Self::Error> {
            match reply {
                Reply::$reply(reply) => Ok(reply),
                _ => Err(crate::Error::InternalError),
            }
        }
    }

    impl core::convert::From<$reply> for Reply {
        fn from(reply: $reply) -> Reply {
            Reply::$reply(reply)
        }
    }

    impl ReplyVariant for $reply {
        type Request = request::$reply;
    }

    )*}
}
