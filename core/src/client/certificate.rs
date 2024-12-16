use super::{ClientError, ClientResult, PollClient};
use crate::{
    api::{reply, request},
    types::{CertId, Location, Message},
};

/// Read/Write + Delete certificates
pub trait CertificateClient: PollClient {
    fn delete_certificate(
        &mut self,
        id: CertId,
    ) -> ClientResult<'_, reply::DeleteCertificate, Self> {
        self.request(request::DeleteCertificate { id })
    }

    fn read_certificate(&mut self, id: CertId) -> ClientResult<'_, reply::ReadCertificate, Self> {
        self.request(request::ReadCertificate { id })
    }

    /// Currently, this writes the cert (assumed but not verified to be DER)
    /// as-is. It might make sense to add attributes (such as "deletable").
    /// (On the other hand, the attn CA certs are not directly accessible to clients,
    /// and generated attn certs can be regenerated).
    fn write_certificate(
        &mut self,
        location: Location,
        der: &[u8],
    ) -> ClientResult<'_, reply::WriteCertificate, Self> {
        let der = Message::from_slice(der).map_err(|_| ClientError::DataTooLarge)?;
        self.request(request::WriteCertificate { location, der })
    }
}
