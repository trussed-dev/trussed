use super::{ClientResult, PollClient};
use crate::{
    api::{reply, request},
    types::{KeyId, Mechanism},
};

pub trait AttestationClient: PollClient {
    fn attest(
        &mut self,
        signing_mechanism: Mechanism,
        private_key: KeyId,
    ) -> ClientResult<'_, reply::Attest, Self> {
        self.request(request::Attest {
            signing_mechanism,
            private_key,
        })
    }
}
