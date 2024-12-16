use super::{ClientResult, PollClient};
use crate::{
    api::{reply, request},
    types::{CounterId, Location},
};

/// Create counters, increment existing counters.
pub trait CounterClient: PollClient {
    fn create_counter(
        &mut self,
        location: Location,
    ) -> ClientResult<'_, reply::CreateCounter, Self> {
        self.request(request::CreateCounter { location })
    }

    fn increment_counter(
        &mut self,
        id: CounterId,
    ) -> ClientResult<'_, reply::IncrementCounter, Self> {
        self.request(request::IncrementCounter { id })
    }
}
