use super::{ClientResult, PollClient};
use crate::{
    api::{reply, request},
    types::reboot,
};

/// All the other methods that are fit to expose.
pub trait ManagementClient: PollClient {
    fn reboot(&mut self, to: reboot::To) -> ClientResult<'_, reply::Reboot, Self> {
        self.request(request::Reboot { to })
    }

    fn uptime(&mut self) -> ClientResult<'_, reply::Uptime, Self> {
        self.request(request::Uptime {})
    }
}
