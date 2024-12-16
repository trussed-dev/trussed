use core::time::Duration;

use super::{ClientResult, PollClient};
use crate::{
    api::{reply, request},
    types::consent::Level,
};

/// User-interfacing functionality.
pub trait UiClient: PollClient {
    fn confirm_user_present(
        &mut self,
        timeout_milliseconds: u32,
    ) -> ClientResult<'_, reply::RequestUserConsent, Self> {
        self.request(request::RequestUserConsent {
            level: Level::Normal,
            timeout_milliseconds,
        })
    }

    fn wink(&mut self, duration: Duration) -> ClientResult<'_, reply::Wink, Self> {
        self.request(request::Wink { duration })
    }

    fn set_custom_status(&mut self, status: u8) -> ClientResult<'_, reply::SetCustomStatus, Self> {
        self.request(request::SetCustomStatus { status })
    }
}
