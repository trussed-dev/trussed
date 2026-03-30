use std::time::{Duration, Instant};

use trussed_core::types::{consent::Level, reboot::To};

use crate::{platform, types::ui::Status};

pub struct UserInterface {
    start_time: Instant,
    user_presence_level: Level,
    inner: Option<Box<dyn platform::UserInterface + Sync + Send>>,
}

impl UserInterface {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            user_presence_level: Level::Normal,
            inner: None,
        }
    }

    pub fn set_user_presence_level(&mut self, level: Level) {
        self.user_presence_level = level;
    }

    pub fn set_inner(&mut self, inner: Box<dyn platform::UserInterface + Sync + Send>) {
        self.inner = Some(inner);
    }

    pub fn take_inner(&mut self) -> Option<Box<dyn platform::UserInterface + Sync + Send>> {
        self.inner.take()
    }
}

impl Default for UserInterface {
    fn default() -> Self {
        Self::new()
    }
}

impl platform::UserInterface for UserInterface {
    fn check_user_presence(&mut self) -> Level {
        self.inner
            .as_mut()
            .map(|inner| inner.check_user_presence())
            .unwrap_or(self.user_presence_level)
    }

    fn set_status(&mut self, status: Status) {
        if let Some(inner) = &mut self.inner {
            inner.set_status(status);
        }
    }

    fn refresh(&mut self) {
        if let Some(inner) = &mut self.inner {
            inner.refresh();
        }
    }

    fn uptime(&mut self) -> Duration {
        self.start_time.elapsed()
    }

    fn reboot(&mut self, to: To) -> ! {
        if let Some(inner) = &mut self.inner {
            inner.reboot(to);
        } else {
            loop {
                continue;
            }
        }
    }

    fn wink(&mut self, duration: Duration) {
        if let Some(inner) = &mut self.inner {
            inner.wink(duration);
        }
    }
}
