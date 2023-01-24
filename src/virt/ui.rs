use crate::platform::{self, consent::Level, reboot::To, ui::Status};
use std::time::{Duration, Instant};

pub struct UserInterface {
    start_time: Instant,
    inner: Option<Box<dyn platform::UserInterface + Sync + Send>>,
}

impl UserInterface {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            inner: None,
        }
    }

    pub fn set_inner(&mut self, inner: impl Into<Box<dyn platform::UserInterface + Sync + Send>>) {
        self.inner = Some(inner.into());
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
            .unwrap_or(Level::Normal)
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
