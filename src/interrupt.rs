use core::{
    fmt::Debug,
    sync::atomic::{AtomicU8, Ordering::Relaxed},
};

#[derive(Default, Debug, PartialEq, Eq)]
pub enum InterruptState {
    #[default]
    Idle = 0,
    Working = 1,
    Interrupted = 2,
}

impl TryFrom<u8> for InterruptState {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Idle),
            1 => Ok(Self::Working),
            2 => Ok(Self::Interrupted),
            _ => Err(()),
        }
    }
}

impl From<InterruptState> for u8 {
    fn from(value: InterruptState) -> Self {
        value as _
    }
}

#[derive(Default)]
pub struct InterruptFlag(AtomicU8);

const CONV_ERROR: &str =
    "Internal trussed error: InterruptState must always be set to an enum variant";

impl InterruptFlag {
    pub const fn new() -> Self {
        Self(AtomicU8::new(0))
    }
    fn load(&self) -> InterruptState {
        self.0.load(Relaxed).try_into().expect(CONV_ERROR)
    }

    pub fn set_idle(&self) {
        self.0.store(InterruptState::Idle.into(), Relaxed)
    }
    pub fn set_working(&self) {
        self.0.store(InterruptState::Working.into(), Relaxed)
    }
    pub fn interrupt(&self) -> bool {
        self.0
            .compare_exchange(
                InterruptState::Working.into(),
                InterruptState::Interrupted.into(),
                Relaxed,
                Relaxed,
            )
            .is_ok()
    }

    pub fn is_interrupted(&self) -> bool {
        let res = self.load();
        info_now!("got interrupt state: {:?}", res);
        res == InterruptState::Interrupted
    }
}

impl Debug for InterruptFlag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.load().fmt(f)
    }
}
