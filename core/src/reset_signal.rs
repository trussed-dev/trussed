use core::sync::atomic::{AtomicU8, Ordering};

/// Structure meant to be stored in  a `static` to signal applications that they have been factory-resetted by a runner
///
/// It is expected to have one such structure for each application supporting factory-reset
#[derive(Debug)]
pub struct ResetSignalAllocation(AtomicU8);

impl Default for ResetSignalAllocation {
    fn default() -> Self {
        Self::new()
    }
}

impl ResetSignalAllocation {
    pub const fn new() -> Self {
        Self(AtomicU8::new(ResetSignal::None as u8))
    }

    pub fn load(&self) -> ResetSignal {
        let v = self.0.load(Ordering::Relaxed);
        ResetSignal::from_repr(v).expect("A reset signal value")
    }

    pub fn set_factory_reset(&self) -> bool {
        self.0
            .compare_exchange(
                ResetSignal::None as u8,
                ResetSignal::FactoryReset as u8,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_ok()
    }

    pub fn set_config_changed(&self) {
        self.0
            .store(ResetSignal::ConfigChanged as u8, Ordering::Relaxed)
    }

    /// Factory reset can be acknowledged so that the application can restart working
    ///
    /// A configuration change cannot be acknowledged as it requires a power cycle to be taken into account.
    pub fn ack_factory_reset(&self) -> bool {
        self.0
            .compare_exchange(
                ResetSignal::FactoryReset as u8,
                ResetSignal::None as u8,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_ok()
    }
}

macro_rules! enum_u8 {
    (
        $(#[$outer:meta])*
        $vis:vis enum $name:ident {
            $($(#[$attr:meta])* $var:ident),+
            $(,)*
        }
    ) => {
        $(#[$outer])*
        #[repr(u8)]
        $vis enum $name {
            $(
                $(#[$attr])*
                $var,
            )*
        }

        impl $name {
            fn from_repr(val: u8) -> Option<$name> {
                mod constants {
                    $(
                        #[allow(non_upper_case_globals)]
                        pub const $var: u8 = super::$name::$var as u8;
                    )*
                }
                match val {
                    $(
                       constants::$var => Some($name::$var),
                    )*
                    _ => None,
                }
            }
        }
    }
}

enum_u8!(
    #[derive(Debug, Default)]
    pub enum ResetSignal {
        #[default]
        /// The App can continue operating
        None,
        /// The app has had it state factory reseted by the admin app
        ///
        /// It should delete any runtime state it is currently holding, then [`acknowledge`](ResetSignalAllocation::ack_factory_reset) the reset and continue working.
        FactoryReset,
        /// A configuration relevant to the application has been changed.
        ///
        /// The application must reject all incoming request and store no persistent state until a power cycle.
        ConfigChanged,
    }
);
