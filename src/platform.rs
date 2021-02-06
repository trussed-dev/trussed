//! Trait for platforms to implement that use Trussed.
//!
//! Trussed requires access to a cryptographically secure random number generator,
//! facilities for persistent and volatile storage, and some user interface to ensure
//! operations do not happen without user consent. Implementing this trait enables this.
//!
//! TODO: Currently, `Platform::R` lacks the `CryptoRng` bound.

// pub use rand_core::{CryptoRng, RngCore};
pub use rand_core::RngCore;
pub use crate::store::Store;
pub use crate::types::{ui, reboot};
pub use crate::types::consent;


pub trait UserInterface {
    /// Check if the user has indicated their presence so as to give
    /// consent to an action.
    fn check_user_presence(&mut self) -> consent::Level;

    /// Set the state of Trussed to give potential feedback to the user.
    fn set_status(&mut self, status: ui::Status);

    /// May be called during idle periods to give the UI the opportunity to update.
    fn refresh(&mut self);

    /// Return the duration since startup.
    fn uptime(&mut self) -> core::time::Duration;

    /// Exit / reset the application
    fn reboot (&mut self, to: reboot::To) -> !;
}

// This is the same trick as in "store.rs",
// replacing generic parameters with associated types
// and a macro.
pub unsafe trait Platform {
    // temporarily remove CryptoRng bound until HALs come along
    type R: /*CryptoRng +*/ RngCore;
    type S: Store;
    type UI: UserInterface;

    fn rng(&mut self) -> &mut Self::R;
    fn store(&self) -> Self::S;
    fn user_interface(&mut self) -> &mut Self::UI;
}

#[macro_export]
macro_rules! platform { (
    $PlatformName:ident,
    R: $Rng:ty,
    S: $Store:ty,
    UI: $UserInterface:ty,
) => {

    /// Platform struct implemented `trussed::Platform`, generated
    /// by a Trussed-supplied macro at call site, using the platform-specific
    /// implementations of its components.
    pub struct $PlatformName {
        rng: $Rng,
        store: $Store,
        user_interface: $UserInterface,
    }

    impl $PlatformName {
        pub fn new(rng: $Rng, store: $Store, user_interface: $UserInterface) -> Self {
            Self { rng, store, user_interface }
        }
    }

    unsafe impl $crate::platform::Platform for $PlatformName {
        type R = $Rng;
        type S = $Store;
        type UI = $UserInterface;

        fn user_interface(&mut self) -> &mut Self::UI {
            &mut self.user_interface
        }

        fn rng(&mut self) -> &mut Self::R {
            &mut self.rng
        }

        fn store(&self) -> Self::S {
            self.store
        }
    }
}}

/// Trussed client will call this method when making a Trussed request.
/// This is intended to trigger a secure context on the platform.
pub trait Syscall {
    fn syscall(&mut self);
}

