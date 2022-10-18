use littlefs2::path::PathBuf;
use chacha20::ChaCha8Rng;
use heapless_bytes::Unsigned;
pub use rand_core::{RngCore, SeedableRng};
use cosey::Bytes;


use crate::types::*;
use crate::api::*;
use crate::platform::*;
use crate::config::*;
use crate::mechanisms;

use crate::error::Error;
pub use crate::pipe::ServiceEndpoint;

pub use crate::store::{
    certstore::{Certstore as _, ClientCertstore},
    counterstore::{ClientCounterstore, Counterstore as _},
    filestore::{ClientFilestore, Filestore, ReadDirFilesState, ReadDirState},
    keystore::{ClientKeystore, Keystore},
};

pub struct SoftwareAuthBackend<P>
where
    P: Platform,
{
    pub(crate) platform: P,
    rng_state: Option<ChaCha8Rng>,
}

/*pub struct SoftwareAuthService<P>
where
    P: Platform,
{
    eps: Vec<ServiceEndpoint, { MAX_SERVICE_CLIENTS::USIZE }>,
    resources: SoftwareAuthBackend<P>,
}

// need to be able to send crypto service to an interrupt handler
unsafe impl<P: Platform> Send for SoftwareAuthService<P> {}*/


impl<P: Platform> SoftwareAuthBackend<P> {
    fn write_policy(&mut self, path: PathBuf, policy: Policy) {

    }
    pub fn rng(&mut self) -> Result<ChaCha8Rng, Error> {
        // Check if our RNG is loaded.
        let mut rng = match self.rng_state.take() {
            Some(rng) => rng,
            None => {
                let mut filestore: ClientFilestore<P::S> =
                    ClientFilestore::new(PathBuf::from("trussed"), self.platform.store());

                let path = PathBuf::from("rng-state.bin");

                // Load previous seed, e.g., externally injected entropy on first run.
                // Else, default to zeros - will mix in new HW RNG entropy next
                let mixin_seed = if !filestore.exists(&path, Location::Internal) {
                    [0u8; 32]
                } else {
                    // Use the last saved state.
                    let mixin_bytes: Bytes<32> = filestore.read(&path, Location::Internal)?;
                    let mut mixin_seed = [0u8; 32];
                    mixin_seed.clone_from_slice(&mixin_bytes);
                    mixin_seed
                };

                // Generally, the TRNG is fed through a DRBG to whiten its output.
                //
                // In principal seeding a DRBG like Chacha8Rng from "good" HW/external entropy
                // should be good enough for the lifetime of the key.
                //
                // Since we have a TRNG though, we might as well mix in some new entropy
                // on each boot. We do not do so on each DRBG draw to avoid excessive flash writes.
                // (e.g., if some app exposes unlimited "read-entropy" functionality to users).
                //
                // Additionally, we use a twist on the ideas of Haskell's splittable RNGs, and store
                // an input seed for the next boot. In this way, even if the HW entropy "goes bad"
                // (e.g., starts returning all zeros), there are still no cycles or repeats of entropy
                // in the output to apps.

                // 1. First, draw fresh entropy from the HW TRNG.
                let mut entropy = [0u8; 32];
                self.platform
                    .rng()
                    .try_fill_bytes(&mut entropy)
                    .map_err(|_| Error::EntropyMalfunction)?;

                // 2. Mix into our previously stored seed.
                let mut our_seed = [0u8; 32];
                for i in 0..32 {
                    our_seed[i] = mixin_seed[i] ^ entropy[i];
                }

                // 3. Initialize ChaCha8 construction with our seed.
                let mut rng = chacha20::ChaCha8Rng::from_seed(our_seed);

                // 4. Store freshly drawn seed for next boot.
                let mut seed_to_store = [0u8; 32];
                rng.fill_bytes(&mut seed_to_store);
                filestore
                    .write(&path, Location::Internal, seed_to_store.as_ref())
                    .unwrap();

                // 5. Finish
                Ok(rng)
            }?,
        };

        // split off another DRBG
        let split_rng = ChaCha8Rng::from_rng(&mut rng).map_err(|_| Error::EntropyMalfunction);
        self.rng_state = Some(rng);
        split_rng
    }
}

impl<P: Platform> ServiceBackend for SoftwareAuthBackend<P> {

    fn reply_to(&mut self, client_ctx: &mut ClientContext, request: &Request)
        -> Result<Reply, Error> {

        let full_store = self.platform.store();

        // prepare keystore, bound to client_id, for cryptographic calls
        let mut keystore: ClientKeystore<P> = ClientKeystore::new(
            client_ctx.path.clone(),
            self.rng().map_err(|_| Error::EntropyMalfunction)?,
            full_store,
        );
        let keystore = &mut keystore;

        // prepare certstore, bound to client_id, for cert calls
        let mut certstore: ClientCertstore<P::S> = ClientCertstore::new(
            client_ctx.path.clone(),
            self.rng().map_err(|_| Error::EntropyMalfunction)?,
            full_store,
        );
        let certstore = &mut certstore;

        // prepare counterstore, bound to client_id, for counter calls
        let mut counterstore: ClientCounterstore<P::S> = ClientCounterstore::new(
            client_ctx.path.clone(),
            self.rng().map_err(|_| Error::EntropyMalfunction)?,
            full_store,
        );
        let counterstore = &mut counterstore;

        // prepare filestore, bound to client_id, for storage calls
        let mut filestore: ClientFilestore<P::S> =
            ClientFilestore::new(client_ctx.path.clone(), full_store);
        let filestore = &mut filestore;

        match request {
            Request::DummyRequest => {
                Ok(Reply::DummyReply)
            },

            Request::Wink(request) => {
                //self.platform.user_interface().wink(request.duration);
                debug_now!("was geht ab....");
                Ok(Reply::Wink(reply::Wink {}))
            }

            /*Request::Agree(request) => {
                match request.mechanism {

                    Mechanism::P256 => mechanisms::P256::agree(keystore, request),
                    Mechanism::X255 => mechanisms::X255::agree(keystore, request),
                    _ => Err(Error::MechanismNotAvailable),

                }.map(Reply::Agree)
            },*/

            _ => {
                Err(Error::RequestNotAvailable)
            },
        }

    }

}
