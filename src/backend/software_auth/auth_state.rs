use littlefs2::path::PathBuf;
use serde::{Deserialize, Serialize};

use crate::{
    error::{Error, Result},
    store::{self, Store},
    types::{AuthContextID, ClientContext, Location, PinData},
    Bytes,
};

const USER_MAX_AUTH_TRIES: u8 = 3;
const ADMIN_MAX_AUTH_TRIES: u8 = 10;

const USER_DEFAULT_SECRET: &str = "1234";
const ADMIN_DEFAULT_SECRET: &str = "123456";

const AUTH_CONTEXT_STATE_PATH: &str = "auth_context.state";

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
struct AuthContextState {
    secret: PinData,
    tries_left: u8,
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
struct AuthContextStateMain {
    user: AuthContextState,
    admin: AuthContextState,
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct AuthState<S: Store> {
    state: AuthContextStateMain,
    full_store: S,
    path: PathBuf,
}

impl<S: Store> AuthState<S> {
    pub fn new(full_store: S, client_ctx: &ClientContext) -> Self {
        let state_path = Self::state_path(client_ctx);

        if !store::exists(full_store, Location::Internal, &state_path) {
            let def = AuthContextStateMain {
                user: AuthContextState {
                    secret: PinData::from_slice(USER_DEFAULT_SECRET.as_bytes()).unwrap(),
                    tries_left: USER_MAX_AUTH_TRIES,
                },
                admin: AuthContextState {
                    secret: PinData::from_slice(ADMIN_DEFAULT_SECRET.as_bytes()).unwrap(),
                    tries_left: ADMIN_MAX_AUTH_TRIES,
                },
            };
            let out = Self {
                state: def,
                full_store,
                path: state_path,
            };
            out.write();
            out
        } else {
            let state: Bytes<256> =
                store::read(full_store, Location::Internal, &state_path).unwrap();
            let obj = crate::cbor_deserialize(state.as_slice()).unwrap();
            Self {
                state: obj,
                full_store,
                path: state_path,
            }
        }
    }

    pub fn state_path(client_ctx: &ClientContext) -> PathBuf {
        let mut state_path = PathBuf::new();
        state_path.push(&client_ctx.path);
        state_path.push(&PathBuf::from(AUTH_CONTEXT_STATE_PATH));
        state_path
    }

    pub fn write(&self) -> Result<()> {
        let serialized: Bytes<256> =
            crate::cbor_serialize_bytes(&self.state).map_err(|_| Error::CborError)?;

        store::store(
            self.full_store,
            Location::Internal,
            &self.path,
            serialized.as_slice(),
        )
        .map_err(|_| Error::InternalError)
    }

    pub fn set(&mut self, auth_ctx_id: AuthContextID, secret: &PinData) -> Result<()> {
        match auth_ctx_id {
            AuthContextID::User => {
                self.state.user.secret = secret.clone();
            }
            AuthContextID::Admin => {
                self.state.admin.secret = secret.clone();
            }
            AuthContextID::Unauthorized => {}
        }
        Ok(())
    }

    pub fn retries(&self, auth_ctx_id: AuthContextID) -> u8 {
        match auth_ctx_id {
            AuthContextID::Unauthorized => u8::MAX,
            AuthContextID::User => self.state.user.tries_left,
            AuthContextID::Admin => self.state.admin.tries_left,
        }
    }

    pub fn check(&mut self, auth_ctx_id: AuthContextID, secret: &PinData) -> Result<bool> {
        // TODO: save state ONLY on retries change
        let tries_left = match auth_ctx_id {
            AuthContextID::Unauthorized => {
                return Ok(true);
            }
            AuthContextID::User => self.state.user.tries_left,
            AuthContextID::Admin => self.state.admin.tries_left,
        };

        if tries_left == 0 {
            return Err(Error::NoAuthTriesLeft);
        }

        match auth_ctx_id {
            AuthContextID::Unauthorized => Ok(true),
            AuthContextID::User => {
                let result = self.state.user.secret.eq(secret);
                match result {
                    true => self.state.user.tries_left = USER_MAX_AUTH_TRIES,
                    false => self.state.user.tries_left = tries_left - 1,
                }
                self.write();
                Ok(result)
            }
            AuthContextID::Admin => {
                let result = self.state.admin.secret.eq(secret);
                match result {
                    true => {
                        self.state.admin.tries_left = ADMIN_MAX_AUTH_TRIES;
                        self.state.user.tries_left = USER_MAX_AUTH_TRIES;
                    }
                    false => self.state.admin.tries_left = tries_left - 1,
                }
                self.write();
                Ok(result)
            }
        }
    }
}
