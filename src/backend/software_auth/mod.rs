use crate::types::{ServiceBackend, ClientContext};
use crate::api::{Request, Reply};
use crate::error::Error;

pub struct SoftwareAuthBackend {


}


impl ServiceBackend for SoftwareAuthBackend {

    fn reply_to(&mut self, client_ctx: &mut ClientContext, request: &Request)
        -> Result<Reply, Error> {


    }
}
