//! Downstream response.

use {
    crate::{body::Body, error::Error, headers::filter_outgoing_headers},
    hyper::http::response::Response,
    std::mem,
    tokio::sync::oneshot::Sender,
};

/// Downstream response states.
///
/// See [`Session::set_downstream_response_sender`][set] and
/// [`Session::send_downstream_response`][send] for more information.
///
/// [send]: struct.Session.html#method.send_downstream_response
/// [set]: struct.Session.html#method.set_downstream_response_sender
pub(super) enum DownstreamResponse {
    /// No channel to send the response has been opened yet.
    Closed,
    /// A channel has been opened, but no response has been sent yet.
    Pending(Sender<Response<Body>>),
    /// A response has already been sent downstream.
    Sent,
}

impl DownstreamResponse {
    /// Open a channel to send a [`Response`][resp] downstream, given a [`oneshot::Sender`][sender].
    ///
    /// [resp]: https://docs.rs/http/latest/http/response/struct.Response.html
    /// [sender]: https://docs.rs/tokio/latest/tokio/sync/oneshot/struct.Sender.html
    pub fn new(sender: Sender<Response<Body>>) -> Self {
        DownstreamResponse::Pending(sender)
    }

    pub fn is_unsent(&self) -> bool {
        matches!(self, Self::Pending(_))
    }

    /// Send a [`Response`][resp] downstream.
    ///
    /// Yield an error if a response has already been sent.
    ///
    /// # Panics
    ///
    /// This method will panic if the associated receiver was dropped prematurely.
    ///
    /// [resp]: https://docs.rs/http/latest/http/response/struct.Response.html
    pub fn send(&mut self, mut response: Response<Body>) -> Result<(), Error> {
        use DownstreamResponse::{Closed, Pending, Sent};

        filter_outgoing_headers(response.headers_mut());

        // Mark this `DownstreamResponse` as having been sent, and match on the previous value.
        match mem::replace(self, Sent) {
            Closed => panic!("downstream response channel was closed"),
            Pending(sender) => sender
                .send(response)
                .map_err(|_| ())
                .expect("response receiver is open"),
            Sent => return Err(Error::DownstreamRespSending),
        }

        Ok(())
    }

    /// Close the `DownstreamResponse`, potentially without sending any response.
    pub fn close(&mut self) {
        *self = DownstreamResponse::Closed;
    }
}
