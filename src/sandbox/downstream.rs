//! Downstream response.

use {
    crate::{
        body::Body, downstream::DownstreamResponse, error::Error, handoff::HandoffInfo,
    },
    hyper::http::response::Response,
    tokio::sync::mpsc::Sender,
};

/// Downstream response states.
///
/// See [`Sandbox::set_downstream_response_sender`][set] and
/// [`Sandbox::send_downstream_response`][send] for more information.
///
/// [send]: struct.Sandbox.html#method.send_downstream_response
/// [set]: struct.Sandbox.html#method.set_downstream_response_sender
pub enum DownstreamResponseState {
    /// A channel has been opened, but no response has been sent yet.
    Unsent(Sender<DownstreamResponse>),
    /// The guest has initiated a proxy to Pushpin; the response will come from there.
    HandingOffToPushpin,
    /// The guest has initiated a proxy to a Backend; the response will come from there.
    HandingOffToBackend,
    /// A response has already been sent downstream.
    Sent,
}

impl DownstreamResponseState {
    /// Open a channel to send a [`Response`][resp] downstream, given a [`oneshot::Sender`][sender].
    ///
    /// [resp]: https://docs.rs/http/latest/http/response/struct.Response.html
    /// [sender]: https://docs.rs/tokio/latest/tokio/sync/oneshot/struct.Sender.html
    pub fn new(sender: Sender<DownstreamResponse>) -> Self {
        DownstreamResponseState::Unsent(sender)
    }

    pub fn is_unsent(&self) -> bool {
        matches!(self, Self::Unsent(_))
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
    pub async fn send(&mut self, response: Response<Body>) -> Result<(), Error> {
        let Self::Unsent(sender) = self else {
            return Err(Error::DownstreamRespSending);
        };

        // Only 103 Early Hints responses are allowed to be sent by the guest.
        //
        // Other 1xx status codes are not allowed and generate an `InvalidArgument` error.
        if response.status().as_u16() == 103 {
            let _ = sender.send(DownstreamResponse::Http(response)).await;
            return Ok(());
        } else if response.status().is_informational() {
            return Err(Error::InvalidArgument);
        }

        // Mark this `DownstreamResponse` as having been sent, and match on the previous value.
        sender
            .send(DownstreamResponse::Http(response))
            .await
            .map_err(|_| ())
            .expect("response receiver is open");
        *self = Self::Sent;

        Ok(())
    }

    /// Ensure the downstream response sender is closed, and send the provided response if it
    /// isn't.
    pub fn send_close(&mut self, response: Response<Body>) {
        let Self::Unsent(sender) = self else {
            return;
        };

        let _ = sender.try_send(DownstreamResponse::Http(response));
        *self = Self::Sent;
    }

    pub async fn redirect_to_pushpin(&mut self, redirect_info: HandoffInfo) -> Result<(), Error> {
        let Self::Unsent(sender) = self else {
            return Err(Error::DownstreamRespSending);
        };

        // Send and transfer to `HandingOffToPushpin`:
        sender
            .send(DownstreamResponse::HandoffToPushpin(redirect_info))
            .await
            .map_err(|_| ())
            .expect("response receiver is open");
        *self = Self::HandingOffToPushpin;

        Ok(())
    }

    pub async fn redirect_to_backend(&mut self, redirect_info: HandoffInfo) -> Result<(), Error> {
        let Self::Unsent(sender) = self else {
            return Err(Error::DownstreamRespSending);
        };

        // Send and transfer to `HandingOffToBackend`:
        sender
            .send(DownstreamResponse::HandoffToBackend(redirect_info))
            .await
            .map_err(|_| ())
            .expect("response receiver is open");
        *self = Self::HandingOffToBackend;

        Ok(())
    }
}
