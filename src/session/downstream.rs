//! Downstream response.

use {
    crate::{
        body::Body, downstream::DownstreamResponse, error::Error, headers::filter_outgoing_headers,
        pushpin::PushpinRedirectInfo, session::ViceroyResponseMetadata
    },
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
pub enum DownstreamResponseState {
    /// No channel to send the response has been opened yet.
    Closed,
    /// A channel has been opened, but no response has been sent yet.
    Pending(Sender<DownstreamResponse>),
    /// The guest has initiated a proxy to Pushpin; the response will come from there.
    RedirectingToPushpin,
    /// A response has already been sent downstream.
    Sent,
}

impl DownstreamResponseState {
    /// Open a channel to send a [`Response`][resp] downstream, given a [`oneshot::Sender`][sender].
    ///
    /// [resp]: https://docs.rs/http/latest/http/response/struct.Response.html
    /// [sender]: https://docs.rs/tokio/latest/tokio/sync/oneshot/struct.Sender.html
    pub fn new(sender: Sender<DownstreamResponse>) -> Self {
        DownstreamResponseState::Pending(sender)
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
        use DownstreamResponseState::{Closed, Pending, RedirectingToPushpin, Sent};

        let manual_framing_headers = response.extensions().get::<ViceroyResponseMetadata>()
            .map(|metadata| metadata.manual_framing_headers).unwrap_or(false);
        if !manual_framing_headers {
            filter_outgoing_headers(response.headers_mut());
        }

        // Supporting 103 Early Hints responses is currently infeasible, as Hyper does not
        // support sending multiple responses on a single connection. But we don't want
        // to generate errors for them either. Early Hints will be dropped, but logged
        // so that people will know they *did work*, even though they won't reach
        // the client.
        if response.status().as_u16() == 103 {
            // We'll do these at different log levels in case someone wants to squelch some.
            tracing::warn!(
                "Guest returned 103 Early Hints response which will not be sent to the client"
            );
            tracing::info!("{:#?}", response);
            return Ok(());
        }

        // Mark this `DownstreamResponse` as having been sent, and match on the previous value.
        match mem::replace(self, Sent) {
            Closed => panic!("downstream response channel was closed"),
            Pending(sender) => sender
                .send(DownstreamResponse::Http(response))
                .map_err(|_| ())
                .expect("response receiver is open"),
            Sent | RedirectingToPushpin => return Err(Error::DownstreamRespSending),
        }

        Ok(())
    }

    pub fn redirect_to_pushpin(&mut self, redirect_info: PushpinRedirectInfo) -> Result<(), Error> {
        use DownstreamResponseState::{Closed, Pending, RedirectingToPushpin, Sent};

        // Mark this `DownstreamResponse` as having been sent, and match on the previous value.
        match mem::replace(self, RedirectingToPushpin) {
            Closed => panic!("downstream response channel was closed"),
            Pending(sender) => sender
                .send(DownstreamResponse::RedirectToPushpin(redirect_info))
                .map_err(|_| ())
                .expect("response receiver is open"),
            Sent | RedirectingToPushpin => return Err(Error::DownstreamRespSending),
        }

        Ok(())
    }

    /// Close the `DownstreamResponse`, potentially without sending any response.
    #[allow(unused)]
    pub fn close(&mut self) {
        *self = DownstreamResponseState::Closed;
    }
}
