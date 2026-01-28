//! Downstream response.

use {
    crate::{
        body::Body,
        downstream::DownstreamResponse,
        error::Error,
        framing::{content_length_is_valid, transfer_encoding_is_supported},
        headers::filter_outgoing_headers,
        pushpin::PushpinRedirectInfo,
        session::ViceroyResponseMetadata,
        wiggle_abi::types::FramingHeadersMode,
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

        let mut framing_headers_mode = response
            .extensions()
            .get::<ViceroyResponseMetadata>()
            .map(|metadata: &ViceroyResponseMetadata| metadata.framing_headers_mode)
            .unwrap_or(FramingHeadersMode::Automatic);

        if framing_headers_mode == FramingHeadersMode::ManuallyFromHeaders {
            if !content_length_is_valid(response.headers()) {
                tracing::warn!("Downstream response has malformed Content-Length header, falling back to automatic framing.");
                framing_headers_mode = FramingHeadersMode::Automatic;
            } else if !transfer_encoding_is_supported(response.headers()) {
                tracing::warn!("Downstream response has unsupported Transfer-Encoding header, falling back to automatic framing.");
                framing_headers_mode = FramingHeadersMode::Automatic;
            } else if !response
                .headers()
                .contains_key(hyper::header::CONTENT_LENGTH)
                && !response
                    .headers()
                    .contains_key(hyper::header::TRANSFER_ENCODING)
            {
                tracing::warn!("Downstream response has neither Content-Length nor Transfer-Encoding header, falling back to automatic framing.");
                framing_headers_mode = FramingHeadersMode::Automatic;
            }
        }
        if framing_headers_mode != FramingHeadersMode::ManuallyFromHeaders {
            filter_outgoing_headers(response.headers_mut());
        }

        // Supporting 103 Early Hints responses is currently infeasible, as Hyper does not
        // support sending multiple responses on a single connection. But we don't want
        // to generate errors for them either. Early Hints will be dropped, but logged
        // so that people will know they *did work*, even though they won't reach
        // the client.
        //
        // Other 1xx status codes, however, are not allowed and generate an InvalidArgument
        // error.
        if response.status().as_u16() == 103 {
            // We'll do these at different log levels in case someone wants to squelch some.
            tracing::warn!(
                "Guest returned 103 Early Hints response which will not be sent to the client"
            );
            tracing::info!("{:#?}", response);
            return Ok(());
        } else if response.status().is_informational() {
            return Err(Error::InvalidArgument);
        }

        tracing::info!("send()");

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

        tracing::info!("redirect_to_pushpin()");

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
