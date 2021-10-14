use crate::{body::Body, streaming_body::StreamingBody, upstream::PendingRequest};

/// Represents either a full body, or the write end of a streaming body.
///
/// This enum is needed because we reuse the handle for a body when it is transformed into a streaming
/// body (writeable only). It is used within the body handle map in `Session`.
#[derive(Debug)]
pub enum AsyncItem {
    Body(Body),
    StreamingBody(StreamingBody),
    PendingReq(PendingRequest),
}

impl AsyncItem {
    pub fn is_streaming(&self) -> bool {
        matches!(self, Self::StreamingBody(_))
    }

    pub fn as_body(&self) -> Option<&Body> {
        match self {
            Self::Body(body) => Some(body),
            _ => None,
        }
    }

    pub fn as_body_mut(&mut self) -> Option<&mut Body> {
        match self {
            Self::Body(body) => Some(body),
            _ => None,
        }
    }

    pub fn into_body(self) -> Option<Body> {
        match self {
            Self::Body(body) => Some(body),
            _ => None,
        }
    }

    pub fn as_streaming_mut(&mut self) -> Option<&mut StreamingBody> {
        match self {
            Self::StreamingBody(sender) => Some(sender),
            _ => None,
        }
    }

    pub fn into_streaming(self) -> Option<StreamingBody> {
        match self {
            Self::StreamingBody(streaming) => Some(streaming),
            _ => None,
        }
    }

    pub fn begin_streaming(&mut self) -> Option<Body> {
        if self.is_streaming() {
            return None;
        }

        let (streaming, receiver) = StreamingBody::new();
        if let Self::Body(mut body) = std::mem::replace(self, Self::StreamingBody(streaming)) {
            body.push_back(receiver);
            Some(body)
        } else {
            unreachable!("!self.is_streaming, but was actually streaming");
        }
    }

    pub fn as_pending_req(&self) -> Option<&PendingRequest> {
        match self {
            Self::PendingReq(req) => Some(req),
            _ => None,
        }
    }

    pub fn as_pending_req_mut(&mut self) -> Option<&mut PendingRequest> {
        match self {
            Self::PendingReq(req) => Some(req),
            _ => None,
        }
    }

    pub fn into_pending_req(self) -> Option<PendingRequest> {
        match self {
            Self::PendingReq(req) => Some(req),
            _ => None,
        }
    }
}
