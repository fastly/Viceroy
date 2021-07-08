use crate::{body::Body, streaming_body::StreamingBody};

/// Represents either a full body, or the write end of a streaming body.
///
/// This enum is needed because we reuse the handle for a body when it is transformed into a streaming
/// body (writeable only). It is used within the body handle map in `Session`.
#[derive(Debug)]
pub enum BodyVariant {
    Body(Body),
    Streaming(StreamingBody),
}

impl BodyVariant {
    pub fn is_streaming(&self) -> bool {
        matches!(self, Self::Streaming(_))
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
            Self::Streaming(sender) => Some(sender),
            _ => None,
        }
    }

    pub fn into_streaming(self) -> Option<StreamingBody> {
        match self {
            Self::Streaming(streaming) => Some(streaming),
            _ => None,
        }
    }

    pub fn begin_streaming(&mut self) -> Option<Body> {
        if self.is_streaming() {
            return None;
        }

        let (streaming, receiver) = StreamingBody::new();
        if let Self::Body(mut body) = std::mem::replace(self, Self::Streaming(streaming)) {
            body.push_back(receiver);
            Some(body)
        } else {
            unreachable!("!self.is_streaming, but was actually streaming");
        }
    }
}
