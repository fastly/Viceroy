use derive_builder::Builder;
use derive_getters::Getters;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "lowercase")]
pub enum MessageType {
  Request,
  Response,
  Event
}

/// A message in the Debug Adapter Protocol format. The generic argument `P` describes
/// the type of the message payload (e.g. `Request<LaunchArguments>`)
#[derive(Serialize, Deserialize, Builder, Getters, Debug, Clone)]
pub struct ProtocolMessage<P> {
  // Sequence number (also known as message ID). For protocol messages of type
  // ['request'](MessageType::Request) this ID can be used to cancel the request.
  seq: u32,

  #[serde(rename="type")]
  message_type: MessageType,

  // The payload of the message. Flattened during (de)serialization so the
  // payload's fields are moved to the top level.
  #[serde(flatten)]
  payload: P
}

/// A request initiated by either the client or debug adapter. The generic argument
/// `P` describes the type of the request arguments.
#[derive(Serialize, Deserialize, Builder, Getters, Debug, Clone)]
pub struct Request<P> {
  command: String,

  arguments: P
}


/// A response to a request. The generic argument `P` describes the type of the response
/// body.
#[derive(Serialize, Deserialize, Builder, Getters, Debug, Clone)]
pub struct Response<P> {
  // The sequence number of the request that this response was triggered by.
  request_seq: u32,

  // The command originally requested
  command: String,

  success: bool,

  // Contains the error message is `success` is false
  #[builder(setter(into, strip_option), default)]
  message: Option<String>,

  body: P
}

/// An event produced by the debug adapter. The generic argument `P` describes the
/// type of the event body.
#[derive(Serialize, Deserialize, Builder, Getters, Debug, Clone)]
pub struct Event<P> {
  event: String,

  body: P
}
