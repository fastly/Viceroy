use std::{
    io::{self, BufRead, Read, StdinLock, StdoutLock, Write},
    net::SocketAddr,
};

use dap_types::{
    requests::{Capabilities, InitializeRequestPayload, LaunchRequestPayload},
    MessageType, ProtocolMessage, ProtocolMessageBuilder, Request, Response, ResponseBuilder,
};
use serde::Serialize;
use tokio::task::JoinHandle;
use tracing::{event, Level};
use viceroy_lib::{Error, ExecuteCtx, ViceroyService};

/// The debug adapter serves a TCP socket on the given address and listens for Debug Adapter Protocol
/// messages. These messages control the execution of the wrapped Viceroy Service.
///
/// Viceroy does not yet support debugging but this functionality is enough to allow it to be run
/// and inspected from within IDEs.
pub struct DebugAdapter {
    ctx: ExecuteCtx,
    app_address: SocketAddr,
}

impl DebugAdapter {
    pub fn new(ctx: ExecuteCtx, app_address: SocketAddr) -> Self {
        Self { ctx, app_address }
    }

    pub fn serve(self) -> Result<(), Error> {
        let stdin = io::stdin();
        let stdout = io::stdout();

        let mut session = DebugSession {
            stdin: stdin.lock(),
            stdout: stdout.lock(),
            sequence: 1,
            server: None,
        };

        // message parsing loop
        loop {
            let mut content_length: usize = 0;

            // header parsing loop
            while let Some((key, value)) = session.read_header()? {
                match key.as_str() {
                    "Content-Length" => {
                        content_length = value
                            .parse::<usize>()
                            .expect("invalid Content-Length header");
                    }
                    _ => {
                        println!("Received unsupported DAP header: {}", key);
                    }
                }
            }

            let mut data: Vec<u8> = vec![0; content_length];
            session.stdin.read_exact(&mut data)?;

            // If this is the first message, it should be an initialize request
            if session.sequence == 1 {
                // parse request
                let init: ProtocolMessage<Request<InitializeRequestPayload>> =
                    serde_json::from_slice(&data).expect("could not parse initial request");
                println!("Client is {}", init.payload().arguments().client_name());

                // build capabilities response
                let resp: ProtocolMessage<Response<Capabilities>> =
                    ProtocolMessageBuilder::default()
                        .message_type(MessageType::Response)
                        .seq(session.sequence)
                        .payload(
                            ResponseBuilder::default()
                                .request_seq(*init.seq())
                                .success(true)
                                .command(init.payload().command().to_string())
                                .body(Capabilities::default())
                                .build()
                                .unwrap(),
                        )
                        .build()
                        .unwrap();

                println!("{}", serde_json::to_string_pretty(&resp).unwrap());

                // send capabilities response
                session.send_message(resp)?;
            } else {
                // extract command from data
                let request_data: serde_json::Map<String, serde_json::Value> =
                    serde_json::from_slice(&data).expect("could not parse message");
                let command = request_data
                    .get("command")
                    .unwrap()
                    .as_str()
                    .expect("expected request to contain 'command'");

                // parse message into expected struct
                // TODO: implement Launch, Terminate, and Restart
                match command {
                    "launch" => {
                        let req: ProtocolMessage<Request<LaunchRequestPayload>> =
                            serde_json::from_value(serde_json::Value::Object(request_data))
                                .expect("could not parse launch request");

                        event!(Level::INFO, "received launch command");

                        if session.server.is_some() {
                            event!(
                                Level::WARN,
                                "received launch command but server is already running"
                            );
                            continue;
                        }

                        let address = self.app_address;
                        let ctx = self.ctx.clone();

                        session.server = Some(tokio::task::spawn(async move {
                            let service = ViceroyService::new(ctx);
                            service.serve(address).await.expect("failed to serve app");
                        }));

                        // We use `Option<u8>` as the generic type for the payload, as the launch response does not have a payload
                        let resp: ProtocolMessage<Response<Option<u8>>> =
                            ProtocolMessageBuilder::default()
                                .message_type(MessageType::Response)
                                .seq(session.sequence)
                                .payload(
                                    ResponseBuilder::default()
                                        .request_seq(*req.seq())
                                        .success(true)
                                        .command(req.payload().command().to_string())
                                        .body(None)
                                        .build()
                                        .unwrap(),
                                )
                                .build()
                                .unwrap();

                        session.send_message(resp)?;
                    }
                    "disconnect" => {
                        event!(Level::INFO, "received disconnect command");
                        break;
                    }
                    _ => {
                        event!(Level::WARN, "received unsupported command: {}", command);
                    }
                }
            }
        }

        Ok(())
    }
}

struct DebugSession<'a> {
    stdin: StdinLock<'a>,
    stdout: StdoutLock<'a>,
    sequence: u32,
    server: Option<JoinHandle<()>>,
}

impl<'a> DebugSession<'a> {
    fn start(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn read_header(&mut self) -> Result<Option<(String, String)>, Error> {
        // Read up to newline
        let mut header_bytes: Vec<u8> = vec![];
        self.stdin.read_until(0x0A, &mut header_bytes)?;

        // If there are no more headers, the remaining data should just be a carriage return
        if header_bytes.len() == 2 {
            return Ok(None);
        }

        assert_eq!(
            header_bytes.pop(),
            Some(0x0A),
            "DAP header should be terminated with \\r\\n"
        );
        assert_eq!(
            header_bytes.pop(),
            Some(0x0D),
            "DAP header should be terminated with \\r\\n"
        );

        let header =
            String::from_utf8(header_bytes).expect("invalid DAP header received. expected UTF-8");

        let (key, value) = header.split_at(header.find(": ").expect("invalid DAP header format"));

        println!("header! key: {}, value{}", key, value);

        Ok(Some((key.to_string(), value[2..value.len()].to_string())))
    }

    fn send_message<T>(&mut self, message: ProtocolMessage<T>) -> Result<(), Error>
    where
        T: Serialize,
    {
        self.sequence += 1;
        let json = serde_json::to_string(&message).expect("could not serialize response");
        let headers = "Content-Length: ".to_string() + &json.len().to_string() + "\r\n\r\n";

        let header_bytes = headers.as_bytes();
        self.stdout.write_all(header_bytes)?;
        self.stdout.write_all(json.as_bytes())?;
        println!("Sent message {:?}", message.message_type());
        Ok(())
    }
}
