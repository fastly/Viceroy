use std::{
    io::{self, BufRead, Read, StdinLock, StdoutLock, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
};

use dap_types::{
    events::{OutputEvent, OutputEventBuilder},
    requests::{Capabilities, CapabilitiesBuilder, InitializeRequestPayload},
    Event, EventBuilder, MessageType, ProtocolMessage, ProtocolMessageBuilder, Request, Response,
    ResponseBuilder,
};
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;
use tracing::{event, Level};
use viceroy_lib::{Error, ExecuteCtx, ViceroyService};

/// The debug adapter serves a TCP socket on the given address and listens for Debug Adapter Protocol
/// messages. These messages control the execution of the wrapped Viceroy Service.
///
/// Viceroy does not yet support debugging but this functionality is enough to allow it to be run
/// and inspected from within IDEs.
pub struct DebugAdapter {
    configure_ctx: Box<dyn Fn(ExecuteCtx) -> ExecuteCtx>,
}

impl DebugAdapter {
    pub fn new(configure_ctx: Box<dyn Fn(ExecuteCtx) -> ExecuteCtx>) -> Self {
        Self { configure_ctx }
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
                                .body(
                                    CapabilitiesBuilder::default()
                                        .supports_terminate_request(true)
                                        .supports_restart_request(false)
                                        .build()
                                        .unwrap(),
                                )
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

                // debugging
                {
                    let mut file = std::fs::OpenOptions::new()
                        .write(true)
                        .append(true)
                        .open("/Users/kailan/Desktop/request.json")
                        .unwrap();

                    if let Err(e) = writeln!(
                        file,
                        "{}",
                        serde_json::to_string_pretty(&request_data).unwrap()
                    ) {
                        eprintln!("Couldn't write to file: {}", e);
                    }
                }

                match command {
                    "launch" => {
                        let req: ProtocolMessage<Request<ViceroyLaunchRequestPayload>> =
                            serde_json::from_value(serde_json::Value::Object(request_data))
                                .expect("could not parse launch request");

                        event!(
                            Level::INFO,
                            "received launch command for project {}",
                            req.payload().arguments().project
                        );

                        if session.server.is_some() {
                            event!(
                                Level::WARN,
                                "received launch command but server is already running"
                            );
                            continue;
                        }

                        let project_path = Path::new(&req.payload().arguments().project);
                        let binary_path = project_path.join("bin/main.wasm");

                        let address = SocketAddr::new(
                            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                            req.payload().arguments().port,
                        );

                        session.send_output(
                            "console",
                            "Loading Wasm binary...",
                        )?;

                        session.send_output(
                            "important",
                            "Debugging for Compute@Edge is currently in development. Please file issue reports at https://github.com/fastly/fastly-vscode.",
                        )?;

                        let ctx = (self.configure_ctx)(ExecuteCtx::new(binary_path)?);

                        session.send_output(
                            "console",
                            &format!("Starting Compute@Edge server at http://{}", address),
                        )?;

                        // Start the Viceroy server within a tokio task so we can continue to process DAP messages.
                        // The task's `JoinHandle` is stored to be able to terminate the server later.
                        session.server = Some(tokio::task::spawn(async move {
                            // TODO: set up event bus so we can register hooks for events within the runtime, e.g. logging.
                            //
                            // This is also a step towards separating fiddle-compute-runtime from Viceroy.
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
                    "terminate" => {
                        event!(Level::INFO, "received terminate command");

                        if let Some(handle) = session.server {
                            handle.abort();
                            session.server = None;
                        } else {
                            event!(
                                Level::WARN,
                                "received terminate command but server is not running"
                            );
                        }

                        break;
                    }
                    "disconnect" => {
                        event!(Level::INFO, "received disconnect command");

                        if let Some(handle) = session.server {
                            handle.abort();
                            session.server = None;
                        }

                        break;
                    }
                    _ => {
                        event!(Level::WARN, "received unsupported command: {}", command);

                        session.send_output(
                            "console",
                            &format!("Unsupported debugger command: {}", command),
                        )?;
                    }
                }
            }
        }

        Ok(())
    }
}

#[derive(Deserialize)]
struct ViceroyLaunchRequestPayload {
    port: u16,
    project: String,
}

struct DebugSession<'a> {
    stdin: StdinLock<'a>,
    stdout: StdoutLock<'a>,
    sequence: u32,
    server: Option<JoinHandle<()>>,
}

impl<'a> DebugSession<'a> {
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

    fn send_output<T>(&mut self, category: T, output: T) -> Result<(), Error>
    where
        std::string::String: std::convert::From<T>,
    {
        let event: ProtocolMessage<Event<OutputEvent>> = ProtocolMessageBuilder::default()
            .message_type(MessageType::Event)
            .seq(self.sequence)
            .payload(
                EventBuilder::default()
                    .event("output".into())
                    .body(
                        OutputEventBuilder::default()
                            .category(category.into())
                            .output(output.into())
                            .build()
                            .unwrap(),
                    )
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        self.send_message(event)
    }
}
