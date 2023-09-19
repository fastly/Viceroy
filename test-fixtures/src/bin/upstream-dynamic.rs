use fastly::experimental::BackendCreationError;
use fastly::{Backend, Error, Request, Response};

/// Pass everything from the downstream request through to the backend, then pass everything back
/// from the upstream request to the downstream response.
fn main() -> Result<(), Error> {
    let client_req = Request::from_client();

    let backend = if let Some(dynamic_string) = client_req.get_header_str("Dynamic-Backend") {
        let mut basic_builder = Backend::builder("dynamic-backend", dynamic_string);

        if let Some(override_host) = client_req.get_header_str("With-Override") {
            basic_builder = basic_builder.override_host(override_host);
        }

        match basic_builder.finish() {
            Ok(x) => x,
            Err(err) => {
                match err {
                    BackendCreationError::Disallowed => Response::from_status(403).send_to_client(),
                    BackendCreationError::NameInUse => Response::from_status(409).send_to_client(),
                    _ => Response::from_status(500).send_to_client(),
                }

                return Ok(());
            }
        }
    } else if let Some(static_string) = client_req.get_header_str("Static-Backend") {
        Backend::from_name(static_string)?
    } else {
        panic!("Couldn't find a backend to use!");
    };

    if let Some(supplementary_backend) = client_req.get_header_str("Supplementary-Backend") {
        match Backend::builder(supplementary_backend, "fastly.com").finish() {
            Ok(_) => {}
            Err(err) => {
                match err {
                    BackendCreationError::Disallowed => Response::from_status(403).send_to_client(),
                    BackendCreationError::NameInUse => Response::from_status(409).send_to_client(),
                    _ => Response::from_status(500).send_to_client(),
                }

                return Ok(());
            }
        }
    }

    client_req
        .send(backend)
        .unwrap_or_else(|_| Response::from_status(503))
        .send_to_client();

    Ok(())
}
