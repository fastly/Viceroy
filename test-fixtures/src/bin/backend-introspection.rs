use fastly::{Backend, Request, Response};

/// Report the host-visible properties of the `origin` backend back to the client, so that the same
/// accessors can be checked on both the core-wasm and component ABIs.
fn main() {
    let _client_req = Request::from_client();

    let backend = Backend::from_name("origin").expect("`origin` backend exists");

    let body = format!(
        "host={}\nport={}\nis_ssl={}\noverride_host={}\n",
        backend.get_host(),
        backend.get_port(),
        backend.is_ssl(),
        backend
            .get_host_override()
            .map(|host| host.to_str().expect("override host is valid UTF-8").to_owned())
            .unwrap_or_else(|| "<none>".to_owned()),
    );

    Response::from_body(body).send_to_client();
}
