use fastly::Request;

fn main() {
    let client_req = Request::from_client();

    // Check the result of fastly_key_is_valid based on the test scenario.
    // The test sends requests with different header values to verify behavior.
    let is_valid = client_req.fastly_key_is_valid();

    // Return the result as the response body so the integration test can check it.
    let body = format!("is_valid={}", is_valid);

    fastly::Response::from_body(body)
        .with_status(200)
        .send_to_client();
}
