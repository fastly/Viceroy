use fastly::Request;

fn main() {
    let client_req = Request::from_client();

    assert_eq!(client_req.get_bot_detected(), false);
    assert_eq!(client_req.get_bot_analyzed(), false);
    assert_eq!(client_req.get_bot_name(), Ok(None));
    assert_eq!(client_req.get_bot_category(), Ok(None));
    assert_eq!(client_req.get_bot_category_kind(), None);
    assert_eq!(client_req.get_bot_verified(), None);
}
