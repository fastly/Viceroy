use fastly::Request;
use fastly::http::request::BotCategory;

fn main() {
    let client_req = Request::from_client();

    assert_eq!(client_req.get_bot_detected(), true);
    assert_eq!(client_req.get_bot_analyzed(), true);
    assert_eq!(client_req.get_bot_name(), Ok(Some("BadBot")));
    assert_eq!(client_req.get_bot_category(), Ok(Some("ai-crawler")));
    assert_eq!(client_req.get_bot_category_kind(), Some(BotCategory::AiCrawler));
    assert_eq!(client_req.get_bot_verified(), Some(true));
}
