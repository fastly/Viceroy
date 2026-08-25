use fastly::Request;
use fastly::http::request::BotCategory;
use fastly_shared::FastlyStatus;
use fastly_sys::fastly_http_downstream as downstream;

fn main() {
    let client_req = Request::from_client();

    assert_eq!(client_req.get_bot_detected(), true);
    assert_eq!(client_req.get_bot_analyzed(), true);
    assert_eq!(client_req.get_bot_name(), Ok(Some("BadBot")));
    assert_eq!(client_req.get_bot_category(), Ok(Some("ai-crawler")));
    assert_eq!(
        client_req.get_bot_category_kind(),
        Some(BotCategory::AiCrawler)
    );
    assert_eq!(client_req.get_bot_verified(), Some(true));

    let (raw_req, _raw_body) = client_req.into_handles();
    let mut detected = 0;
    assert_eq!(
        unsafe {
            #[allow(deprecated)]
            downstream::downstream_bot_detected(raw_req.as_u32(), &mut detected)
        },
        FastlyStatus::OK
    );
    assert_eq!(detected, 1);
    
    let mut analyzed = 0;
    assert_eq!(
        unsafe {
            #[allow(deprecated)]
            downstream::downstream_bot_analyzed(raw_req.as_u32(), &mut analyzed)
        },
        FastlyStatus::OK
    );
    assert_eq!(analyzed, 1);
    
    let mut name_nwritten = 0;
    let mut name_out: Vec<u8> = Vec::with_capacity(32);
    assert_eq!(
        unsafe {
            #[allow(deprecated)]
            downstream::downstream_bot_name(raw_req.as_u32(), name_out.as_mut_ptr(), 32, &mut name_nwritten)
        },
        FastlyStatus::OK
    );
    unsafe { name_out.set_len(name_nwritten); }
    assert_eq!(name_nwritten, "BadBot".len());
    assert_eq!(String::from_utf8(name_out).unwrap(), "BadBot".to_string());
    
    let mut cat_nwritten = 0;
    let mut cat_out: Vec<u8> = Vec::with_capacity(32);
    assert_eq!(
        unsafe {
            #[allow(deprecated)]
            downstream::downstream_bot_category(raw_req.as_u32(), cat_out.as_mut_ptr(), 32, &mut cat_nwritten)
        },
        FastlyStatus::OK
    );
    unsafe { cat_out.set_len(cat_nwritten); }
    assert_eq!(cat_nwritten, "ai-crawler".len());
    assert_eq!(String::from_utf8(cat_out).unwrap(), "ai-crawler".to_string());
    
    let mut cat_kind_out = u32::MAX;
    assert_eq!(
        unsafe {
            #[allow(deprecated)]
            downstream::downstream_bot_category_kind(raw_req.as_u32(), &mut cat_kind_out)
        },
        FastlyStatus::OK
    );
    assert_eq!(cat_kind_out, BotCategory::AiCrawler as u32);

    let mut verified = 0;
    assert_eq!(
        unsafe {
            #[allow(deprecated)]
            downstream::downstream_bot_verified(raw_req.as_u32(), &mut verified)
        },
        FastlyStatus::OK
    );
    assert_eq!(verified, 1);
}
