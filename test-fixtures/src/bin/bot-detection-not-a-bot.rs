use fastly::Request;
use fastly_shared::FastlyStatus;
use fastly_sys::fastly_http_downstream as downstream;

fn main() {
    let client_req = Request::from_client();

    assert_eq!(client_req.get_bot_detected(), false);
    assert_eq!(client_req.get_bot_analyzed(), false);
    assert_eq!(client_req.get_bot_name(), Ok(None));
    assert_eq!(client_req.get_bot_category(), Ok(None));
    assert_eq!(client_req.get_bot_category_kind(), None);
    assert_eq!(client_req.get_bot_verified(), None);

    let (raw_req, _raw_body) = client_req.into_handles();
    let mut detected = 1;
    assert_eq!(
        unsafe {
            #[allow(deprecated)]
            downstream::downstream_bot_detected(raw_req.as_u32(), &mut detected)
        },
        FastlyStatus::OK
    );
    assert_eq!(detected, 0);

    let mut analyzed = 1;
    assert_eq!(
        unsafe {
            #[allow(deprecated)]
            downstream::downstream_bot_analyzed(raw_req.as_u32(), &mut analyzed)
        },
        FastlyStatus::OK
    );
    assert_eq!(analyzed, 0);

    let mut name_nwritten = 32;
    let mut name_out: Vec<u8> = Vec::with_capacity(32);
    assert_eq!(
        unsafe {
            #[allow(deprecated)]
            downstream::downstream_bot_name(
                raw_req.as_u32(),
                name_out.as_mut_ptr(),
                32,
                &mut name_nwritten,
            )
        },
        FastlyStatus::NONE
    );
    assert_eq!(name_nwritten, 32, "nwritten is untouched");

    let mut cat_nwritten = 32;
    let mut cat_out: Vec<u8> = Vec::with_capacity(32);
    assert_eq!(
        unsafe {
            #[allow(deprecated)]
            downstream::downstream_bot_category(
                raw_req.as_u32(),
                cat_out.as_mut_ptr(),
                32,
                &mut cat_nwritten,
            )
        },
        FastlyStatus::NONE
    );
    assert_eq!(cat_nwritten, 32, "nwritten is untouched");

    let mut cat_kind_out = 50000;
    assert_eq!(
        unsafe {
            #[allow(deprecated)]
            downstream::downstream_bot_category_kind(raw_req.as_u32(), &mut cat_kind_out)
        },
        FastlyStatus::NONE
    );
    assert_eq!(cat_kind_out, 50000);

    let mut verified = 10;
    assert_eq!(
        unsafe {
            #[allow(deprecated)]
            downstream::downstream_bot_verified(raw_req.as_u32(), &mut verified)
        },
        FastlyStatus::NONE
    );
    assert_eq!(verified, 10, "verified is untouched");
}
