use crate::{
    common::{Test, TestResult},
    viceroy_test,
};
use hyper::{Request, Response, StatusCode};

viceroy_test!(vcpu_time_getter_works, |is_component| {
    let req = Request::get("/")
        .header("Accept", "text/html")
        .body("Hello, world!")
        .unwrap();

    let resp = Test::using_fixture("vcpu_time_test.wasm")
        .adapt_component(is_component)
        .backend("slow-server", "/", None, |_| {
            std::thread::sleep(std::time::Duration::from_millis(3000));
            Response::builder()
                .status(StatusCode::OK)
                .body(vec![])
                .unwrap()
        })
        .await
        .against(req)
        .await?;

    println!("resp.status() = {}", resp.status());
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
});
