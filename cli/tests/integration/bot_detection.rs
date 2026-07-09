use {
    crate::{
        common::{Test, TestResult},
        viceroy_test,
    },
    hyper::{Request, StatusCode},
};

viceroy_test!(bot_detection_not_a_bot, |is_component| {
    let req = Request::get("/").body("Hello, world!")?;
    let resp = Test::using_fixture("bot-detection-not-a-bot.wasm")
        .adapt_component(is_component)
        .against(req)
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
});

viceroy_test!(bot_detection_got_a_bot, |is_component| {
    let req = Request::get("/")
        .header("X-Fastly-Bot-Analyzed", "true")
        .header("X-Fastly-Bot-Detected", "true")
        .header("X-Fastly-Bot-Name", "BadBot")
        .header("X-Fastly-Bot-Category", "ai-crawler")
        .header("X-Fastly-Bot-Verified", "true")
        .body("Hello, world!")?;
    let resp = Test::using_fixture("bot-detection-got-a-bot.wasm")
        .adapt_component(is_component)
        .against(req)
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
});
