use fastly::handle::BodyHandle;
use fastly::http::StatusCode;
use fastly::security::{inspect, InspectConfig};
use fastly::{Error, Request, Response};

#[fastly::main]
fn main(req: Request) -> Result<Response, Error> {
    let (req, body) = req.into_handles();
    let body = body.unwrap_or_else(BodyHandle::new);

    let inspectconf = InspectConfig::new(&req, &body)
        .corp("junichi-lab")
        .workspace("lab");

    let resp = match inspect(inspectconf) {
        Ok(x) => {
            let body = format!(
                "inspect result: waf_response={}, tags={:?}, decision_ms={}ms, verdict={:?}",
                x.status(),
                x.tags(),
                x.decision_ms().as_millis(),
                x.verdict()
            );

            Response::from_status(StatusCode::OK).with_body_text_plain(&body)
        }
        Err(e) => {
            let body = format!("Error: {e:?}");

            Response::from_status(StatusCode::BAD_REQUEST).with_body_text_plain(&body)
        }
    };

    Ok(resp)
}
