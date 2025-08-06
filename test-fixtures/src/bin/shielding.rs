use fastly::{shielding::Shield, Error, Request, Response};
use http::StatusCode;

#[fastly::main]
fn main(request: Request) -> Result<Response, Error> {
    let Some(shield_name) = request.get_header_str("shield") else {
        return Ok(
            Response::from_status(StatusCode::BAD_REQUEST).with_body("No 'shield' header found")
        );
    };

    let Ok(shield) = Shield::new(shield_name) else {
        return Ok(Response::from_status(StatusCode::INTERNAL_SERVER_ERROR)
            .with_body(format!("Invalid shield name '{shield_name}'")));
    };

    match request.get_path() {
        "/is-shield" => {
            Ok(Response::from_status(StatusCode::OK).with_body(shield.running_on().to_string()))
        }

        "/shield-to" => {
            let Some(shield_type) = request.get_header_str("shield-type") else {
                return Ok(Response::from_status(StatusCode::CONFLICT)
                    .with_body("No 'shield-type' header found"));
            };

            if shield_type != "unencrypted" && shield_type != "encrypted" {
                return Ok(Response::from_status(StatusCode::NOT_ACCEPTABLE)
                    .with_body("Invalid 'shield-type' header found"));
            }

            let backend = if shield_type == "unencrypted" {
                shield.unencrypted_backend().unwrap()
            } else {
                shield.encrypted_backend().unwrap()
            };

            request.send(backend).map_err(Into::into)
        }

        _ => Ok(Response::from_status(StatusCode::NOT_FOUND)),
    }
}
