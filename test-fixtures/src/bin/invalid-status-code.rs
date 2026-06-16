use fastly::{Error, Request, Response};

#[fastly::main]
fn main(_req: Request) -> Result<Response, Error> {
    Ok(Response::from_status(101).with_body("This should cause an error"))
}
