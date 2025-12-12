use crate::component::bindings::fastly::compute::{
    http_body, http_req, http_resp, image_optimizer, types,
};
use crate::session::Session;
use wasmtime::component::Resource;

pub(crate) fn transform_image_optimizer_request(
    _session: &mut Session,
    _origin_image_request: Resource<http_req::Request>,
    _origin_image_request_body: Option<Resource<http_body::Body>>,
    _origin_image_request_backend: &str,
    _io_transform_config: image_optimizer::ImageOptimizerTransformOptions,
) -> Result<http_resp::ResponseWithBody, types::Error> {
    Err(types::Error::Unsupported)
}
