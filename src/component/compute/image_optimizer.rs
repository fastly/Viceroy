use crate::component::bindings::fastly::compute::{
    http_body, http_req, http_resp, image_optimizer, types,
};
use crate::linking::ComponentCtx;
use wasmtime::component::Resource;

impl image_optimizer::Host for ComponentCtx {
    fn transform_image_optimizer_request(
        &mut self,
        _origin_image_request: Resource<http_req::Request>,
        _origin_image_request_body: Option<Resource<http_body::Body>>,
        _origin_image_request_backend: String,
        _io_transform_config: image_optimizer::ImageOptimizerTransformOptions,
    ) -> Result<http_resp::ResponseWithBody, types::Error> {
        Err(types::Error::Unsupported)
    }
}

impl image_optimizer::HostExtraImageOptimizerTransformOptions for ComponentCtx {
    fn drop(
        &mut self,
        _options: Resource<image_optimizer::ExtraImageOptimizerTransformOptions>,
    ) -> wasmtime::Result<()> {
        Ok(())
    }
}
