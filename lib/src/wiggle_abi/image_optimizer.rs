use crate::error::{Error, HandleError};
use crate::session::Session;
use crate::wiggle_abi::{fastly_image_optimizer, types};

#[wiggle::async_trait]
impl fastly_image_optimizer::FastlyImageOptimizer for Session {
    fn transform_image_optimizer_request(
        &mut self,
        _origin_image_request: http_req::RequestHandle,
        _origin_image_request_body: http_req::BodyHandle,
        _origin_image_request_backend: Vec<u8>,
        _io_transform_config_mask: image_optimizer::ImageOptimizerTransformConfigOptions,
        _io_transform_config: image_optimizer::ImageOptimizerTransformConfig,
        _io_error_detail: image_optimizer::ImageOptimizerErrorDetail,
    ) -> Result<http_req::Response, types::Error> {
        Err(types::Error::Unsupported)
    }
}