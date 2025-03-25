use super::fastly::api::{http_req, http_types, image_optimizer, types};
use crate::linking::ComponentCtx;

#[async_trait::async_trait]
impl image_optimizer::Host for ComponentCtx {
    async fn transform_image_optimizer_request(
        &mut self,
        _origin_image_request: http_req::RequestHandle,
        _origin_image_request_body: http_req::BodyHandle,
        _origin_image_request_backend: Vec<u8>,
        _io_transform_config_mask: image_optimizer::ImageOptimizerTransformConfigOptions,
        _io_transform_config: image_optimizer::ImageOptimizerTransformConfig,
        _io_error_detail: image_optimizer::ImageOptimizerErrorDetail,
    ) -> Result<http_types::Response, types::Error> {
        Err(types::Error::Unsupported)
    }
}