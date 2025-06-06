use super::fastly::api::{http_body, http_req, http_resp, image_optimizer, types};
use crate::component::component::Resource;
use crate::linking::ComponentCtx;

#[async_trait::async_trait]
impl image_optimizer::Host for ComponentCtx {
    async fn transform_image_optimizer_request(
        &mut self,
        _origin_image_request: Resource<http_req::RequestHandle>,
        _origin_image_request_body: Option<Resource<http_body::BodyHandle>>,
        _origin_image_request_backend: String,
        _io_transform_config_mask: image_optimizer::ImageOptimizerTransformConfigOptions,
        _io_transform_config: image_optimizer::ImageOptimizerTransformConfig,
        _io_error_detail: image_optimizer::ImageOptimizerErrorDetail,
    ) -> Result<http_resp::Response, types::Error> {
        Err(types::Error::Unsupported)
    }
}
