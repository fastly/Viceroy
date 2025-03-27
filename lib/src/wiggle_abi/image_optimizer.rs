use crate::error::{Error};
use crate::session::Session;
use crate::wiggle_abi::{fastly_image_optimizer, types};
use wiggle::{GuestMemory, GuestPtr};

#[wiggle::async_trait]
impl fastly_image_optimizer::FastlyImageOptimizer for Session {
    async fn transform_image_optimizer_request(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        _origin_image_request: types::RequestHandle,
        _origin_image_request_body: types::BodyHandle,
        _origin_image_request_backend: GuestPtr<str>,
        _io_transform_config_mask: types::ImageOptimizerTransformConfigOptions,
        _io_transform_config: GuestPtr<types::ImageOptimizerTransformConfig>,
        _io_error_detail: GuestPtr<types::ImageOptimizerErrorDetail>,
    ) -> Result<(types::ResponseHandle, types::BodyHandle), Error> {
        Err(Error::Unsupported {
            msg: "image optimizer unsupported in Viceroy",
        })
    }
}
