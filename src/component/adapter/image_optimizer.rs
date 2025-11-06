use crate::component::bindings::fastly::adapter::adapter_image_optimizer;
use crate::component::bindings::fastly::compute::types;
use crate::linking::ComponentCtx;

use wasmtime::component::Resource;

impl adapter_image_optimizer::Host for ComponentCtx {
    fn transform_image_optimizer_request(
        &mut self,
        origin_image_request: Resource<adapter_image_optimizer::Request>,
        origin_image_request_body: Option<Resource<adapter_image_optimizer::Body>>,
        customer_backend_name: String,
        io_transform_config: adapter_image_optimizer::ImageOptimizerTransformOptions,
    ) -> Result<adapter_image_optimizer::ResponseWithBody, types::Error> {
        crate::component::image_optimizer::transform_image_optimizer_request(
            &mut self.session,
            origin_image_request,
            origin_image_request_body,
            &customer_backend_name,
            io_transform_config,
        )
    }
}
