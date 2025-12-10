use crate::component::bindings::fastly::adapter::adapter_abi;
use crate::linking::ComponentCtx;

impl adapter_abi::Host for ComponentCtx {
    fn init(&mut self) {}
}
