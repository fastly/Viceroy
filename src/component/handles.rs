// error[E0277]: the trait bound `wasmtime::component::Resource<component::fastly::api::http_req::RequestHandle>: From<wiggle_abi::types::RequestHandle>` is not satisfied

use crate::wiggle_abi::types::*;

/// Macro which provides the common implementation of a resource type.
macro_rules! resource_impl {
    ($entity:ident, $bindings_type:path) => {
        // Add convenient functions for converting to and from `Resource`s.
        impl From<$crate::component::component::Resource<$bindings_type>> for $entity {
            fn from(resource: $crate::component::component::Resource<$bindings_type>) -> Self {
                Self::from(resource.rep())
            }
        }

        impl From<$entity> for $crate::component::component::Resource<$bindings_type> {
            fn from(entity: $entity) -> $crate::component::component::Resource<$bindings_type> {
                crate::component::component::Resource::new_own(entity.into())
            }
        }
    };
}

resource_impl!(
    ConfigStoreHandle,
    crate::component::fastly::api::config_store::Handle
);

resource_impl!(
    DictionaryHandle,
    crate::component::fastly::api::dictionary::Handle
);

resource_impl!(
    AsyncItemHandle,
    crate::component::fastly::api::async_io::Handle
);

resource_impl!(
    RequestHandle,
    crate::component::fastly::api::http_req::RequestHandle
);

resource_impl!(
    ResponseHandle,
    crate::component::fastly::api::http_resp::ResponseHandle
);

resource_impl!(
    BodyHandle,
    crate::component::fastly::api::http_body::BodyHandle
);

resource_impl!(
    PendingRequestHandle,
    crate::component::fastly::api::http_req::PendingRequestHandle
);

resource_impl!(EndpointHandle, crate::component::fastly::api::log::Handle);

resource_impl!(
    PendingKvLookupHandle,
    crate::component::fastly::api::object_store::PendingLookupHandle
);

resource_impl!(
    PendingKvInsertHandle,
    crate::component::fastly::api::object_store::PendingInsertHandle
);

resource_impl!(
    PendingKvDeleteHandle,
    crate::component::fastly::api::object_store::PendingDeleteHandle
);

resource_impl!(
    KvStoreLookupHandle,
    crate::component::fastly::api::kv_store::LookupHandle
);

resource_impl!(
    KvStoreInsertHandle,
    crate::component::fastly::api::kv_store::InsertHandle
);

resource_impl!(
    KvStoreDeleteHandle,
    crate::component::fastly::api::kv_store::DeleteHandle
);

resource_impl!(
    KvStoreListHandle,
    crate::component::fastly::api::kv_store::ListHandle
);

resource_impl!(
    KvStoreHandle,
    crate::component::fastly::api::kv_store::Handle
);

resource_impl!(
    ObjectStoreHandle,
    crate::component::fastly::api::object_store::Handle
);

resource_impl!(
    SecretStoreHandle,
    crate::component::fastly::api::secret_store::StoreHandle
);

resource_impl!(
    SecretHandle,
    crate::component::fastly::api::secret_store::SecretHandle
);

resource_impl!(CacheHandle, crate::component::fastly::api::cache::Handle);

resource_impl!(
    CacheBusyHandle,
    crate::component::fastly::api::cache::BusyHandle
);

resource_impl!(
    CacheReplaceHandle,
    crate::component::fastly::api::cache::CacheReplaceHandle
);

resource_impl!(
    HttpCacheHandle,
    crate::component::fastly::api::http_cache::CacheHandle
);

resource_impl!(AclHandle, crate::component::fastly::api::acl::AclHandle);
