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
    crate::component::bindings::fastly::compute::config_store::Store
);

resource_impl!(
    DictionaryHandle,
    crate::component::bindings::fastly::compute::dictionary::Dictionary
);

resource_impl!(
    AsyncItemHandle,
    crate::component::bindings::fastly::compute::async_io::Pollable
);

resource_impl!(
    RequestHandle,
    crate::component::bindings::fastly::compute::http_req::Request
);

resource_impl!(
    ResponseHandle,
    crate::component::bindings::fastly::compute::http_resp::Response
);

resource_impl!(
    BodyHandle,
    crate::component::bindings::fastly::compute::http_body::Body
);

resource_impl!(
    PendingRequestHandle,
    crate::component::bindings::fastly::compute::http_req::PendingRequest
);

resource_impl!(
    EndpointHandle,
    crate::component::bindings::fastly::compute::log::Endpoint
);

resource_impl!(
    KvStoreLookupHandle,
    crate::component::bindings::fastly::compute::kv_store::PendingLookup
);

resource_impl!(
    KvStoreInsertHandle,
    crate::component::bindings::fastly::compute::kv_store::PendingInsert
);

resource_impl!(
    KvStoreDeleteHandle,
    crate::component::bindings::fastly::compute::kv_store::PendingDelete
);

resource_impl!(
    KvStoreListHandle,
    crate::component::bindings::fastly::compute::kv_store::PendingList
);

resource_impl!(
    KvStoreHandle,
    crate::component::bindings::fastly::compute::kv_store::Store
);

resource_impl!(
    SecretStoreHandle,
    crate::component::bindings::fastly::compute::secret_store::Store
);

resource_impl!(
    SecretHandle,
    crate::component::bindings::fastly::compute::secret_store::Secret
);

resource_impl!(
    CacheHandle,
    crate::component::bindings::fastly::compute::cache::Entry
);

resource_impl!(
    CacheBusyHandle,
    crate::component::bindings::fastly::compute::cache::PendingEntry
);

resource_impl!(
    CacheReplaceHandle,
    crate::component::bindings::fastly::compute::cache::ReplaceEntry
);

resource_impl!(
    HttpCacheHandle,
    crate::component::bindings::fastly::compute::http_cache::Entry
);

resource_impl!(
    AclHandle,
    crate::component::bindings::fastly::compute::acl::Acl
);

resource_impl!(
    RequestPromiseHandle,
    crate::component::bindings::fastly::compute::http_downstream::RequestPromise
);
