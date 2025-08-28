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
    crate::component::fastly::compute::config_store::Store
);

resource_impl!(
    DictionaryHandle,
    crate::component::fastly::compute::dictionary::Dictionary
);

resource_impl!(
    AsyncItemHandle,
    crate::component::fastly::compute::async_io::Pollable
);

resource_impl!(
    RequestHandle,
    crate::component::fastly::compute::http_req::Request
);

resource_impl!(
    ResponseHandle,
    crate::component::fastly::compute::http_resp::Response
);

resource_impl!(
    BodyHandle,
    crate::component::fastly::compute::http_body::Body
);

resource_impl!(
    PendingRequestHandle,
    crate::component::fastly::compute::http_req::PendingRequest
);

resource_impl!(
    EndpointHandle,
    crate::component::fastly::compute::log::Endpoint
);

resource_impl!(
    KvStoreLookupHandle,
    crate::component::fastly::compute::kv_store::PendingLookup
);

resource_impl!(
    KvStoreInsertHandle,
    crate::component::fastly::compute::kv_store::PendingInsert
);

resource_impl!(
    KvStoreDeleteHandle,
    crate::component::fastly::compute::kv_store::PendingDelete
);

resource_impl!(
    KvStoreListHandle,
    crate::component::fastly::compute::kv_store::PendingList
);

resource_impl!(
    KvStoreHandle,
    crate::component::fastly::compute::kv_store::Store
);

resource_impl!(
    KvStoreHandle,
    crate::component::fastly::compute::object_store::Store
);

resource_impl!(
    PendingKvLookupHandle,
    crate::component::fastly::compute::object_store::PendingLookup
);

resource_impl!(
    PendingKvInsertHandle,
    crate::component::fastly::compute::object_store::PendingInsert
);

resource_impl!(
    PendingKvDeleteHandle,
    crate::component::fastly::compute::object_store::PendingDelete
);

resource_impl!(
    SecretStoreHandle,
    crate::component::fastly::compute::secret_store::Store
);

resource_impl!(
    SecretHandle,
    crate::component::fastly::compute::secret_store::Secret
);

resource_impl!(CacheHandle, crate::component::fastly::compute::cache::Entry);

resource_impl!(
    CacheBusyHandle,
    crate::component::fastly::compute::cache::PendingEntry
);

resource_impl!(
    CacheReplaceHandle,
    crate::component::fastly::compute::cache::ReplaceEntry
);

resource_impl!(
    HttpCacheHandle,
    crate::component::fastly::compute::http_cache::Entry
);

resource_impl!(AclHandle, crate::component::fastly::compute::acl::Acl);

resource_impl!(
    RequestPromiseHandle,
    crate::component::fastly::compute::http_downstream::RequestPromise
);
