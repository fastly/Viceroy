use std::time::Duration;

use crate::component::bindings::fastly::compute::{http_body, http_downstream, http_req, types};
use crate::component::compute::headers::get_names;
use crate::error::Error;
use crate::linking::{ComponentCtx, SandboxView};
use crate::sandbox::Sandbox;
use crate::wiggle_abi::types::RequestPromiseHandle;
use wasmtime::component::Resource;
use wasmtime_wasi_io::IoView;

impl http_downstream::Host for ComponentCtx {
    async fn next_request(
        &mut self,
        options: http_downstream::NextRequestOptions,
    ) -> Result<Resource<http_downstream::PendingRequest>, types::Error> {
        let timeout = options.timeout_ms.map(Duration::from_millis);
        let handle = self
            .sandbox_mut()
            .register_pending_downstream_req(timeout)
            .await?;

        let handle = RequestPromiseHandle::from(handle);

        Ok(handle.into())
    }

    async fn await_request(
        &mut self,
        handle: Resource<http_downstream::PendingRequest>,
    ) -> Result<Option<(Resource<http_req::Request>, Resource<http_body::Body>)>, types::Error>
    {
        let handle = RequestPromiseHandle::from(handle).into();
        let Some((req, body)) = self.sandbox_mut().await_downstream_req(handle).await? else {
            return Ok(None);
        };

        Ok(Some((req.into(), body.into())))
    }

    fn downstream_client_ip_addr(
        &mut self,
        h: Resource<http_req::Request>,
    ) -> Option<types::IpAddress> {
        self.sandbox()
            .downstream_client_ip(h.into())
            .ok()?
            .map(|ip| ip.into())
    }

    fn downstream_server_ip_addr(
        &mut self,
        h: Resource<http_req::Request>,
    ) -> Option<types::IpAddress> {
        self.sandbox()
            .downstream_server_ip(h.into())
            .ok()?
            .map(|ip| ip.into())
    }

    fn downstream_client_ddos_detected(
        &mut self,
        _h: Resource<http_req::Request>,
    ) -> Result<bool, types::Error> {
        Ok(false)
    }

    fn downstream_tls_cipher_openssl_name(
        &mut self,
        h: Resource<http_req::Request>,
        _max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        Ok(self.sandbox().absent_metadata_value(h)?)
    }

    fn downstream_tls_protocol(
        &mut self,
        h: Resource<http_req::Request>,
        _max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        Ok(self.sandbox().absent_metadata_value(h)?)
    }

    fn downstream_tls_client_servername(
        &mut self,
        h: Resource<http_req::Request>,
        _max_len: u64,
    ) -> Result<Option<String>, types::Error> {
        self.sandbox().absent_metadata_value(h).map_err(Into::into)
    }

    fn downstream_tls_client_hello(
        &mut self,
        h: Resource<http_req::Request>,
        _max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        Ok(self.sandbox().absent_metadata_value(h)?)
    }

    fn downstream_tls_raw_client_certificate(
        &mut self,
        h: Resource<http_req::Request>,
        _max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        Ok(self.sandbox().absent_metadata_value(h)?)
    }

    fn downstream_tls_client_cert_verify_result(
        &mut self,
        h: Resource<http_req::Request>,
    ) -> Result<Option<http_req::ClientCertVerifyResult>, types::Error> {
        Ok(self.sandbox().absent_metadata_value(h)?)
    }

    fn downstream_tls_ja3_md5(
        &mut self,
        h: Resource<http_req::Request>,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        Ok(self.sandbox().absent_metadata_value(h)?)
    }

    fn downstream_client_h2_fingerprint(
        &mut self,
        h: Resource<http_req::Request>,
        _max_len: u64,
    ) -> Result<String, types::Error> {
        Ok(self
            .sandbox()
            .absent_metadata_value(h)?
            .ok_or(Error::MissingDownstreamMetadata)?)
    }

    fn downstream_client_request_id(
        &mut self,
        h: Resource<http_req::Request>,
        max_len: u64,
    ) -> Result<String, types::Error> {
        let reqid = self
            .sandbox()
            .downstream_request_id(h.into())?
            .ok_or(Error::MissingDownstreamMetadata)?;
        let result = format!("{:032x}", reqid);

        if result.len() > usize::try_from(max_len).unwrap() {
            return Err(types::Error::BufferLen(
                u64::try_from(result.len()).unwrap(),
            ));
        }

        Ok(result)
    }

    fn downstream_client_oh_fingerprint(
        &mut self,
        h: Resource<http_req::Request>,
        _max_len: u64,
    ) -> Result<String, types::Error> {
        Ok(self
            .sandbox()
            .absent_metadata_value(h)?
            .ok_or(Error::MissingDownstreamMetadata)?)
    }

    fn downstream_tls_ja4(
        &mut self,
        h: Resource<http_req::Request>,
        _max_len: u64,
    ) -> Result<Option<String>, types::Error> {
        Ok(self.sandbox().absent_metadata_value(h)?)
    }

    fn downstream_compliance_region(
        &mut self,
        h: Resource<http_req::Request>,
        region_max_len: u64,
    ) -> Result<Option<String>, types::Error> {
        let region = Sandbox::downstream_compliance_region(self.sandbox(), h.into())?
            .ok_or(Error::MissingDownstreamMetadata)?;
        let region_len = region.len();

        match u64::try_from(region_len) {
            Ok(region_len) if region_len <= region_max_len => Ok(Some(region.to_owned())),
            too_large => Err(types::Error::BufferLen(too_large.unwrap_or(0))),
        }
    }

    fn downstream_original_header_names(
        &mut self,
        h: Resource<http_req::Request>,
        max_len: u64,
        cursor: u32,
    ) -> Result<(String, Option<u32>), types::Error> {
        let headers = self
            .sandbox()
            .downstream_original_headers(h.into())?
            .ok_or(Error::MissingDownstreamMetadata)?;
        let res = get_names(headers.keys(), max_len, cursor)?;

        Ok(res)
    }

    fn downstream_original_header_count(
        &mut self,
        h: Resource<http_req::Request>,
    ) -> Result<u32, types::Error> {
        Ok(self
            .sandbox()
            .downstream_original_headers(h.into())?
            .ok_or(Error::MissingDownstreamMetadata)?
            .len()
            .try_into()
            .expect("More than u32::MAX headers"))
    }

    fn fastly_key_is_valid(
        &mut self,
        h: Resource<http_req::Request>,
    ) -> Result<bool, types::Error> {
        self.sandbox()
            .check_fastly_key(h.into())
            .map_err(Into::into)
    }

    fn downstream_bot_analyzed(
        &mut self,
        h: Resource<http_req::Request>,
    ) -> Result<bool, types::Error> {
        let headers = self
            .sandbox()
            .downstream_original_headers(h.into())?
            .ok_or(Error::MissingDownstreamMetadata)?;
        Ok(headers
            .get("x-fastly-bot-analyzed")
            .map(|a| a == "true")
            .unwrap_or_default())
    }

    fn downstream_bot_detected(
        &mut self,
        h: Resource<http_req::Request>,
    ) -> Result<bool, types::Error> {
        let headers = self
            .sandbox()
            .downstream_original_headers(h.into())?
            .ok_or(Error::MissingDownstreamMetadata)?;
        Ok(headers
            .get("x-fastly-bot-detected")
            .map(|a| a == "true")
            .unwrap_or_default())
    }

    fn downstream_bot_name(
        &mut self,
        h: Resource<http_req::Request>,
        max_len: u64,
    ) -> Result<Option<String>, types::Error> {
        let headers = self
            .sandbox()
            .downstream_original_headers(h.into())?
            .ok_or(Error::MissingDownstreamMetadata)?;
        let name = headers
            .get("x-fastly-bot-name")
            .and_then(|n| n.to_str().ok())
            .map(|n| n.to_string());
        if let Some(name) = &name
            && name.len() > max_len as usize
        {
            Err(types::Error::LimitExceeded)
        } else {
            Ok(name)
        }
    }

    fn downstream_bot_category(
        &mut self,
        h: Resource<http_req::Request>,
        max_len: u64,
    ) -> Result<Option<String>, types::Error> {
        let headers = self
            .sandbox()
            .downstream_original_headers(h.into())?
            .ok_or(Error::MissingDownstreamMetadata)?;
        let name = headers
            .get("x-fastly-bot-category")
            .and_then(|n| n.to_str().ok())
            .map(|n| n.to_string());
        if let Some(name) = &name
            && name.len() > max_len as usize
        {
            Err(types::Error::LimitExceeded)
        } else {
            Ok(name)
        }
    }

    fn downstream_bot_category_kind(
        &mut self,
        h: Resource<http_req::Request>,
    ) -> Result<Option<http_downstream::BotCategory>, types::Error> {
        let kind = self
            .sandbox()
            .downstream_original_headers(h.into())?
            .ok_or(Error::MissingDownstreamMetadata)?
            .get("x-fastly-bot-category")
            .and_then(|n| n.to_str().ok());
        if let Some(kind) = kind {
            use http_downstream::BotCategory::*;
            Ok(Some(match kind.to_lowercase().as_ref() {
                "none" | "0" => http_downstream::BotCategory::None,
                "suspected" | "1" => Suspected,
                "accessibility" | "2" => Accessibility,
                "ai-crawler" | "3" => AiCrawler,
                "ai-fetcher" | "4" => AiFetcher,
                "content-fetcher" | "5" => ContentFetcher,
                "monitoring-site-tools" | "6" => MonitoringSiteTools,
                "online-marketing" | "7" => OnlineMarketing,
                "page-preview" | "8" => PagePreview,
                "platform-integration" | "9" => PlatformIntegrations,
                "research" | "10" => Research,
                "search-engine-crawler" | "11" => SearchEngineCrawler,
                "search-engine-optimization" | "12" => SearchEngineOptimization,
                "security-tools" | "13" => SecurityTools,
                other => {
                    let k = if other == "headless" {
                        14
                    } else {
                        other.parse().map_err(|_| types::Error::GenericError)?
                    };
                    let resource = ExtraBotCategory { raw: k };
                    self.table()
                        .push(resource)
                        .map_err(|_| types::Error::GenericError)
                        .map(|handle| http_downstream::BotCategory::Extra(handle))?
                }
            }))
        } else {
            Ok(None)
        }
    }

    fn downstream_bot_verified(
        &mut self,
        h: Resource<http_req::Request>,
    ) -> Result<Option<bool>, types::Error> {
        let headers = self
            .sandbox()
            .downstream_original_headers(h.into())?
            .ok_or(Error::MissingDownstreamMetadata)?;
        Ok(headers.get("x-fastly-bot-analyzed").map(|a| a == "true"))
    }

    fn downstream_resvpnproxy_is_anonymous(
        &mut self,
        _h: Resource<http_req::Request>,
    ) -> Result<Option<bool>, types::Error> {
        Ok(None)
    }

    fn downstream_resvpnproxy_is_anonymous_vpn(
        &mut self,
        _h: Resource<http_req::Request>,
    ) -> Result<Option<bool>, types::Error> {
        Ok(None)
    }

    fn downstream_resvpnproxy_is_hosting_provider(
        &mut self,
        _h: Resource<http_req::Request>,
    ) -> Result<Option<bool>, types::Error> {
        Ok(None)
    }

    fn downstream_resvpnproxy_is_proxy_over_vpn(
        &mut self,
        _h: Resource<http_req::Request>,
    ) -> Result<Option<bool>, types::Error> {
        Ok(None)
    }

    fn downstream_resvpnproxy_is_public_proxy(
        &mut self,
        _h: Resource<http_req::Request>,
    ) -> Result<Option<bool>, types::Error> {
        Ok(None)
    }

    fn downstream_resvpnproxy_is_relay_proxy(
        &mut self,
        _h: Resource<http_req::Request>,
    ) -> Result<Option<bool>, types::Error> {
        Ok(None)
    }

    fn downstream_resvpnproxy_is_residential_proxy(
        &mut self,
        _h: Resource<http_req::Request>,
    ) -> Result<Option<bool>, types::Error> {
        Ok(None)
    }

    fn downstream_resvpnproxy_is_smart_dns_proxy(
        &mut self,
        _h: Resource<http_req::Request>,
    ) -> Result<Option<bool>, types::Error> {
        Ok(None)
    }

    fn downstream_resvpnproxy_is_tor_exit_node(
        &mut self,
        _h: Resource<http_req::Request>,
    ) -> Result<Option<bool>, types::Error> {
        Ok(None)
    }

    fn downstream_resvpnproxy_is_vpn_datacenter(
        &mut self,
        _h: Resource<http_req::Request>,
    ) -> Result<Option<bool>, types::Error> {
        Ok(None)
    }

    fn downstream_resvpnproxy_vpn_service_name(
        &mut self,
        _h: Resource<http_req::Request>,
        _max_len: u64,
    ) -> Result<Option<String>, types::Error> {
        Ok(None)
    }

    fn downstream_visits_this_service(&mut self) -> Result<u64, types::Error> {
        Err(Error::Unsupported {
            msg: "`downstream_visits_this_service` not yet supported",
        }
        .into())
    }

    fn downstream_visits_this_pop(&mut self) -> Result<u64, types::Error> {
        Err(Error::Unsupported {
            msg: "`downstream_visits_this_pop` not yet supported",
        }
        .into())
    }
}

impl http_downstream::HostExtraNextRequestOptions for ComponentCtx {
    fn drop(
        &mut self,
        _options: Resource<http_downstream::ExtraNextRequestOptions>,
    ) -> wasmtime::Result<()> {
        Ok(())
    }
}

pub struct ExtraBotCategory {
    raw: u32,
}

impl http_downstream::HostExtraBotCategory for ComponentCtx {
    fn as_raw(&mut self, h: wasmtime::component::Resource<ExtraBotCategory>) -> u32 {
        self.table().get(&h).map(|r| r.raw).unwrap_or_default()
    }

    fn drop(&mut self, h: wasmtime::component::Resource<ExtraBotCategory>) -> wasmtime::Result<()> {
        self.table().delete(h)?;
        Ok(())
    }
}

pub(in super::super) trait MetadataView {
    /// Stub for metadata that Viceroy does not support.
    ///
    /// Validates the handle normally, but always returns `Ok(None)` rather than a meaningful value.
    fn absent_metadata_value<T>(
        &self,
        handle: Resource<http_req::Request>,
    ) -> Result<Option<T>, Error>;
}
impl MetadataView for Sandbox {
    fn absent_metadata_value<T>(
        &self,
        handle: Resource<http_req::Request>,
    ) -> Result<Option<T>, Error> {
        let _ = self
            .downstream_metadata(handle.into())?
            .ok_or(Error::MissingDownstreamMetadata)?;
        Ok(None)
    }
}
