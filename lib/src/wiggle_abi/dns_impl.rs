//! `fastly_dns` hostcall implementations.

use {
    crate::{
        dns::{DnsLookup, DnsLookupResult},
        error::{Error, HandleError},
        session::Session,
        wiggle_abi::fastly_dns::*,
        wiggle_abi::{
            types::{DnsLookupHandle, MultiValueCursor, MultiValueCursorResult},
            MultiValueWriter,
        },
    },
    std::convert::TryFrom,
    wiggle::GuestPtr,
};

#[wiggle::async_trait]
impl FastlyDns for Session {
    /// Lookup IPv4 and IPv6 addresses of a given host name.
    async fn lookup_addr<'a>(
        &mut self,
        name: &GuestPtr<'a, str>,
    ) -> Result<DnsLookupHandle, Error> {
        let name = name.as_str()?.to_string();
        let dns_client = self.dns_client().clone();
        let fut = async move {
            dns_client
                .query_addrs(&name)
                .await
                .map(|x| DnsLookupResult::Ips(x))
        };
        let pending_lookup = DnsLookup::spawn(fut);
        Ok(self.insert_dns_lookup(pending_lookup))
    }

    /// Reverse IP DNS lookup.
    async fn lookup_reverse<'a>(
        &mut self,
        ip: &GuestPtr<'a, str>,
    ) -> Result<DnsLookupHandle, Error> {
        let ip = ip.as_str()?.parse().map_err(|_| Error::InvalidArgument)?;
        let dns_client = self.dns_client().clone();
        let fut = async move {
            dns_client
                .query_ptr(&ip)
                .await
                .map(|x| DnsLookupResult::Ptrs(x))
        };
        let pending_lookup = DnsLookup::spawn(fut);
        Ok(self.insert_dns_lookup(pending_lookup))
    }

    /// Lookup TXT records associated with a name.
    async fn lookup_txt<'a>(&mut self, name: &GuestPtr<'a, str>) -> Result<DnsLookupHandle, Error> {
        let name = name.as_str()?.to_string();
        let dns_client = self.dns_client().clone();
        let fut = async move {
            dns_client
                .query_txt(&name)
                .await
                .map(|x| DnsLookupResult::Txts(x))
        };
        let pending_lookup = DnsLookup::spawn(fut);
        Ok(self.insert_dns_lookup(pending_lookup))
    }

    async fn lookup_wait<'a>(
        &mut self,
        handle: DnsLookupHandle,
        buf: &GuestPtr<'a, u8>,
        buf_len: u32,
        cursor: MultiValueCursor,
        ending_cursor_out: &GuestPtr<'a, MultiValueCursorResult>,
        nwritten_out: &GuestPtr<'a, u32>,
    ) -> Result<(), Error> {
        let pending_lookup = self.take_dns_lookup(handle)?;
        let results = pending_lookup
            .receiver
            .await
            .map_err(|_| Error::LookupError)??;
        let res = match results {
            DnsLookupResult::Ips(ips) => ips.iter().map(|x| x.to_string()).write_values(
                b'\0',
                &buf.as_array(buf_len),
                cursor,
                nwritten_out,
            ),
            DnsLookupResult::Ptrs(ptrs) => {
                ptrs.iter()
                    .write_values(b'\0', &buf.as_array(buf_len), cursor, nwritten_out)
            }
            DnsLookupResult::Txts(txts) => {
                txts.iter()
                    .write_values(b'\0', &buf.as_array(buf_len), cursor, nwritten_out)
            }
            _ => return Err(HandleError::InvalidDnsLookupHandle(handle).into()),
        };
        multi_value_result!(res, ending_cursor_out)
    }

    /// Lookup TXT records associated with a name.
    async fn lookup_raw<'a>(
        &mut self,
        query: &GuestPtr<'a, u8>,
        query_len: u32,
    ) -> Result<DnsLookupHandle, Error> {
        let query = query.as_array(query_len).as_slice()?.to_vec();
        let dns_client = self.dns_client().clone();
        let fut = async move {
            dns_client
                .query_raw(&query, true)
                .await
                .map(|x| DnsLookupResult::Raw(x))
        };
        let pending_lookup = DnsLookup::spawn(fut);
        Ok(self.insert_dns_lookup(pending_lookup))
    }

    /// Waits for a raw DNS response, to be parsed by the WebAssembly application.
    async fn lookup_wait_raw<'a>(
        &mut self,
        handle: DnsLookupHandle,
        response: &GuestPtr<'a, u8>,
        response_len: u32,
        nwritten_out: &GuestPtr<'a, u32>,
    ) -> Result<(), Error> {
        let pending_lookup = self.take_dns_lookup(handle)?;
        let result = pending_lookup
            .receiver
            .await
            .map_err(|_| Error::LookupError)??;
        let raw_response = match result {
            DnsLookupResult::Raw(raw_response) => raw_response,
            _ => return Err(HandleError::InvalidDnsLookupHandle(handle).into()),
        };
        if raw_response.len() > response_len as _ {
            return Err(Error::BufferLengthError {
                buf: "response",
                len: "response_len",
            });
        }
        let raw_response_len = u32::try_from(raw_response.len()).expect("overflow");
        response
            .as_array(raw_response_len)
            .copy_from_slice(&raw_response)?;
        nwritten_out.write(raw_response_len)?;
        Ok(())
    }
}
