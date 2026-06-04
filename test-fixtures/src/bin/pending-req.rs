use fastly::error::{anyhow, Error};
use fastly::handle::PendingRequestHandle;
use fastly::http::request::Request;
use fastly_shared::FastlyStatus;

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingResponseKind {
    Any = 0,
    Response = 1,
    Error = 2,
}

#[link(wasm_import_module = "fastly_http_req")]
unsafe extern "C" {
    #[link_name = "pending_req_header_append"]
    pub fn pending_req_header_append(
        pending_req_handle: u32,
        name: *const u8,
        name_len: usize,
        value: *const u8,
        value_len: usize,
        target: PendingResponseKind,
    ) -> FastlyStatus;

    #[link_name = "pending_req_header_insert"]
    pub fn pending_req_header_insert(
        pending_req_handle: u32,
        name: *const u8,
        name_len: usize,
        value: *const u8,
        value_len: usize,
        target: PendingResponseKind,
    ) -> FastlyStatus;

    #[link_name = "pending_req_header_remove"]
    pub fn pending_req_header_remove(
        pending_req_handle: u32,
        name: *const u8,
        name_len: usize,
        target: PendingResponseKind,
    ) -> FastlyStatus;
}

#[link(wasm_import_module = "fastly_http_resp")]
unsafe extern "C" {
    #[link_name = "send_downstream_pending"]
    pub fn send_downstream_pending(pending_req_handle: u32) -> FastlyStatus;
}

enum PendingHeaderOp<'a> {
    Insert(&'a str, &'a str),
    Append(&'a str, &'a str),
    Remove(&'a str),
}

impl<'a> PendingHeaderOp<'a> {
    fn apply(self, handle: PendingRequestHandle, target: PendingResponseKind) -> PendingRequestHandle {
        match self {
            PendingHeaderOp::Insert(name, val) => unsafe {
                pending_req_header_insert(handle.as_u32(), name.as_ptr(), name.len(), val.as_ptr(), val.len(), target)
                    .result()
                    .expect("pending_req_header_insert should succeed")
            },
            PendingHeaderOp::Append(name, val) => unsafe {
                pending_req_header_append(handle.as_u32(), name.as_ptr(), name.len(), val.as_ptr(), val.len(), target)
                    .result()
                    .expect("pending_req_header_append should succeed")
            },
            PendingHeaderOp::Remove(name) => unsafe {
                pending_req_header_remove(handle.as_u32(), name.as_ptr(), name.len(), target)
                    .result()
                    .expect("pending_req_header_remove should succeed")
            },
        }

        handle
    }

    fn parse_multi(s: &'a str) -> Result<Vec<Self>, Error> {
        s.split(',')
            .filter(|s| !s.is_empty())
            .map(PendingHeaderOp::try_from)
            .collect()
    }
}

impl<'a> TryFrom<&'a str> for PendingHeaderOp<'a> {
    type Error = Error;

    fn try_from(op: &'a str) -> Result<Self, Self::Error> {
        if let Some(insert) = op.strip_prefix("insert:") {
            let (name, val) = insert.split_once(':').unwrap();
            Ok(PendingHeaderOp::Insert(name, val))
        } else if let Some(append) = op.strip_prefix("append:") {
            let (name, val) = append.split_once(':').unwrap();
            Ok(PendingHeaderOp::Append(name, val))
        } else if let Some(name) = op.strip_prefix("remove:") {
            Ok(PendingHeaderOp::Remove(name))
        } else {
            Err(anyhow!("unknown op: {op:?}"))
        }
    }
}

fn handler(mut req: Request) -> Result<(), Error> {
    let origin = req
        .remove_header_str("Backend-Name")
        .ok_or_else(|| anyhow!("missing Backend-Name header"))?;

    let with_header_ops = req
        .remove_header_str("With-Header-Ops")
        .unwrap_or_else(String::new);

    let with_error_header_ops = req
        .remove_header_str("With-Error-Header-Ops")
        .unwrap_or_else(String::new);

    let headers = PendingHeaderOp::parse_multi(&with_header_ops)?;
    let errorhs = PendingHeaderOp::parse_multi(&with_error_header_ops)?;
    let pending = req.with_pass(true).send_async(origin)?;
    let handle = PendingRequestHandle::from(pending);

    let handle = headers
        .into_iter()
        .fold(handle, |h, op| op.apply(h, PendingResponseKind::Any));

    let handle = errorhs
        .into_iter()
        .fold(handle, |h, op| op.apply(h, PendingResponseKind::Error));

    unsafe {
        send_downstream_pending(handle.as_u32())
            .result()
            .expect("send_downstream_pending should succeed");
    }

    Ok(())
}

fn main() -> Result<(), Error> {
    handler(Request::from_client())
        .inspect_err(|e| println!("request handler failed: {e}"))
}
