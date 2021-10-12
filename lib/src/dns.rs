use futures::Future;
use std::{io, net::IpAddr};
use tokio::sync::oneshot;

#[derive(Debug)]
pub enum DnsLookupResult {
    Ips(Vec<IpAddr>),
    Txts(Vec<Vec<u8>>),
    Ptrs(Vec<String>),
    Raw(Vec<u8>),
}

#[derive(Debug)]
pub struct DnsLookup {
    pub receiver: oneshot::Receiver<Result<DnsLookupResult, io::Error>>,
}

impl DnsLookup {
    pub fn spawn(
        req: impl Future<Output = Result<DnsLookupResult, io::Error>> + Send + 'static,
    ) -> Self {
        let (sender, receiver) = oneshot::channel();
        tokio::task::spawn(async move { sender.send(req.await) });
        Self { receiver }
    }
}
