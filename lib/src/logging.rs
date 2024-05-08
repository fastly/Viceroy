use {
    lazy_static::lazy_static,
    std::{
        io::{self, Write},
        sync::Mutex,
    },
};

/// A logging endpoint, which for Viceroy is just a name.
pub struct LogEndpoint(Vec<u8>);

lazy_static! {
    /// The underlying writer to use for all log messages. It defaults to `stdout`,
    /// but can be redirected for tests. We make this a static, rather than e.g.
    /// a field in `ExecuteCtx`, because the `Write` implementation for `LogEndpoint`
    /// doesn't have direct access to context data.
    pub static ref LOG_WRITER: Mutex<Box<dyn Write + Send>> = Mutex::new(Box::new(io::stdout()));
}

impl LogEndpoint {
    /// Allocate a new `LogEndpoint` with the given name.
    pub fn new(name: &[u8]) -> LogEndpoint {
        LogEndpoint(name.to_owned())
    }

    /// Write a log entry to this endpoint.
    ///
    /// Log entries are prefixed with the endpoint name and terminated with a newline.
    /// Any newlines in the message will be escaped to the string r"\n".
    ///
    /// The entry is written atomically to `LOG_WRITER`.
    pub fn write_entry(&self, mut msg: &[u8]) -> io::Result<()> {
        const LOG_ENDPOINT_DELIM: &[u8] = b" :: ";

        // Strip any trailing newlines; we will add a newline at the end,
        // and escape any interior newlines.
        if msg.last() == Some(&b'\n') {
            msg = &msg[..msg.len() - 1];
        }

        if msg.is_empty() {
            return Ok(());
        }

        // Accumulate log entry into a buffer before writing, while escaping newlines
        let mut to_write =
            Vec::with_capacity(msg.len() + self.0.len() + LOG_ENDPOINT_DELIM.len() + 1);

        to_write.extend_from_slice(&self.0);
        to_write.extend_from_slice(LOG_ENDPOINT_DELIM);
        for &byte in msg {
            if byte == b'\n' {
                to_write.extend_from_slice(br"\n");
            } else {
                to_write.push(byte);
            }
        }
        to_write.push(b'\n');

        LOG_WRITER.lock().unwrap().write_all(&to_write)
    }
}

impl Write for LogEndpoint {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_entry(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        LOG_WRITER.lock().unwrap().flush()
    }
}

impl wasmtime_wasi::StdoutStream for LogEndpoint {
    fn stream(&self) -> Box<dyn wasmtime_wasi::HostOutputStream> {
        Box::new(LogEndpoint(self.0.clone()))
    }

    fn isatty(&self) -> bool {
        false
    }
}

#[wiggle::async_trait]
impl wasmtime_wasi::Subscribe for LogEndpoint {
    async fn ready(&mut self) {}
}

impl wasmtime_wasi::HostOutputStream for LogEndpoint {
    fn write(&mut self, bytes: bytes::Bytes) -> wasmtime_wasi::StreamResult<()> {
        self.write_entry(&bytes)
            .map_err(|e| wasmtime_wasi::StreamError::LastOperationFailed(anyhow::anyhow!(e)))
    }

    fn flush(&mut self) -> wasmtime_wasi::StreamResult<()> {
        <Self as Write>::flush(self)
            .map_err(|e| wasmtime_wasi::StreamError::LastOperationFailed(anyhow::anyhow!(e)))
    }

    fn check_write(&mut self) -> wasmtime_wasi::StreamResult<usize> {
        Ok(1024 * 1024)
    }
}
