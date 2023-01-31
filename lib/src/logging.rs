use {
    lazy_static::lazy_static,
    std::{
        io::{self, Write},
        sync::Mutex,
    },
    tokio::io::AsyncWrite,
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

impl AsyncWrite for LogEndpoint {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        std::task::Poll::Ready(self.as_mut().write(buf))
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        std::task::Poll::Ready(self.as_mut().flush())
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}
