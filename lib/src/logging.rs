use tokio::sync::mpsc::Sender;
use {
    lazy_static::lazy_static,
    std::{
        io::{self, Write},
        sync::Mutex,
    },
};

/// A logging endpoint.
pub struct LogEndpoint {
    name: Vec<u8>,
    sender: Option<Sender<Vec<u8>>>,
}

lazy_static! {
    /// The underlying writer to use for all log messages. It defaults to `stdout`,
    /// but can be redirected for tests. We make this a static, rather than e.g.
    /// a field in `ExecuteCtx`, because the `Write` implementation for `LogEndpoint`
    /// doesn't have direct access to context data.
    pub static ref LOG_WRITER: Mutex<Box<dyn Write + Send>> = Mutex::new(Box::new(io::stdout()));
}

impl LogEndpoint {
    /// Allocate a new `LogEndpoint` with the given name and optional sender.
    pub fn new(name: &[u8], sender: Option<Sender<Vec<u8>>>) -> LogEndpoint {
        LogEndpoint {
            name: name.to_owned(),
            sender,
        }
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
        // A listener just takes the messages line by line, while the stdout format is with delimiters.
        let mut to_write = if self.sender.is_some() {
            Vec::with_capacity(msg.len())
        } else {
            let buf_len = msg.len() + self.name.len() + LOG_ENDPOINT_DELIM.len() + 1;
            let mut buf = Vec::with_capacity(buf_len);

            buf.extend_from_slice(&self.name);
            buf.extend_from_slice(LOG_ENDPOINT_DELIM);
            buf
        };

        for &byte in msg {
            if byte == b'\n' {
                to_write.extend_from_slice(br"\n");
            } else {
                to_write.push(byte);
            }
        }
        to_write.push(b'\n');

        if let Some(ref sender) = self.sender {
            sender.try_send(to_write).expect("todo");
            Ok(())
        } else {
            LOG_WRITER.lock().unwrap().write_all(&to_write)
        }
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
