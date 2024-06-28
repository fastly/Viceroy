use {
    crate::common::{Test, TestResult},
    hyper::StatusCode,
    std::{
        io::{self, Write},
        sync::{Arc, Mutex},
    },
};

struct LogWriter(Vec<Vec<u8>>);

impl Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.push(buf.to_owned());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn logging_works() -> TestResult {
    let log_writer = Arc::new(Mutex::new(LogWriter(Vec::new())));
    let resp = Test::using_fixture("logging.wasm")
        .capture_logs(log_writer.clone())
        .log_stderr()
        .log_stdout()
        .against_empty()
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);

    let mut logs = std::mem::take(&mut log_writer.lock().unwrap().0).into_iter();
    let mut read_log_line = || String::from_utf8(logs.next().unwrap()).unwrap();

    assert_eq!(read_log_line(), "inigo :: Who are you?\n");
    assert_eq!(read_log_line(), "mib :: No one of consequence.\n");
    assert_eq!(read_log_line(), "inigo :: I must know.\n");
    assert_eq!(read_log_line(), "mib :: Get used to disappointment.\n");

    assert_eq!(
        read_log_line(),
        "mib :: There is something\\nI ought to tell you.\n"
    );
    assert_eq!(read_log_line(), "inigo :: Tell me.\\n\n");
    assert_eq!(read_log_line(), "mib :: I'm not left-handed either.\n");
    assert_eq!(read_log_line(), "inigo :: O_O\n");

    assert_eq!(read_log_line(), "stdout :: logging from stdout\n");
    assert_eq!(read_log_line(), "stderr :: logging from stderr\n");

    // showcase line buffering on stdout
    assert_eq!(read_log_line(), "stdout :: log line terminates on flush\n");
    assert_eq!(read_log_line(), "stdout :: newline completes a log line\n");

    // showcase no buffering on stderr
    assert_eq!(read_log_line(), "stderr :: log line terminates on flush\n");
    assert_eq!(read_log_line(), "stderr :: log line terminates\n");
    assert_eq!(read_log_line(), "stderr :: on each write\n");

    Ok(())
}
