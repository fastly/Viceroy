use {
    crate::common::{Test, TestResult},
    hyper::StatusCode,
    std::{
        io::{self, Write},
        sync::mpsc,
    },
    viceroy_lib::logging,
};

struct LogWriter(mpsc::Sender<Vec<u8>>);

impl Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.0.send(buf.to_owned()) {
            Ok(()) => Ok(buf.len()),
            Err(_) => Err(io::ErrorKind::ConnectionReset.into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn setup_log_writer() -> mpsc::Receiver<Vec<u8>> {
    let (send, recv) = mpsc::channel();
    *logging::LOG_WRITER.lock().unwrap() = Box::new(LogWriter(send));
    recv
}

#[tokio::test(flavor = "multi_thread")]
async fn logging_works() -> TestResult {
    let log_recv = setup_log_writer();
    let resp = Test::using_fixture("logging.wasm")
        .log_stderr()
        .log_stdout()
        .against_empty()
        .await?;

    assert_eq!(resp.status(), StatusCode::OK);

    let read_log_line = || String::from_utf8(log_recv.recv().unwrap()).unwrap();

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
