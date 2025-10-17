//! Trivial wrappers around wasmtime-wasi implementations.
//!
//! This exists because Wasmtime's bindgen system doesn't gracefully handle
//! component implementations that are split between multiple crates.

use crate::component::bindings::wasi;
use crate::linking::ComponentCtx;
use wasmtime::component::Resource;
use wasmtime_wasi::WasiView;
use wasmtime_wasi_io::IoView;

impl wasi::clocks::wall_clock::Host for ComponentCtx {
    fn now(&mut self) -> wasi::clocks::wall_clock::Datetime {
        let x = wasmtime_wasi::p2::bindings::sync::clocks::wall_clock::Host::now(&mut self.ctx())
            .unwrap();
        wasi::clocks::wall_clock::Datetime {
            seconds: x.seconds,
            nanoseconds: x.nanoseconds,
        }
    }

    fn resolution(&mut self) -> wasi::clocks::wall_clock::Datetime {
        let x = wasmtime_wasi::p2::bindings::sync::clocks::wall_clock::Host::resolution(
            &mut self.ctx(),
        )
        .unwrap();
        wasi::clocks::wall_clock::Datetime {
            seconds: x.seconds,
            nanoseconds: x.nanoseconds,
        }
    }
}

impl wasi::clocks::monotonic_clock::Host for ComponentCtx {
    fn now(&mut self) -> wasi::clocks::monotonic_clock::Instant {
        wasmtime_wasi::p2::bindings::sync::clocks::monotonic_clock::Host::now(&mut self.ctx())
            .unwrap()
    }

    fn resolution(&mut self) -> wasi::clocks::monotonic_clock::Duration {
        wasmtime_wasi::p2::bindings::sync::clocks::monotonic_clock::Host::resolution(
            &mut self.ctx(),
        )
        .unwrap()
    }

    fn subscribe_instant(
        &mut self,
        when: wasi::clocks::monotonic_clock::Instant,
    ) -> Resource<wasi::clocks::monotonic_clock::Pollable> {
        wasmtime_wasi::p2::bindings::sync::clocks::monotonic_clock::Host::subscribe_instant(
            &mut self.ctx(),
            when,
        )
        .unwrap()
    }

    fn subscribe_duration(
        &mut self,
        when: wasi::clocks::monotonic_clock::Duration,
    ) -> Resource<wasi::clocks::monotonic_clock::Pollable> {
        wasmtime_wasi::p2::bindings::sync::clocks::monotonic_clock::Host::subscribe_duration(
            &mut self.ctx(),
            when,
        )
        .unwrap()
    }
}

impl wasi::io::poll::Host for ComponentCtx {
    async fn poll(&mut self, pollables: Vec<Resource<wasi::io::poll::Pollable>>) -> Vec<u32> {
        wasmtime_wasi::p2::bindings::io::poll::Host::poll(&mut self.table(), pollables)
            .await
            .unwrap()
    }
}

impl wasi::io::poll::HostPollable for ComponentCtx {
    fn ready(&mut self, pollable: Resource<wasi::io::poll::Pollable>) -> bool {
        wasmtime_wasi::p2::bindings::sync::io::poll::HostPollable::ready(
            &mut self.table(),
            pollable,
        )
        .unwrap()
    }
    async fn block(&mut self, pollable: Resource<wasi::io::poll::Pollable>) {
        wasmtime_wasi::p2::bindings::io::poll::HostPollable::block(&mut self.table(), pollable)
            .await
            .unwrap()
    }
    fn drop(&mut self, pollable: Resource<wasi::io::poll::Pollable>) -> wasmtime::Result<()> {
        wasmtime_wasi::p2::bindings::sync::io::poll::HostPollable::drop(&mut self.table(), pollable)
    }
}

impl wasi::io::error::Host for ComponentCtx {}

impl wasi::io::error::HostError for ComponentCtx {
    fn to_debug_string(&mut self, self_: Resource<wasi::io::error::Error>) -> String {
        wasmtime_wasi::p2::bindings::sync::io::error::HostError::to_debug_string(
            &mut self.table(),
            self_,
        )
        .unwrap()
    }

    fn drop(&mut self, rep: Resource<wasi::io::error::Error>) -> wasmtime::Result<()> {
        wasmtime_wasi::p2::bindings::sync::io::error::HostError::drop(&mut self.table(), rep)
    }
}

impl wasi::io::streams::Host for ComponentCtx {
    fn convert_stream_error(
        &mut self,
        err: wasmtime_wasi::p2::StreamError,
    ) -> wasmtime::Result<wasi::io::streams::StreamError> {
        match err {
            wasmtime_wasi::p2::StreamError::Closed => Ok(wasi::io::streams::StreamError::Closed),
            wasmtime_wasi::p2::StreamError::LastOperationFailed(e) => Ok(
                wasi::io::streams::StreamError::LastOperationFailed(self.wasi_table.push(e)?),
            ),
            wasmtime_wasi::p2::StreamError::Trap(e) => Err(e),
        }
    }
}

impl wasi::io::streams::HostOutputStream for ComponentCtx {
    fn write(
        &mut self,
        stream: Resource<wasi::io::streams::OutputStream>,
        contents: Vec<u8>,
    ) -> Result<(), wasmtime_wasi::p2::StreamError> {
        wasmtime_wasi::p2::bindings::sync::io::streams::HostOutputStream::write(
            &mut self.table(),
            stream,
            contents,
        )
    }

    async fn blocking_write_and_flush(
        &mut self,
        stream: Resource<wasi::io::streams::OutputStream>,
        contents: Vec<u8>,
    ) -> Result<(), wasmtime_wasi::p2::StreamError> {
        wasmtime_wasi::p2::bindings::io::streams::HostOutputStream::blocking_write_and_flush(
            &mut self.table(),
            stream,
            contents,
        )
        .await
    }

    fn flush(
        &mut self,
        stream: Resource<wasi::io::streams::OutputStream>,
    ) -> Result<(), wasmtime_wasi::p2::StreamError> {
        wasmtime_wasi::p2::bindings::sync::io::streams::HostOutputStream::flush(
            &mut self.table(),
            stream,
        )
    }

    async fn blocking_flush(
        &mut self,
        stream: Resource<wasi::io::streams::OutputStream>,
    ) -> Result<(), wasmtime_wasi::p2::StreamError> {
        wasmtime_wasi::p2::bindings::io::streams::HostOutputStream::blocking_flush(
            &mut self.table(),
            stream,
        )
        .await
    }

    fn check_write(
        &mut self,
        stream: Resource<wasi::io::streams::OutputStream>,
    ) -> Result<u64, wasmtime_wasi::p2::StreamError> {
        wasmtime_wasi::p2::bindings::sync::io::streams::HostOutputStream::check_write(
            &mut self.table(),
            stream,
        )
    }

    fn subscribe(
        &mut self,
        self_: Resource<wasi::io::streams::OutputStream>,
    ) -> Resource<wasi::io::streams::Pollable> {
        wasmtime_wasi::p2::bindings::sync::io::streams::HostOutputStream::subscribe(
            &mut self.table(),
            self_,
        )
        .unwrap()
    }

    fn write_zeroes(
        &mut self,
        self_: Resource<wasi::io::streams::OutputStream>,
        len: u64,
    ) -> Result<(), wasmtime_wasi::p2::StreamError> {
        wasmtime_wasi::p2::bindings::sync::io::streams::HostOutputStream::write_zeroes(
            &mut self.table(),
            self_,
            len,
        )
    }

    async fn blocking_write_zeroes_and_flush(
        &mut self,
        self_: Resource<wasi::io::streams::OutputStream>,
        len: u64,
    ) -> Result<(), wasmtime_wasi::p2::StreamError> {
        wasmtime_wasi::p2::bindings::io::streams::HostOutputStream::blocking_write_zeroes_and_flush(
            &mut self.table(),
            self_,
            len,
        )
        .await
    }

    fn splice(
        &mut self,
        self_: Resource<wasi::io::streams::OutputStream>,
        src: Resource<wasi::io::streams::InputStream>,
        len: u64,
    ) -> Result<u64, wasmtime_wasi::p2::StreamError> {
        wasmtime_wasi::p2::bindings::sync::io::streams::HostOutputStream::splice(
            &mut self.table(),
            self_,
            src,
            len,
        )
    }

    async fn blocking_splice(
        &mut self,
        self_: Resource<wasi::io::streams::OutputStream>,
        src: Resource<wasi::io::streams::InputStream>,
        len: u64,
    ) -> Result<u64, wasmtime_wasi::p2::StreamError> {
        wasmtime_wasi::p2::bindings::io::streams::HostOutputStream::blocking_splice(
            &mut self.table(),
            self_,
            src,
            len,
        )
        .await
    }

    fn drop(&mut self, rep: Resource<wasi::io::streams::OutputStream>) -> wasmtime::Result<()> {
        wasmtime_wasi::p2::bindings::sync::io::streams::HostOutputStream::drop(
            &mut self.table(),
            rep,
        )
    }
}

impl wasi::io::streams::HostInputStream for ComponentCtx {
    fn read(
        &mut self,
        self_: Resource<wasi::io::streams::InputStream>,
        len: u64,
    ) -> Result<Vec<u8>, wasmtime_wasi::p2::StreamError> {
        wasmtime_wasi::p2::bindings::sync::io::streams::HostInputStream::read(
            &mut self.table(),
            self_,
            len,
        )
    }

    async fn blocking_read(
        &mut self,
        self_: Resource<wasi::io::streams::InputStream>,
        len: u64,
    ) -> Result<Vec<u8>, wasmtime_wasi::p2::StreamError> {
        wasmtime_wasi::p2::bindings::io::streams::HostInputStream::blocking_read(
            &mut self.table(),
            self_,
            len,
        )
        .await
    }

    fn skip(
        &mut self,
        self_: Resource<wasi::io::streams::InputStream>,
        len: u64,
    ) -> Result<u64, wasmtime_wasi::p2::StreamError> {
        wasmtime_wasi::p2::bindings::sync::io::streams::HostInputStream::skip(
            &mut self.table(),
            self_,
            len,
        )
    }

    async fn blocking_skip(
        &mut self,
        self_: Resource<wasi::io::streams::InputStream>,
        len: u64,
    ) -> Result<u64, wasmtime_wasi::p2::StreamError> {
        wasmtime_wasi::p2::bindings::io::streams::HostInputStream::blocking_skip(
            &mut self.table(),
            self_,
            len,
        )
        .await
    }

    fn subscribe(
        &mut self,
        self_: Resource<wasi::io::streams::InputStream>,
    ) -> Resource<wasi::io::streams::Pollable> {
        wasmtime_wasi::p2::bindings::sync::io::streams::HostInputStream::subscribe(
            &mut self.table(),
            self_,
        )
        .unwrap()
    }

    fn drop(&mut self, rep: Resource<wasi::io::streams::InputStream>) -> wasmtime::Result<()> {
        wasmtime_wasi::p2::bindings::sync::io::streams::HostInputStream::drop(
            &mut self.table(),
            rep,
        )
    }
}

impl wasi::random::random::Host for ComponentCtx {
    fn get_random_bytes(&mut self, len: u64) -> Vec<u8> {
        wasmtime_wasi::p2::bindings::random::random::Host::get_random_bytes(
            &mut self.wasi_random,
            len,
        )
        .unwrap()
    }

    fn get_random_u64(&mut self) -> u64 {
        wasmtime_wasi::p2::bindings::random::random::Host::get_random_u64(&mut self.wasi_random)
            .unwrap()
    }
}

impl wasi::random::insecure::Host for ComponentCtx {
    fn get_insecure_random_bytes(&mut self, len: u64) -> Vec<u8> {
        wasmtime_wasi::p2::bindings::random::insecure::Host::get_insecure_random_bytes(
            &mut self.wasi_random,
            len,
        )
        .unwrap()
    }

    fn get_insecure_random_u64(&mut self) -> u64 {
        wasmtime_wasi::p2::bindings::random::insecure::Host::get_insecure_random_u64(
            &mut self.wasi_random,
        )
        .unwrap()
    }
}

impl wasi::random::insecure_seed::Host for ComponentCtx {
    fn insecure_seed(&mut self) -> (u64, u64) {
        wasmtime_wasi::p2::bindings::random::insecure_seed::Host::insecure_seed(
            &mut self.wasi_random,
        )
        .unwrap()
    }
}

impl wasi::cli::environment::Host for ComponentCtx {
    fn get_environment(&mut self) -> Vec<(String, String)> {
        wasmtime_wasi::p2::bindings::cli::environment::Host::get_environment(&mut self.ctx())
            .unwrap()
    }

    fn get_arguments(&mut self) -> Vec<String> {
        wasmtime_wasi::p2::bindings::cli::environment::Host::get_arguments(&mut self.ctx()).unwrap()
    }

    fn initial_cwd(&mut self) -> Option<String> {
        wasmtime_wasi::p2::bindings::cli::environment::Host::initial_cwd(&mut self.ctx()).unwrap()
    }
}

impl wasi::cli::stdin::Host for ComponentCtx {
    fn get_stdin(&mut self) -> Resource<wasi::cli::stdin::InputStream> {
        wasmtime_wasi::p2::bindings::cli::stdin::Host::get_stdin(&mut self.ctx()).unwrap()
    }
}

impl wasi::cli::stdout::Host for ComponentCtx {
    fn get_stdout(&mut self) -> Resource<wasi::cli::stdout::OutputStream> {
        wasmtime_wasi::p2::bindings::cli::stdout::Host::get_stdout(&mut self.ctx()).unwrap()
    }
}

impl wasi::cli::stderr::Host for ComponentCtx {
    fn get_stderr(&mut self) -> Resource<wasi::cli::stderr::OutputStream> {
        wasmtime_wasi::p2::bindings::cli::stderr::Host::get_stderr(&mut self.ctx()).unwrap()
    }
}

impl wasi::cli::exit::Host for ComponentCtx {
    fn exit(&mut self, status: Result<(), ()>) -> wasmtime::Result<()> {
        wasmtime_wasi::p2::bindings::cli::exit::Host::exit(&mut self.ctx(), status)
    }

    fn exit_with_code(&mut self, status_code: u8) -> wasmtime::Result<()> {
        wasmtime_wasi::p2::bindings::cli::exit::Host::exit_with_code(&mut self.ctx(), status_code)
    }
}
