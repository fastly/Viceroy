# Viceroy

Viceroy provides local testing for developers working with Compute@Edge. It
allows you to run services written against the Compute@Edge APIs on your local
development machine, and allows you to configure testing backends for your
service to communicate with.

In the near future, Viceroy will be packaged as part of the Fastly CLI and
integrate with other Compute@Edge workflows. But for the moment, you can use it
by hand, as described below.

## Installation

To install Viceroy, you'll need to first
[install Rust](https://www.rust-lang.org/tools/install) if you haven't already.

### Clone the repo

You'll need to get a copy of the Viceroy source code locally, by cloning the
[Viceroy repo](https://github.com/fastly/Viceroy/) like so:

```
git clone git@github.com:fastly/Viceroy.git
git submodule update --recursive --init
```

### Install via Cargo

Next, navigate to the `Viceroy` directory resulting from the `git clone` above,
and run:

```
cargo install --path cli
```

You should see a message that says `Installing viceroy-cli` followed by a large
number of compilation messages. The end result is that the `viceroy` command
is made available on your system.

### Updating Viceroy

o update Viceroy, navigate to the `Viceroy` directory you cloned above, and then:

```
git pull
git submodule update --recursive --init
cargo install --path cli
```

## Usage

After installation, the `viceroy` command should be available on your path. The
only required argument is the path to a compiled `.wasm` blob, which can be
built by `fastly compute build`. The Fastly CLI should put the blob at
`bin/main.wasm`. To test the service, you can run:

```
viceroy bin/main.wasm
```

This will start a local server (by default at: `http://127.0.0.1:7878`), which can be used to make requests to, and execute, your C@E Wasm module. This can be done by using [curl](https://curl.se/), or you can send a simple GET request by visiting the URL in your web browser.

**NOTE:** Viceroy expects to find a `fastly.toml` manifest. It will look only in the
current directory by default; you can specify a path to the file using the
`--manifest-path` option. The manifest is used to configure backends, which we
describe next.

### Configuring backends

Most Compute@Edge services need to make requests to named backends (origin
servers), which are normally configured using the Fastly UI. For testing with
Viceroy, you can specify backends in a **dedicated** TOML file, which you
provide to Viceroy using the `-C` flag:

```
viceroy bin/main.wasm -C backends.toml
```

In the future, testing backends will be part of the `fastly.toml` manifest
managed by the Fastly CLI, but for now you should **not** use the `fastly.toml`
manifest, because the Fastly CLI will remove any additions you make.

Backends are specified in the TOML file within a `local_server.backends`
section:

```toml
[local_server.backends]

[local_server.backends.origin]
url = "http://localhost:8000"

[local_server.backends.example]
url = "http://example.com:80"
```

The host and port are used when routing requests to the named backends while
testing your Compute@Edge service.

#### Backend path prefixes

Backend URLs can include a path, which will be used as a _prefix_ to the URL of
any requests your service makes to the backend. Path prefixes are useful when
simulating multiple backends with a single mock service.

So, for example, you might use the following configuration:

```toml
[local_server.backends]

[local_server.backends.main]
url = "http://localhost:8000/main"

[local_server.backends.secondary]
url = "http://localhost:8000/secondary"
```

When your service makes a request against the `main` backend with URL
`/index.html`, it will be routed to the http service on `localhost` at port
`8000`, against the url `/main/index.html`. Similarly, the same requests
against the `secondary` backend would route to `/secondary/index.html` on the
same host.

### Environment variables

Viceroy offers a subset of the environment variables available in Compute@Edge:

* `FASTLY_HOSTNAME`: in Viceroy, this is always set to `localhost`, which
  provides an easy way for guest code to detect it is running within Viceroy.
* `FASTLY_TRACE_ID`: in Viceroy, this is an ID starting from 0 and incrementing
  with each incoming request, providing each guest instance with its own unique
  ID.

## Limitations

At the moment, Viceroy does not support the full Compute@Edge API. In
particular:

* GeoIP is unsupported.
* Dictionaries are unsupported.
* Caching directives are ignored; no caching is ever performed.
* Information about the TLS connection from the client is not available.

## Colophon

![Viceroy](doc/logo.png)

The viceroy is a butterfly whose color and pattern mimics that of the monarch
butterfly but is smaller in size.
