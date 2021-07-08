FROM ubuntu:bionic

ARG VICEROY_SRC=/Viceroy

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
	build-essential \
	curl \
	git \
	ca-certificates \
	pkg-config \
	libssl-dev

# Setting a consistent LD_LIBRARY_PATH across the entire environment prevents
# unnecessary Cargo rebuilds.
ENV LD_LIBRARY_PATH=/usr/local/lib

# Install Rust, rustfmt, and the wasm32-wasi cross-compilation target
RUN curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain 1.52.1 -y
ENV PATH=/root/.cargo/bin:$PATH
RUN rustup component add rustfmt
RUN rustup target add wasm32-wasi

WORKDIR $VICEROY_SRC
