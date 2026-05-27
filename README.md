# lbxdp

## Description
This little project was implemented on educational purposes mainly, and not intended to become a real production ready application (as of yet at least :))
This is a working prototype of TCP load balancer supporting least connection load balancing algorithm,  based on eBPF xdp application. 

## Working priniple
Incoming requests routed by means of NATing ip and mac addresses for both source and destination. We keep track of all active connection and update connection map along with tcp connection develops.
We keep backends active connections in a separate map, that provides least connection lb algorithm.

## Limitations
- Clients, Load Balancer and Backends are expected to reside in the same LAN segment
- Assymetric traffic routing would be an issue. Both client-to-lb and lb-to-client traffic must go through Load  Balancer.

## Known bugs:
- Given that source port is not NATed, there is a likebility (quite low in lab environment), that multiple clients open connections with the same source tcp port, and get distributed to the same backend. In this case these connections would collapse in single one in connections maps.   

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package lbxdp --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/lbxdp` can be
copied to a Linux server or VM and run there.

## License

With the exception of eBPF code, lbxdp is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
