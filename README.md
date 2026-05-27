# lbxdp

## Description
This little project was implemented mainly for educational purposes and is not intended to be a production-ready application, at least not yet.
It is a working prototype of a TCP load balancer based on an eBPF XDP program. It supports a least-connections balancing strategy and performs packet rewriting directly in the XDP path, before packets reach the normal kernel networking stack.

The project is intended to show how an XDP program can make forwarding decisions, rewrite packets, and share runtime configuration with a user-space loader through eBPF maps. The user-space component loads the program, attaches it to an interface, reads the local configuration, and fills maps such as the backend address lists and load balancer configuration.

## Working principle
Incoming requests are routed by NATing both IP and MAC addresses for the source and destination. For packets going from a client to a backend, the load balancer rewrites the destination to the selected backend. For packets returning from a backend to a client, it rewrites the source back to the load balancer address so the client sees a single stable endpoint.

The eBPF program keeps the active connection state in maps keyed by client/backend packet details. The main connection maps are used in both directions, so the program can recognize return traffic and send it back to the correct client. Backend IPs, backend MAC addresses, per-backend connection counters, and load balancer configuration are also stored in separate maps populated by user space.

To keep connection counters reasonably accurate, the program has a small TCP connection state machine. It tracks the SYN, SYN-ACK, and ACK phases of the TCP handshake, and also watches FIN and RST packets to detect connection shutdown. This is intentionally lightweight and only tracks enough state for the load balancer to associate packets with the selected backend, update connection maps as traffic develops, and maintain the least-connections counters.

## Limitations
- Clients, the load balancer, and the backends are expected to reside in the same LAN segment.
- Asymmetric traffic routing is not supported. Both client-to-load-balancer and backend-to-load-balancer traffic must pass through the load balancer, otherwise the eBPF program will not see enough packets to maintain connection state.
- The prototype assumes a small, fixed maximum number of backends configured through maps at startup.
- The implementation is focused on IPv4/TCP traffic and does not try to be a general-purpose L4 load balancer.

## Known bugs
- Since the source port is not NATed, there is a possibility, although quite low in a lab environment, that multiple clients open connections with the same source TCP port and get distributed to the same backend. In that case, those connections can collapse into a single entry in the connection maps.
- TCP state tracking is intentionally minimal. Unusual packet loss, retransmission patterns, or connections that do not follow the expected handshake/teardown flow may leave counters or map entries inaccurate.
- A stale connection map cleanup mechanism is not implemented.

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
