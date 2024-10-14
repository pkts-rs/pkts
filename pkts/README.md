# pkts

[![Latest Version]][crates.io] [![GHA Status]][GitHub Actions] [![Documentation]][docs.rs] [![pkts: rustc 1.65+]][Rust 1.65]

[Latest Version]: https://img.shields.io/crates/v/pkts.svg
[GitHub Actions]: https://github.com/pkts-rs/pkts/actions
[GHA Status]: https://github.com/pkts-rs/pkts/actions/workflows/full_ci.yaml/badge.svg
[crates.io]: https://crates.io/crates/pkts
[pkts: rustc 1.65+]: https://img.shields.io/badge/MSRV-rustc_1.65+-blue.svg
[Rust 1.65]: https://blog.rust-lang.org/2022/11/03/Rust-1.65.0.html
[Documentation]: https://docs.rs/pkts/badge.svg
[docs.rs]: https://docs.rs/pkts/


### **pkts - create, decode and modify network packet layers**

---

`pkts` provides ergonomic, `no-std`-friendly APIs for handling packets from a diverse range of
network protocols. It provides intuitive abstractions for handling packets that span multiple
protocol layers, and aims to be as easy to use as `scapy` (a Python packet parsing framework)
while also offering performant zero-allocation APIs suitable for embedded networking firmware.
`unsafe` code is explicitly forbidden in the library, but we're well aware this doesn't guarantee
the absence of potential Denial of Service threat vectors via `panic`s; as such, we're working on
integrating both fuzzing and symbolic model checking to test the correctness of packet parsing
implementations.

For those looking for packet capture/transmission functionality (similar to what `libpcap` or
`scapy` offer), the `rscap` crate provides cross-platform and rust-native APIs for such that
integrate well with `pkts`.

## Features

- **Robust APIs for building/modifying packets:** `pkts` provides simple operations to combine
various layers into a single packet, and to index into a different layers of a packet to retrieve
or modify fields. Users of [`scapy`](https://github.com/secdev/scapy) may find the API surprisingly
familiar, especially for layer composition and indexing operations:
```rust
use layers::{ip::Ipv4, tcp::Tcp};

let pkt = Ip::new() / Tcp::new();
pkt[Tcp].set_sport(80);
pkt[Tcp].set_dport(12345);
```
- **`no-std` Compatible:** every packet type in the `pkts` crate can be used without the standard
library, and a special `LayerRef` type can be used to access raw packet bytes without any
allocations. Packets can additionally be constructed from scratch in `no-std` environments using
allocation-free `Builder` patterns.
- **Packet defragmentation/reordering:** In some protocols, packets may be fragmented (such as IPv4)
or arrive out-of-order (TCP, SCTP, etc.). `pkts` overcomes both of these issues through `Sequence`
types that transparently handle defragmentation and reordering. `Sequence` types can even be stacked
so that application-layer data can easily be reassembled from captured packets. They even work in
`no-std` environments with or without an allocator.
- **Stateful packet support:** Many network protocols are stateful, and interpreting packets from
such protocols can be difficult (if not impossible) to accomplish unless information about the
protocol session is stored. `pkts` provides `Session` types that handle these kinds of
packets--`Session`s ensure that packets are validated based on the current expected state of the
protocol. Just like `Sequence`types, `Session` types are compatible with `no-std`/`no-alloc`
environments.

## Dependency Policy

Like other crates managed by pkts.org, `pkts` aims to rely on a minimal set of dependencies
that are vetted and well-used in the Rust ecosystem. As such, `pkts` makes use of only the
following dependencies:

* `bitflags` - Provides a simple, clean interface for accessing and modifying bitfields in packets.
Used extensively in the rust ecosystem (e.g. by `rustix`, `openssl`, `bindgen`, etc.)
* `pkts-macros` - Procedural macros used by `pkts`; nested dependencies are only `syn` and `quote`.
* `pkts-common` - Shared data types/methods for `pkts` and other crates; no nested dependencies.

We do not plan on adding in any additional dependencies to `pkts` in future releases, with the
exception of submodule libraries that break off individual pieces of functionality from `pkts` and
are maintained by pkts.org.

## License

This project is licensed under either of

* [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
  ([LICENSE-APACHE](https://github.com/rust-lang/libc/blob/HEAD/LICENSE-APACHE))

* [MIT License](https://opensource.org/licenses/MIT)
  ([LICENSE-MIT](https://github.com/rust-lang/libc/blob/HEAD/LICENSE-MIT))

at your option.

## Contributing

`pkts` is open to contribution--feel free to submit an issue or pull request if there's
something you'd like to add to the library.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
`pkts` by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without
any additional terms or conditions.

