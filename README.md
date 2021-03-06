# tls-async

[![build status][travis-badge]][travis-url]
[![crates.io version][crates-badge]][crates-url]
[![docs.rs docs][docs-badge]][docs-url]
[![MIT licensed][mit-badge]][mit-url]

This is an experimental fork of [tokio-tls](https://github.com/tokio-rs/tokio/tree/master/tokio-tls) on top of [Futures 0.3](https://github.com/rust-lang-nursery/futures-rs) AsyncRead, AsyncWrite, and Compat. It is primarily intended for usage with [Romio](https://github.com/withoutboats/romio).

An implementation of TLS/SSL streams for [Futures 0.3](https://github.com/rust-lang-nursery/futures-rs) built on top of the [`native-tls`
crate]

[Documentation](https://docs.rs/tls-async/0.3.0-alpha.5/)

[`native-tls` crate]: https://github.com/sfackler/rust-native-tls

[travis-badge]: https://travis-ci.com/dbcfd/tls-async.svg?branch=master
[travis-url]: https://travis-ci.com/dbcfd/tls-async
[crates-badge]: https://img.shields.io/crates/v/tls-async.svg?style=flat-square
[crates-url]: https://crates.io/crates/tls-async
[docs-badge]: https://img.shields.io/badge/docs.rs-latest-blue.svg?style=flat-square
[docs-url]: https://docs.rs/tls-async
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square
[mit-url]: LICENSE-MIT

## Usage

First, add this to your `Cargo.toml`:

```toml
[dependencies]
tls-async = "0.3.0-alpha.5"
```

Next, add this to your crate:

```rust
use tls_async::{TlsConnector, TlsAcceptor};
```

You can find few examples how to use this crate in tests directory.

By default the `native-tls` crate currently uses the "platform appropriate"
backend for a TLS implementation. This means:

* On Windows, [SChannel] is used
* On OSX, [SecureTransport] is used
* Everywhere else, [OpenSSL] is used

[SChannel]: https://msdn.microsoft.com/en-us/library/windows/desktop/aa380123%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
[SecureTransport]: https://developer.apple.com/reference/security/1654508-secure_transport
[OpenSSL]: https://www.openssl.org/

Typically these selections mean that you don't have to worry about a portability
when using TLS, these libraries are all normally installed by default.

## License

This project is licensed under the [MIT license](./LICENSE).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in tls-async by you, shall be licensed as MIT, without any additional
terms or conditions.
