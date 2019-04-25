#![feature(async_await, await_macro)]
use std::net::ToSocketAddrs;

use cfg_if::cfg_if;
use futures::{FutureExt, TryFutureExt};
use futures::io::{AsyncReadExt, AsyncWriteExt};
use romio::TcpStream;
use tls_async::{Error, TlsConnector};

fn check_cause(err: Error, s: &str) {
    match err {
        Error::Handshake(e) => {
            let err = e.to_string();
            assert!(e.to_string().contains(s), "Error {} did not contain {}", err, s);
        }
        _ => panic!("Error {:?} was not a handshake error")
    }
}

macro_rules! t {
    ($e:expr) => (match $e {
        Ok(e) => e,
        Err(e) => panic!("{} failed with {:?}", stringify!($e), e),
    })
}

cfg_if! {
    if #[cfg(feature = "force-rustls")] {
        fn assert_bad_hostname_error(err: Error) {
            check_cause(err, "CertNotValidForName");
        }
    } else if #[cfg(any(feature = "force-openssl",
                        all(not(target_os = "macos"),
                            not(target_os = "windows"),
                            not(target_os = "ios"))))] {
        extern crate openssl;

        fn assert_bad_hostname_error(err: Error) {
            check_cause(err, "certificate verify failed");
        }
    } else if #[cfg(any(target_os = "macos", target_os = "ios"))] {
        fn assert_bad_hostname_error(err: Error) {
            check_cause(err, "was not trusted.");
        }
    } else {
        fn assert_bad_hostname_error(err: Error) {
            let err = err.compat().to_string();
            check_cause(err, "CN name");
        }
    }
}

#[test]
fn fetch_google() {
    drop(env_logger::try_init());

    let fut_result = async {
        // First up, resolve google.com
        let addr = t!("google.com:443".to_socket_addrs()).next().unwrap();

        let socket = t!(await!(TcpStream::connect(&addr)));

        println!("Connected to google");

        // Send off the request by first negotiating an SSL handshake, then writing
        // of our request, then flushing, then finally read off the response.
        let builder = TlsConnector::builder();
        let connector = t!(builder.build());

        println!("Attempting tls connection");

        let mut stream = t!(await!(connector.connect("google.com", socket)));
        t!(await!(stream.write_all(b"GET / HTTP/1.0\r\n\r\n")));
        t!(await!(stream.flush()));
        let mut buf = vec![];
        t!(await!(stream.read_to_end(&mut buf)));
        t!(await!(stream.close()));
        buf
    };

    let mut rt = t!(tokio::runtime::Runtime::new());
    let data = t!(rt.block_on(fut_result.fuse().boxed().unit_error().compat()));

    println!("Data={}", String::from_utf8_lossy(&data));

    // any response code is fine
    assert!(data.starts_with(b"HTTP/1.0 "));

    let data = String::from_utf8_lossy(&data);
    let data = data.trim_end();
    assert!(data.ends_with("</html>") || data.ends_with("</HTML>"));
}

// see comment in bad.rs for ignore reason
#[cfg_attr(all(target_os = "macos", feature = "force-openssl"), ignore)]
#[test]
fn wrong_hostname_error() {
    drop(env_logger::try_init());

    let fut_result = async {
        let addr = t!("google.com:443".to_socket_addrs()).next().unwrap();
        let socket = t!(await!(TcpStream::connect(&addr)));
        let builder = TlsConnector::builder();
        let connector = t!(builder.build());
        await!(connector.connect("rust-lang.org", socket))
    };

    let mut rt = t!(tokio::runtime::Runtime::new());
    let res = rt.block_on(fut_result.fuse().boxed().compat());

    assert!(res.is_err());
    assert_bad_hostname_error(res.err().unwrap());
}
