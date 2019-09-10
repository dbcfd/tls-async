use std::net::ToSocketAddrs;

use cfg_if::cfg_if;
use futures::io::{AsyncReadExt, AsyncWriteExt};
use futures::FutureExt;
use futures_tokio_compat::Compat;
use tls_async::{Error, TlsConnector};
use tokio::net::TcpStream;

fn check_cause(err: Error, s: &str) {
    assert!(
        err.to_string().contains(s),
        "Error {} did not contain {}",
        err,
        s
    );
}

macro_rules! t {
    ($e:expr) => {
        match $e {
            Ok(e) => e,
            Err(e) => panic!("{} failed with {:?}", stringify!($e), e),
        }
    };
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
            let err = err.to_string();
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

        let socket = Compat::new(t!(TcpStream::connect(&addr).await));

        println!("Connected to google");

        // Send off the request by first negotiating an SSL handshake, then writing
        // of our request, then flushing, then finally read off the response.
        let builder = TlsConnector::builder();
        let connector = t!(builder.build());

        println!("Attempting tls connection");

        let mut stream = t!(connector.connect("google.com", socket).await);
        t!(stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await);
        t!(stream.flush().await);
        let mut buf = vec![];
        t!(stream.read_to_end(&mut buf).await);
        t!(stream.close().await);
        buf
    };

    let rt = t!(tokio::runtime::Runtime::new());
    let data = t!(rt.block_on(fut_result.fuse().boxed().unit_error()));

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
        let socket = Compat::new(t!(TcpStream::connect(&addr).await));
        let builder = TlsConnector::builder();
        let connector = t!(builder.build());
        connector.connect("rust-lang.org", socket).await
    };

    let rt = t!(tokio::runtime::Runtime::new());
    let res = rt.block_on(fut_result.fuse().boxed());

    assert!(res.is_err());
    assert_bad_hostname_error(res.err().unwrap());
}
