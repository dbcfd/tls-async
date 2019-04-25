#![feature(async_await, await_macro)]
use std::net::ToSocketAddrs;

use cfg_if::cfg_if;
use futures::{FutureExt, TryFutureExt};
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
        fn assert_expired_error(err: Error) {
            check_cause(err, "CertExpired");
        }

        fn assert_wrong_host(err: Error) {
            check_cause(err, "CertNotValidForName");
        }

        fn assert_self_signed(err: Error) {
            check_cause(err, "UnknownIssuer");
        }

        fn assert_untrusted_root(err: Error) {
            check_cause(err, "UnknownIssuer");
        }
    } else if #[cfg(any(feature = "force-openssl",
                        all(not(target_os = "macos"),
                            not(target_os = "windows"),
                            not(target_os = "ios"))))] {
        use openssl;

        fn verify_failed(err: Error) {
            check_cause(err, "certificate verify failed")        ;
        }

        use self::verify_failed as assert_expired_error;
        use self::verify_failed as assert_wrong_host;
        use self::verify_failed as assert_self_signed;
        use self::verify_failed as assert_untrusted_root;
    } else if #[cfg(any(target_os = "macos", target_os = "ios"))] {

        fn assert_invalid_cert_chain(err: Error) {
            check_cause(err, "was not trusted.");
        }

        use self::assert_invalid_cert_chain as assert_expired_error;
        use self::assert_invalid_cert_chain as assert_wrong_host;
        use self::assert_invalid_cert_chain as assert_self_signed;
        use self::assert_invalid_cert_chain as assert_untrusted_root;
    } else {
        fn assert_expired_error(err: Error) {
            check_cause(err, "system clock");
        }

        fn assert_wrong_host(err: Error) {
            check_cause(err, "CN name");
        }

        fn assert_self_signed(err: Error) {
            check_cause(err, "root certificate which is not trusted");
        }

        use self::assert_self_signed as assert_untrusted_root;
    }
}

async fn get_host(host: String) -> Result<(), Error> {
    drop(env_logger::try_init());

    let addr = format!("{}:443", host);
    let addr = t!(addr.to_socket_addrs()).next().unwrap();

    let socket = t!(await!(TcpStream::connect(&addr)));
    let builder = TlsConnector::builder();
    let cx = t!(builder.build());
    await!(cx.connect(&host, socket))?;
    Ok(())
}

#[test]
fn expired() {
    let fut_res = async {
        await!(get_host("expired.badssl.com".to_owned()))
    };
    let mut rt = t!(tokio::runtime::Runtime::new());
    let res = rt.block_on(fut_res.boxed().compat());

    assert!(res.is_err());
    assert_expired_error(res.err().unwrap());
}

// TODO: the OSX builders on Travis apparently fail this tests spuriously?
//       passes locally though? Seems... bad!
#[test]
#[cfg_attr(all(target_os = "macos", feature = "force-openssl"), ignore)]
fn wrong_host() {
    let fut_res = async {
        await!(get_host("wrong.host.badssl.com".to_owned()))
    };
    let mut rt = t!(tokio::runtime::Runtime::new());
    let res = rt.block_on(fut_res.boxed().compat());

    assert!(res.is_err());
    assert_wrong_host(res.err().unwrap());
}

#[test]
fn self_signed() {
    let fut_res = async {
        await!(get_host("self-signed.badssl.com".to_owned()))
    };
    let mut rt = t!(tokio::runtime::Runtime::new());
    let res = rt.block_on(fut_res.boxed().compat());

    assert!(res.is_err());
    assert_self_signed(res.err().unwrap());
}

#[test]
fn untrusted_root() {
    let fut_res = async {
        await!(get_host("untrusted-root.badssl.com".to_owned()))
    };
    let mut rt = t!(tokio::runtime::Runtime::new());
    let res = rt.block_on(fut_res.boxed().compat());

    assert!(res.is_err());
    assert_untrusted_root(res.err().unwrap());
}
