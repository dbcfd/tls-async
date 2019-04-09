#![feature(async_await, await_macro, futures_api)]
use std::net::ToSocketAddrs;

use futures::{FutureExt, TryFutureExt};
use futures::io::{AsyncReadExt, AsyncWriteExt};
use romio::TcpStream;
use tls_async::TlsConnector;
use tokio::runtime::Runtime;

fn main() {
    let mut runtime = Runtime::new().expect("Could not build runtime");

    let fut_result = async {
        let addr: std::net::SocketAddr = "www.rust-lang.org:443"
            .to_socket_addrs()
            .expect("not a valid address")
            .next()
            .expect("Not a valid address");

        let socket = await!(TcpStream::connect(&addr)).expect("Could not connect");
        let cx = TlsConnector::builder().build().expect("Could not build");

        let mut socket = await!(cx.connect("www.rust-lang.org", socket)).expect("Could not form tls connection");
        let _ = await!(socket.write_all(b"\
            GET / HTTP/1.0\r\n\
            Host: www.rust-lang.org\r\n\
            \r\n\
        "));
        await!(socket.flush()).expect("Could not flush");
        let mut vec = vec![];
        await!(socket.read_to_end(&mut vec)).expect("Could not read");
        await!(socket.close()).expect("Could not close");
        vec
    };

    let data: Vec<u8> = runtime.block_on(fut_result.boxed().unit_error().compat()).expect("Could not run");
    println!("{}", String::from_utf8_lossy(&data));
}
