use std::net::ToSocketAddrs;

use futures::io::{AsyncReadExt, AsyncWriteExt};
use futures::FutureExt;
use futures_tokio_compat::Compat;
use tls_async::TlsConnector;
use tokio::net::TcpStream;
use tokio::runtime::Runtime;

fn main() {
    let runtime = Runtime::new().expect("Could not build runtime");

    let fut_result = async {
        let addr: std::net::SocketAddr = "www.rust-lang.org:443"
            .to_socket_addrs()
            .expect("not a valid address")
            .next()
            .expect("Not a valid address");

        let socket = Compat::new(TcpStream::connect(&addr).await.expect("Could not connect"));
        let cx = TlsConnector::builder().build().expect("Could not build");

        let mut socket = cx
            .connect("www.rust-lang.org", socket)
            .await
            .expect("Could not form tls connection");
        let _ = socket
            .write_all(
                b"\
            GET / HTTP/1.0\r\n\
            Host: www.rust-lang.org\r\n\
            \r\n\
        ",
            )
            .await;
        socket.flush().await.expect("Could not flush");
        let mut vec = vec![];
        socket.read_to_end(&mut vec).await.expect("Could not read");
        socket.close().await.expect("Could not close");
        vec
    };

    let data: Vec<u8> = runtime.block_on(fut_result.boxed());
    println!("{}", String::from_utf8_lossy(&data));
}
