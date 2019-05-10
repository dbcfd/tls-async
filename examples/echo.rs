#![feature(async_await)]
// A tiny async TLS echo server with Tokio
use futures::{FutureExt, TryFutureExt, StreamExt};
use futures::io::AsyncReadExt;
use native_tls::Identity;

async fn accept_connections() -> () {
    // Bind the server's socket
    let addr = "127.0.0.1:12345".parse().expect("Failed to parse address");
    let mut tcp = romio::TcpListener::bind(&addr).expect("Failed to bind");

    // Create the TLS acceptor.
    let der = include_bytes!("identity.p12");
    let cert = Identity::from_pkcs12(der, "mypass").expect("Failed to create identity");
    let tls_acceptor = tls_async::TlsAcceptor::from(
        native_tls::TlsAcceptor::builder(cert).build().expect("Failed to build native acceptor")
    );

    // Iterate incoming connections
    let mut tcp_incoming = tcp.incoming();
    while let Some(tcp) = tcp_incoming.next().await {
        let tcp = tcp.expect("Error encountered while fetching next");
        let tcp = tls_acceptor.accept(tcp);
        let tls = async {
            let tls = tcp.await.expect("Failed to form tls connection");
            // Split up the read and write halves
            let (mut reader, mut writer) = tls.split();

            // Copy the data back to the client
            match reader.copy_into(&mut writer).await {
                Ok(n) => println!("wrote {} bytes", n),
                Err(err) => println!("IO error {:?}", err)
            }
        };
        tokio::spawn(tls.boxed().unit_error().compat());
    }
}

fn main() {
    let mut rt = tokio::runtime::Runtime::new().expect("Failed to build runtime");

    // Start the runtime and spin up the server
    rt.block_on(accept_connections().boxed().unit_error().compat()).expect("Failed to run");
}
