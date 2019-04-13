use failure::Fail;

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display="NativeTls Acceptor Error")]
    Acceptor(#[cause] native_tls::Error),
    #[fail(display="NativeTls Connector Error")]
    Connector(#[cause] native_tls::Error),
    #[fail(display="Error during handshake")]
    Handshake(#[cause] native_tls::Error),
    #[fail(display="NativeTls Error")]
    Native(#[cause] native_tls::Error),
    #[fail(display="Cannot repeat handshake")]
    RepeatedHandshake,
}

unsafe impl Sync for Error {}
unsafe impl Send for Error {}