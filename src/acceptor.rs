use crate::errors::Error;
use crate::pending::PendingTlsStream;
use crate::{Identity, Protocol};

use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite};

/// A builder for `TlsAcceptor`s.
pub struct TlsAcceptorBuilder {
    inner: native_tls::TlsAcceptorBuilder,
}

impl TlsAcceptorBuilder {
    /// Sets the minimum supported protocol version.
    ///
    /// A value of `None` enables support for the oldest protocols supported by the implementation.
    ///
    /// Defaults to `Some(Protocol::Tlsv10)`.
    pub fn min_protocol_version(&mut self, protocol: Option<Protocol>) -> &mut TlsAcceptorBuilder {
        self.inner.min_protocol_version(protocol);
        self
    }

    /// Sets the maximum supported protocol version.
    ///
    /// A value of `None` enables support for the newest protocols supported by the implementation.
    ///
    /// Defaults to `None`.
    pub fn max_protocol_version(&mut self, protocol: Option<Protocol>) -> &mut TlsAcceptorBuilder {
        self.inner.max_protocol_version(protocol);
        self
    }

    /// Creates a new `TlsAcceptor`.
    pub fn build(&self) -> Result<TlsAcceptor, Error> {
        let acceptor = self.inner.build().map_err(Error::Acceptor)?;
        Ok(TlsAcceptor {
            inner: acceptor
        })
    }
}

/// A builder for server-side TLS connections.
///
/// # Examples
///
/// ```rust,no_run
/// #![feature(async_await, await_macro, futures_api)]
/// use futures::StreamExt;
/// use futures::io::AsyncRead;
/// use tls_async::{Identity, TlsAcceptor, TlsStream};
/// use std::fs::File;
/// use std::io::{Read};
/// use romio::{TcpListener, TcpStream};
/// use std::sync::Arc;
/// use std::thread;
///
/// let mut file = File::open("identity.pfx").unwrap();
/// let mut identity = vec![];
/// file.read_to_end(&mut identity).unwrap();
/// let identity = Identity::from_pkcs12(&identity, "hunter2").unwrap();
///
/// let mut listener = TcpListener::bind(&"0.0.0.0:8443".parse().unwrap()).unwrap();
/// let acceptor = TlsAcceptor::new(identity).unwrap();
/// let acceptor = Arc::new(acceptor);
///
/// fn handle_client<S: AsyncRead>(stream: S) {
///     // ...
/// }
///
/// let mut incoming = listener.incoming();
/// # futures::executor::block_on(async {
/// for stream in await!(incoming.next()) {
///     match stream {
///         Ok(stream) => {
///             let acceptor = acceptor.clone();
///             let stream = await!(acceptor.accept(stream)).unwrap();
///             handle_client(stream);
///         }
///         Err(e) => { /* connection failed */ }
///     }
/// }
/// # })
/// ```
#[derive(Clone)]
pub struct TlsAcceptor {
    inner: native_tls::TlsAcceptor,
}

impl TlsAcceptor {
    /// Creates a acceptor with default settings.
    ///
    /// The identity acts as the server's private key/certificate chain.
    pub fn new(identity: Identity) -> Result<TlsAcceptor, Error> {
        let native_acceptor = native_tls::TlsAcceptor::new(identity).map_err(Error::Acceptor)?;
        Ok(TlsAcceptor {
            inner: native_acceptor,
        })
    }

    /// Returns a new builder for a `TlsAcceptor`.
    ///
    /// The identity acts as the server's private key/certificate chain.
    pub fn builder(identity: Identity) -> TlsAcceptorBuilder {
        let builder = native_tls::TlsAcceptor::builder(identity);
        TlsAcceptorBuilder {
            inner: builder,
        }
    }

    /// Accepts a new client connection with the provided stream.
    ///
    /// This function will internally call `TlsAcceptor::accept` to connect
    /// the stream and returns a future representing the resolution of the
    /// connection operation. The returned future will resolve to either
    /// `TlsStream<S>` or `Error` depending if it's successful or not.
    ///
    /// This is typically used after a new socket has been accepted from a
    /// `TcpListener`. That socket is then passed to this function to perform
    /// the server half of accepting a client connection.
    pub fn accept<S>(&self, stream: S) -> PendingTlsStream<S>
        where S: AsyncRead + AsyncWrite,
    {
        PendingTlsStream::new(self.inner.accept(stream.compat()))
    }
}

impl From<native_tls::TlsAcceptor> for TlsAcceptor {
    fn from(inner: native_tls::TlsAcceptor) -> Self {
        Self {
            inner,
        }
    }
}