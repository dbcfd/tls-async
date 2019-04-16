use crate::errors::Error;
use crate::pending::PendingTlsStream;
use crate::{Certificate, Identity, Protocol};

use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite};

/// A builder for `TlsConnector`s.
pub struct TlsConnectorBuilder {
    inner: native_tls::TlsConnectorBuilder,
}

impl TlsConnectorBuilder {
    /// Sets the identity to be used for client certificate authentication.
    pub fn identity(&mut self, identity: Identity) -> &mut TlsConnectorBuilder {
        self.inner.identity(identity);
        self
    }

    /// Sets the minimum supported protocol version.
    ///
    /// A value of `None` enables support for the oldest protocols supported by the implementation.
    ///
    /// Defaults to `Some(Protocol::Tlsv10)`.
    pub fn min_protocol_version(&mut self, protocol: Option<Protocol>) -> &mut TlsConnectorBuilder {
        self.inner.min_protocol_version(protocol);
        self
    }

    /// Sets the maximum supported protocol version.
    ///
    /// A value of `None` enables support for the newest protocols supported by the implementation.
    ///
    /// Defaults to `None`.
    pub fn max_protocol_version(&mut self, protocol: Option<Protocol>) -> &mut TlsConnectorBuilder {
        self.inner.max_protocol_version(protocol);
        self
    }

    /// Adds a certificate to the set of roots that the connector will trust.
    ///
    /// The connector will use the system's trust root by default. This method can be used to add
    /// to that set when communicating with servers not trusted by the system.
    ///
    /// Defaults to an empty set.
    pub fn add_root_certificate(&mut self, cert: Certificate) -> &mut TlsConnectorBuilder {
        self.inner.add_root_certificate(cert);
        self
    }

    /// Controls the use of certificate validation.
    ///
    /// Defaults to `false`.
    ///
    /// # Warning
    ///
    /// You should think very carefully before using this method. If invalid certificates are trusted, *any*
    /// certificate for *any* site will be trusted for use. This includes expired certificates. This introduces
    /// significant vulnerabilities, and should only be used as a last resort.
    pub fn danger_accept_invalid_certs(
        &mut self,
        accept_invalid_certs: bool,
    ) -> &mut TlsConnectorBuilder {
        self.inner.danger_accept_invalid_certs(accept_invalid_certs);
        self
    }

    /// Controls the use of Server Name Indication (SNI).
    ///
    /// Defaults to `true`.
    pub fn use_sni(&mut self, use_sni: bool) -> &mut TlsConnectorBuilder {
        self.inner.use_sni(use_sni);
        self
    }

    /// Controls the use of hostname verification.
    ///
    /// Defaults to `false`.
    ///
    /// # Warning
    ///
    /// You should think very carefully before using this method. If invalid hostnames are trusted, *any* valid
    /// certificate for *any* site will be trusted for use. This introduces significant vulnerabilities, and should
    /// only be used as a last resort.
    pub fn danger_accept_invalid_hostnames(
        &mut self,
        accept_invalid_hostnames: bool,
    ) -> &mut TlsConnectorBuilder {
        self.inner.danger_accept_invalid_hostnames(accept_invalid_hostnames);
        self
    }

    /// Creates a new `TlsConnector`.
    pub fn build(&self) -> Result<TlsConnector, Error> {
        let connector = self.inner.build().map_err(Error::Connector)?;
        Ok(TlsConnector {
            inner: connector
        })
    }
}

///
/// # Examples
///
/// ```rust,no_run
/// #![feature(async_await, await_macro, futures_api)]
/// use futures::io::{AsyncReadExt, AsyncWriteExt};
/// use tls_async::TlsConnector;
/// use std::io::{Read, Write};
/// use std::net::ToSocketAddrs;
/// use romio::TcpStream;
///
/// # futures::executor::block_on(async {
/// let connector = TlsConnector::new().unwrap();
///
/// let addr = "google.com:443".to_socket_addrs().unwrap().next().unwrap();
/// let stream = await!(TcpStream::connect(&addr)).unwrap();
/// let mut stream = await!(connector.connect("google.com", stream)).unwrap();
///
/// await!(stream.write_all(b"GET / HTTP/1.0\r\n\r\n")).unwrap();
/// let mut res = vec![];
/// await!(stream.read_to_end(&mut res)).unwrap();
/// println!("{}", String::from_utf8_lossy(&res));
/// # })
/// ```
#[derive(Clone)]
pub struct TlsConnector {
    inner: native_tls::TlsConnector,
}

impl TlsConnector {
    /// Returns a new connector with default settings.
    pub fn new() -> Result<TlsConnector, Error> {
        let native_connector = native_tls::TlsConnector::new().map_err(Error::Connector)?;
        Ok( TlsConnector {
            inner: native_connector,
        })
    }

    /// Returns a new builder for a `TlsConnector`.
    pub fn builder() -> TlsConnectorBuilder {
        TlsConnectorBuilder {
            inner: native_tls::TlsConnector::builder(),
        }
    }

    /// Connects the provided stream with this connector, assuming the provided
    /// domain.
    ///
    /// This function will internally call `TlsConnector::connect` to connect
    /// the stream and returns a future representing the resolution of the
    /// connection operation. The returned future will resolve to either
    /// `TlsStream<S>` or `Error` depending if it's successful or not.
    ///
    /// This is typically used for clients who have already established, for
    /// example, a TCP connection to a remote server. That stream is then
    /// provided here to perform the client half of a connection to a
    /// TLS-powered server.
    pub fn connect<'a, S>(&'a self, domain: &'a str, stream: S) -> PendingTlsStream<S>
        where S: AsyncRead + AsyncWrite + Unpin,
    {
        PendingTlsStream::new(self.inner.connect(domain, stream.compat()))
    }
}