#![warn(missing_docs, rust_2018_idioms, unreachable_pub)]
#![doc(test(no_crate_inject, attr(deny(rust_2018_idioms))))]

//! Async TLS streams
//!
//! This library is an implementation of TLS streams using the most appropriate
//! system library by default for negotiating the connection. That is, on
//! Windows this library uses SChannel, on OSX it uses SecureTransport, and on
//! other platforms it uses OpenSSL.
//!
//! Each TLS stream implements the `Read` and `Write` traits to interact and
//! interoperate with the rest of the futures I/O ecosystem. Client connections
//! initiated from this crate verify hostnames automatically and by default.
//!
//! This crate primarily exports this ability through two newtypes,
//! `TlsConnector` and `TlsAcceptor`. These newtypes augment the
//! functionality provided by the `native-tls` crate, on which this crate is
//! built. Configuration of TLS parameters is still primarily done through the
//! `native-tls` crate.

use futures::io::{AsyncRead, AsyncWrite, Initializer};
use native_tls::{HandshakeError, MidHandshakeTlsStream};
use std::fmt;
use std::future::Future;
use std::io::{self, Read, Write};
use std::marker::Unpin;
use std::pin::Pin;
use std::ptr::null_mut;
use std::task::{Context, Poll};

pub use native_tls::{Certificate, Error, Identity, Protocol};

#[derive(Debug)]
struct AllowStd<S> {
    inner: S,
    context: *mut (),
}

/// A wrapper around an underlying raw stream which implements the TLS or SSL
/// protocol.
///
/// A `TlsStream<S>` represents a handshake that has been completed successfully
/// and both the server and the client are ready for receiving and sending
/// data. Bytes read from a `TlsStream` are decrypted from `S` and bytes written
/// to a `TlsStream` are encrypted when passing through to `S`.
#[derive(Debug)]
pub struct TlsStream<S>(native_tls::TlsStream<AllowStd<S>>);

/// A wrapper around a `native_tls::TlsConnector`, providing an async `connect`
/// method.
#[derive(Clone)]
pub struct TlsConnector(native_tls::TlsConnector);

/// A wrapper around a `native_tls::TlsAcceptor`, providing an async `accept`
/// method.
#[derive(Clone)]
pub struct TlsAcceptor(native_tls::TlsAcceptor);

struct MidHandshake<S>(Option<MidHandshakeTlsStream<AllowStd<S>>>);

enum StartedHandshake<S> {
    Done(TlsStream<S>),
    Mid(MidHandshakeTlsStream<AllowStd<S>>),
}

struct StartedHandshakeFuture<F, S>(Option<StartedHandshakeFutureInner<F, S>>);
struct StartedHandshakeFutureInner<F, S> {
    f: F,
    stream: S,
}

struct Guard<'a, S>(&'a mut TlsStream<S>)
where
    AllowStd<S>: Read + Write;

impl<S> Drop for Guard<'_, S>
where
    AllowStd<S>: Read + Write,
{
    fn drop(&mut self) {
        (self.0).0.get_mut().context = null_mut();
    }
}

// *mut () context is neither Send nor Sync
unsafe impl<S: Send> Send for AllowStd<S> {}
unsafe impl<S: Sync> Sync for AllowStd<S> {}

impl<S> AllowStd<S>
where
    S: Unpin,
{
    fn with_context<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut Context<'_>, Pin<&mut S>) -> R,
    {
        unsafe {
            assert!(!self.context.is_null());
            let waker = &mut *(self.context as *mut _);
            f(waker, Pin::new(&mut self.inner))
        }
    }
}

impl<S> Read for AllowStd<S>
where
    S: AsyncRead + Unpin,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.with_context(|ctx, stream| stream.poll_read(ctx, buf)) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }
}

impl<S> Write for AllowStd<S>
where
    S: AsyncWrite + Unpin,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.with_context(|ctx, stream| stream.poll_write(ctx, buf)) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.with_context(|ctx, stream| stream.poll_flush(ctx)) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }
}

fn cvt<T>(r: io::Result<T>) -> Poll<io::Result<T>> {
    match r {
        Ok(v) => Poll::Ready(Ok(v)),
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
        Err(e) => Poll::Ready(Err(e)),
    }
}

impl<S> TlsStream<S> {
    fn with_context<F, R>(&mut self, ctx: &mut Context<'_>, f: F) -> R
    where
        F: FnOnce(&mut native_tls::TlsStream<AllowStd<S>>) -> R,
        AllowStd<S>: Read + Write,
    {
        self.0.get_mut().context = ctx as *mut _ as *mut ();
        let g = Guard(self);
        f(&mut (g.0).0)
    }

    /// Returns a shared reference to the inner stream.
    pub fn get_ref(&self) -> &S
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        &self.0.get_ref().inner
    }

    /// Returns a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut S
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        &mut self.0.get_mut().inner
    }
}

impl<S> AsyncRead for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    unsafe fn initializer(&self) -> Initializer {
        Initializer::nop()
    }

    fn poll_read(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.with_context(ctx, |s| cvt(s.read(buf)))
    }
}

impl<S> AsyncWrite for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.with_context(ctx, |s| cvt(s.write(buf)))
    }

    fn poll_flush(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.with_context(ctx, |s| cvt(s.flush()))
    }

    fn poll_close(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.with_context(ctx, |s| s.shutdown()) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

async fn handshake<F, S>(f: F, stream: S) -> Result<TlsStream<S>, Error>
where
    F: FnOnce(
            AllowStd<S>,
        ) -> Result<native_tls::TlsStream<AllowStd<S>>, HandshakeError<AllowStd<S>>>
        + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let start = StartedHandshakeFuture(Some(StartedHandshakeFutureInner { f, stream }));

    match start.await {
        Err(e) => Err(e),
        Ok(StartedHandshake::Done(s)) => Ok(s),
        Ok(StartedHandshake::Mid(s)) => MidHandshake(Some(s)).await,
    }
}

impl<F, S> Future for StartedHandshakeFuture<F, S>
where
    F: FnOnce(
            AllowStd<S>,
        ) -> Result<native_tls::TlsStream<AllowStd<S>>, HandshakeError<AllowStd<S>>>
        + Unpin,
    S: Unpin,
    AllowStd<S>: Read + Write,
{
    type Output = Result<StartedHandshake<S>, Error>;

    fn poll(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
    ) -> Poll<Result<StartedHandshake<S>, Error>> {
        let inner = self.0.take().expect("future polled after completion");
        let stream = AllowStd {
            inner: inner.stream,
            context: ctx as *mut _ as *mut (),
        };

        match (inner.f)(stream) {
            Ok(mut s) => {
                s.get_mut().context = null_mut();
                Poll::Ready(Ok(StartedHandshake::Done(TlsStream(s))))
            }
            Err(HandshakeError::WouldBlock(mut s)) => {
                s.get_mut().context = null_mut();
                Poll::Ready(Ok(StartedHandshake::Mid(s)))
            }
            Err(HandshakeError::Failure(e)) => Poll::Ready(Err(e)),
        }
    }
}

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
        self.inner
            .danger_accept_invalid_hostnames(accept_invalid_hostnames);
        self
    }

    /// Creates a new `TlsConnector`.
    pub fn build(&self) -> Result<TlsConnector, Error> {
        let connector = self.inner.build()?;
        Ok(TlsConnector(connector))
    }
}

impl TlsConnector {
    /// Returns a new connector with default settings.
    pub fn new() -> Result<TlsConnector, Error> {
        let native_connector = native_tls::TlsConnector::new()?;
        Ok(TlsConnector(native_connector))
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
    pub async fn connect<S>(&self, domain: &str, stream: S) -> Result<TlsStream<S>, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        handshake(|s| self.0.connect(domain, s), stream).await
    }
}

impl fmt::Debug for TlsConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConnector").finish()
    }
}

impl From<native_tls::TlsConnector> for TlsConnector {
    fn from(inner: native_tls::TlsConnector) -> TlsConnector {
        TlsConnector(inner)
    }
}

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
        let acceptor = self.inner.build()?;
        Ok(TlsAcceptor(acceptor))
    }
}

impl TlsAcceptor {
    /// Creates a acceptor with default settings.
    ///
    /// The identity acts as the server's private key/certificate chain.
    pub fn new(identity: Identity) -> Result<TlsAcceptor, Error> {
        let native_acceptor = native_tls::TlsAcceptor::new(identity)?;
        Ok(TlsAcceptor(native_acceptor))
    }

    /// Returns a new builder for a `TlsAcceptor`.
    ///
    /// The identity acts as the server's private key/certificate chain.
    pub fn builder(identity: Identity) -> TlsAcceptorBuilder {
        let builder = native_tls::TlsAcceptor::builder(identity);
        TlsAcceptorBuilder { inner: builder }
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
    pub async fn accept<S>(&self, stream: S) -> Result<TlsStream<S>, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        handshake(|s| self.0.accept(s), stream).await
    }
}

impl fmt::Debug for TlsAcceptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsAcceptor").finish()
    }
}

impl From<native_tls::TlsAcceptor> for TlsAcceptor {
    fn from(inner: native_tls::TlsAcceptor) -> TlsAcceptor {
        TlsAcceptor(inner)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Future for MidHandshake<S> {
    type Output = Result<TlsStream<S>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut_self = self.get_mut();
        let mut s = mut_self.0.take().expect("future polled after completion");

        s.get_mut().context = cx as *mut _ as *mut ();
        match s.handshake() {
            Ok(stream) => Poll::Ready(Ok(TlsStream(stream))),
            Err(HandshakeError::Failure(e)) => Poll::Ready(Err(e)),
            Err(HandshakeError::WouldBlock(mut s)) => {
                s.get_mut().context = null_mut();
                mut_self.0 = Some(s);
                Poll::Pending
            }
        }
    }
}
