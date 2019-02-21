#![feature(async_await, await_macro, futures_api)]
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

use std::io::{self, Read, Write};
use std::pin::Pin;
use std::task::Waker;

use futures::Future;
use futures::compat::Compat;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use futures::Poll;
use log::debug;
use native_tls::{Error, HandshakeError, MidHandshakeTlsStream, TlsStream as NativeTlsStream};

pub type NativeWrapperStream<S> = NativeTlsStream<Compat<S>>;

/// A wrapper around an underlying raw stream which implements the TLS or SSL
/// protocol.
///
/// A `TlsStream<S>` represents a handshake that has been completed successfully
/// and both the server and the client are ready for receiving and sending
/// data. Bytes read from a `TlsStream` are decrypted from `S` and bytes written
/// to a `TlsStream` are encrypted when passing through to `S`.
#[derive(Debug)]
pub struct TlsStream<S> {
    inner: NativeWrapperStream<S>,
}

impl<S> TlsStream<S> {
    /// Get access to the internal `native_tls::TlsStream` stream which also
    /// transitively allows access to `S`.
    pub fn get_ref(&self) -> &NativeWrapperStream<S> {
        &self.inner
    }

    /// Get mutable access to the internal `native_tls::TlsStream` stream which
    /// also transitively allows mutable access to `S`.
    pub fn get_mut(&mut self) -> &mut NativeWrapperStream<S> {
        &mut self.inner
    }
}

impl<S: AsyncRead + AsyncWrite> AsyncRead for TlsStream<S> {
    fn poll_read(&mut self, _lw: &Waker, buf: &mut [u8])
                 -> Poll<Result<usize, io::Error>> {
        match self.inner.read(buf) {
            Ok(sz) => Poll::Ready(Ok(sz)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e))
        }
    }
}

impl<S: AsyncRead + AsyncWrite> AsyncWrite for TlsStream<S> {
    fn poll_write(&mut self, _lw: &Waker, buf: &[u8])
                  -> Poll<Result<usize, io::Error>> {
        match self.inner.write(buf) {
            Ok(sz) => Poll::Ready(Ok(sz)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e))
        }
    }

    fn poll_flush(&mut self, _lw: &Waker) -> Poll<Result<(), io::Error>> {
        match self.inner.flush() {
            Ok(sz) => Poll::Ready(Ok(sz)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e))
        }
    }

    fn poll_close(&mut self, _lw: &Waker) -> Poll<Result<(), io::Error>> {
        match self.inner.shutdown() {
            Ok(sz) => Poll::Ready(Ok(sz)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e))
        }
    }
}

/// A wrapper around a `native_tls::TlsConnector`, providing an async `connect`
/// method.
#[derive(Clone)]
pub struct TlsConnector {
    inner: native_tls::TlsConnector,
}

impl TlsConnector {
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
        where S: AsyncRead + AsyncWrite,
    {
        let connect_result = self.inner.connect(domain, stream.compat()).map(|i| {
            Handshake::Completed(i)
        });
        PendingTlsStream {
            inner: Some(connect_result)
        }
    }
}

impl From<native_tls::TlsConnector> for TlsConnector {
    fn from(inner: native_tls::TlsConnector) -> Self {
        Self {
            inner,
        }
    }
}

/// A wrapper around a `native_tls::TlsAcceptor`, providing an async `accept`
/// method.
#[derive(Clone)]
pub struct TlsAcceptor {
    inner: native_tls::TlsAcceptor,
}

impl TlsAcceptor {
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
        let accept_result = self.inner.accept(stream.compat()).map(|i| {
            Handshake::Completed(i)
        });
        PendingTlsStream {
            inner: Some(accept_result)
        }
    }
}

impl From<native_tls::TlsAcceptor> for TlsAcceptor {
    fn from(inner: native_tls::TlsAcceptor) -> Self {
        Self {
            inner,
        }
    }
}

pub enum Handshake<S> {
    Completed(NativeWrapperStream<S>),
    Midhandshake(MidHandshakeTlsStream<Compat<S>>)
}

pub struct PendingTlsStream<S> {
    inner: Option<Result<Handshake<S>, HandshakeError<Compat<S>>>>
}

impl<S: AsyncRead + AsyncWrite + Unpin + std::fmt::Debug> Future for PendingTlsStream<S> {
    type Output = Result<TlsStream<S>, Error>;

    fn poll(mut self: Pin<&mut Self>, _lw: &Waker) -> Poll<Self::Output> {
        let this: &mut Self = &mut *self;
        let inner = std::mem::replace(&mut this.inner, None);

        match inner.expect("Cannot poll handshake twice") {
            Ok(Handshake::Completed(native_stream)) => {
                debug!("Connection was completed");
                Poll::Ready(Ok(TlsStream { inner: native_stream }))
            }
            Ok(Handshake::Midhandshake(midhandshake_stream)) => {
                debug!("Connection was interrupted mid handshake, attempting handshake");
                match midhandshake_stream.handshake() {
                    Ok(native_stream) => {
                        debug!("Handshake completed, connection established");
                        Poll::Ready(Ok(TlsStream { inner: native_stream }))
                    },
                    Err(HandshakeError::Failure(e)) => Poll::Ready(Err(e)),
                    Err(HandshakeError::WouldBlock(midhandshake_stream)) => {
                        debug!("Handshake interrupted, {:?}", midhandshake_stream);
                        std::mem::replace(&mut this.inner, Some(Ok(Handshake::Midhandshake(midhandshake_stream))));
                        Poll::Pending
                    }
                }
            }
            Err(HandshakeError::Failure(e)) => Poll::Ready(Err(e)),
            Err(HandshakeError::WouldBlock(midhandshake_stream)) => {
                debug!("Handshake interrupted, {:?}", midhandshake_stream);
                std::mem::replace(&mut this.inner, Some(Ok(Handshake::Midhandshake(midhandshake_stream))));
                Poll::Pending
            }
        }
    }
}


