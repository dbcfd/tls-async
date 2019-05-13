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
#![feature(async_await)]
mod acceptor;
mod connector;
mod errors;
mod pending;

pub use acceptor::TlsAcceptor as TlsAcceptor;
pub use connector::TlsConnector as TlsConnector;
pub use errors::Error as Error;

use std::io::{self, Read, Write};
use std::pin::Pin;
use std::task::Context;

use futures::compat::Compat;
use futures::io::{AsyncRead, AsyncWrite};
use futures::Poll;
pub use native_tls::{Certificate as Certificate, Identity as Identity, Protocol as Protocol};

/// A wrapper around an underlying raw stream which implements the TLS or SSL
/// protocol.
///
/// A `TlsStream<S>` represents a handshake that has been completed successfully
/// and both the server and the client are ready for receiving and sending
/// data. Bytes read from a `TlsStream` are decrypted from `S` and bytes written
/// to a `TlsStream` are encrypted when passing through to `S`.
#[derive(Debug)]
pub struct TlsStream<S> {
    inner: native_tls::TlsStream<Compat<S>>,
}

impl<S> TlsStream<S> {
    /// Get access to the internal `native_tls::TlsStream` stream which also
    /// transitively allows access to `S`.
    pub fn get_ref(&self) -> &native_tls::TlsStream<Compat<S>> {
        &self.inner
    }

    /// Get mutable access to the internal `native_tls::TlsStream` stream which
    /// also transitively allows mutable access to `S`.
    pub fn get_mut(&mut self) -> &mut native_tls::TlsStream<Compat<S>> {
        &mut self.inner
    }

    fn inner<'a>(self: Pin<&'a mut Self>) -> &'a mut native_tls::TlsStream<Compat<S>> {
        unsafe {
            &mut Pin::get_unchecked_mut(self).inner
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut [u8])
                 -> Poll<Result<usize, io::Error>> {
        match self.as_mut().inner().read(buf) {
            Ok(sz) => Poll::Ready(Ok(sz)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e))
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8])
                  -> Poll<Result<usize, io::Error>> {
        match self.as_mut().inner().write(buf) {
            Ok(sz) => Poll::Ready(Ok(sz)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e))
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match self.as_mut().inner().flush() {
            Ok(sz) => Poll::Ready(Ok(sz)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e))
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match self.as_mut().inner().shutdown() {
            Ok(sz) => Poll::Ready(Ok(sz)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e))
        }
    }
}
