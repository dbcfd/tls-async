use crate::errors::Error;
use crate::TlsStream;

use std::pin::Pin;
use std::task::Waker;

use futures::Future;
use futures::compat::Compat;
use futures::io::{AsyncRead, AsyncWrite};
use futures::Poll;
use log::debug;
use native_tls::{HandshakeError, MidHandshakeTlsStream};
pub use native_tls::{TlsConnector as NativeTlsConnector, TlsStream as NativeTlsStream};

enum Handshake<S> {
    Error(Error),
    Midhandshake(MidHandshakeTlsStream<Compat<S>>),
    Completed(NativeTlsStream<Compat<S>>),
}

impl<S> Handshake<S> {
    pub fn was_pending(&self) -> bool {
        if let Handshake::Midhandshake(_) = self {
            true
        } else {
            false
        }
    }
}

type NativeHandshake<S> = Result<NativeTlsStream<Compat<S>>, HandshakeError<Compat<S>>>;

impl<S> From<NativeHandshake<S>> for Handshake<S> {
    fn from(v: NativeHandshake<S>) -> Self {
        match v {
            Ok(native_stream) => Handshake::Completed(native_stream),
            Err(HandshakeError::Failure(e)) => Handshake::Error(Error::Handshake(e)),
            Err(HandshakeError::WouldBlock(midhandshake_stream)) => Handshake::Midhandshake(midhandshake_stream),
        }
    }
}

pub struct PendingTlsStream<S> {
    inner: Handshake<S>,
}

impl<S> PendingTlsStream<S> {
    pub fn new(inner: NativeHandshake<S>) -> Self {
        PendingTlsStream {
            inner: Handshake::from(inner)
        }
    }
    fn inner<'a>(self: Pin<&'a mut Self>) -> &'a mut Handshake<S> {
        unsafe {
            &mut Pin::get_unchecked_mut(self).inner
        }
    }
}

impl<S: AsyncRead + AsyncWrite + std::fmt::Debug> Future for PendingTlsStream<S> {
    type Output = Result<TlsStream<S>, Error>;

    fn poll(mut self: Pin<&mut Self>, _lw: &Waker) -> Poll<Self::Output> {
        loop {
            let handshake = std::mem::replace(self.as_mut().inner(), Handshake::Error(Error::RepeatedHandshake));
            match handshake {
                Handshake::Error(e) => return Poll::Ready(Err(e)),
                Handshake::Midhandshake(midhandshake_stream) => {
                    debug!("Connection was interrupted mid handshake, attempting handshake");
                    let res = Handshake::from(midhandshake_stream.handshake());
                    let was_pending = res.was_pending();
                    *self.as_mut().inner() = res;
                    if was_pending {
                        return Poll::Pending;
                    }
                }
                Handshake::Completed(native_stream) => {
                    debug!("Connection was completed");
                    return Poll::Ready(Ok(TlsStream { inner: native_stream }))
                }
            }
        }
    }
}


