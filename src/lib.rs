//! Run a secret-handshake and return a box-stream encrypted connection.
//!
//! This library uses libsodium internally. In application code, call
//! [`sodiumoxide::init()`](https://dnaq.github.io/sodiumoxide/sodiumoxide/fn.init.html)
//! before using any functions from this module.

#![deny(missing_docs)]

extern crate secret_handshake;
extern crate box_stream;
#[macro_use]
extern crate futures;
extern crate tokio_io;
extern crate sodiumoxide;

use std::io;

use futures::{Future, Async, Poll};
use tokio_io::{AsyncRead, AsyncWrite};
use sodiumoxide::crypto::{sign, box_};
use secret_handshake::*;
use box_stream::*;

/// A future that initiates a secret-handshake and then yields a channel that
/// encrypts/decrypts all data via box-stream.
pub struct Client<'a, S>(ClientHandshaker<'a, S>);

impl<'a, S: AsyncRead + AsyncWrite> Client<'a, S> {
    /// Create a new `Client` to connect to a server with known public key
    /// and app key over the given `stream`.
    ///
    /// Ephemeral keypairs can be generated via
    /// `sodiumoxide::crypto::box_::gen_keypair`.
    pub fn new(stream: S,
               network_identifier: &'a [u8; NETWORK_IDENTIFIER_BYTES],
               client_longterm_pk: &'a sign::PublicKey,
               client_longterm_sk: &'a sign::SecretKey,
               client_ephemeral_pk: &'a box_::PublicKey,
               client_ephemeral_sk: &'a box_::SecretKey,
               server_longterm_pk: &'a sign::PublicKey)
               -> Client<'a, S> {
        Client(ClientHandshaker::new(stream,
                                     network_identifier,
                                     client_longterm_pk,
                                     client_longterm_sk,
                                     client_ephemeral_pk,
                                     client_ephemeral_sk,
                                     server_longterm_pk))
    }
}

impl<'a, S: AsyncRead + AsyncWrite> Future for Client<'a, S> {
    type Item = Result<BoxDuplex<S>, (ClientHandshakeFailure, S)>;
    type Error = (io::Error, S);

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let (res, stream) = try_ready!(self.0.poll());
        match res {
            Ok(outcome) => {
                Ok(Async::Ready(Ok(BoxDuplex::new(stream,
                                                  outcome.encryption_key(),
                                                  outcome.decryption_key(),
                                                  outcome.encryption_nonce(),
                                                  outcome.decryption_nonce()))))
            }
            Err(failure) => Ok(Async::Ready(Err((failure, stream)))),
        }
    }
}

/// A future that initiates a secret-handshake and then yields a channel that
/// encrypts/decrypts all data via box-stream.
///
/// This copies the handshake keys so that it is not constrained by the key's lifetime.
pub struct OwningClient<S>(OwningClientHandshaker<S>);

impl<S: AsyncRead + AsyncWrite> OwningClient<S> {
    /// Create a new `OwningClient` to connect to a server with known public key
    /// and app key over the given `stream`.
    ///
    /// This copies the handshake keys so that it is not constrained by the key's lifetime.
    ///
    /// Ephemeral keypairs can be generated via
    /// `sodiumoxide::crypto::box_::gen_keypair`.
    pub fn new(stream: S,
               network_identifier: &[u8; NETWORK_IDENTIFIER_BYTES],
               client_longterm_pk: &sign::PublicKey,
               client_longterm_sk: &sign::SecretKey,
               client_ephemeral_pk: &box_::PublicKey,
               client_ephemeral_sk: &box_::SecretKey,
               server_longterm_pk: &sign::PublicKey)
               -> OwningClient<S> {
        OwningClient(OwningClientHandshaker::new(stream,
                                                 network_identifier,
                                                 client_longterm_pk,
                                                 client_longterm_sk,
                                                 client_ephemeral_pk,
                                                 client_ephemeral_sk,
                                                 server_longterm_pk))
    }
}

impl<S: AsyncRead + AsyncWrite> Future for OwningClient<S> {
    type Item = Result<BoxDuplex<S>, (ClientHandshakeFailure, S)>;
    type Error = (io::Error, S);

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let (res, stream) = try_ready!(self.0.poll());
        match res {
            Ok(outcome) => {
                Ok(Async::Ready(Ok(BoxDuplex::new(stream,
                                                  outcome.encryption_key(),
                                                  outcome.decryption_key(),
                                                  outcome.encryption_nonce(),
                                                  outcome.decryption_nonce()))))
            }
            Err(failure) => Ok(Async::Ready(Err((failure, stream)))),
        }
    }
}

/// A future that accepts a secret-handshake and then yields a channel that
/// encrypts/decrypts all data via box-stream.
pub struct Server<'a, S>(ServerHandshaker<'a, S>);

impl<'a, S: AsyncRead + AsyncWrite> Server<'a, S> {
    /// Create a new `Server` to accept a connection from a client which knows
    /// the server's public key and uses the right app key over the given
    /// `stream`.
    ///
    /// Ephemeral keypairs can be generated via
    /// `sodiumoxide::crypto::box_::gen_keypair`.
    pub fn new(stream: S,
               network_identifier: &'a [u8; NETWORK_IDENTIFIER_BYTES],
               server_longterm_pk: &'a sign::PublicKey,
               server_longterm_sk: &'a sign::SecretKey,
               server_ephemeral_pk: &'a box_::PublicKey,
               server_ephemeral_sk: &'a box_::SecretKey)
               -> Server<'a, S> {
        Server(ServerHandshaker::new(stream,
                                     network_identifier,
                                     server_longterm_pk,
                                     server_longterm_sk,
                                     &server_ephemeral_pk,
                                     &server_ephemeral_sk))
    }
}

impl<'a, S: AsyncRead + AsyncWrite> Future for Server<'a, S> {
    /// On success, the result contains the encrypted connection and the
    /// longterm public key of the client.
    type Item = Result<(BoxDuplex<S>, sign::PublicKey), (ServerHandshakeFailure, S)>;
    type Error = (io::Error, S);

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let (res, stream) = try_ready!(self.0.poll());
        match res {
            Ok(outcome) => {
                Ok(Async::Ready(Ok((BoxDuplex::new(stream,
                                                   outcome.encryption_key(),
                                                   outcome.decryption_key(),
                                                   outcome.encryption_nonce(),
                                                   outcome.decryption_nonce()),
                                    outcome.peer_longterm_pk()))))
            }
            Err(failure) => Ok(Async::Ready(Err((failure, stream)))),
        }
    }
}

/// A future that accepts a secret-handshake based on a filter function and then
/// yields a channel that encrypts/decrypts all data via box-stream.
pub struct ServerFilter<'a, S, FilterFn, AsyncBool>(ServerHandshakerWithFilter<'a,
                                                                                S,
                                                                                FilterFn,
                                                                                AsyncBool>);

impl<'a, S, FilterFn, AsyncBool> ServerFilter<'a, S, FilterFn, AsyncBool>
    where S: AsyncRead + AsyncWrite,
          FilterFn: FnOnce(&sign::PublicKey) -> AsyncBool,
          AsyncBool: Future<Item = bool>
{
    /// Create a new `Server` to accept a connection from a client which knows
    /// the server's public key, uses the right app key over the given `stream`
    /// and whose longterm public key is accepted by the filter function.
    ///
    /// Ephemeral keypairs can be generated via
    /// `sodiumoxide::crypto::box_::gen_keypair`.
    pub fn new(stream: S,
               filter_fn: FilterFn,
               network_identifier: &'a [u8; NETWORK_IDENTIFIER_BYTES],
               server_longterm_pk: &'a sign::PublicKey,
               server_longterm_sk: &'a sign::SecretKey,
               server_ephemeral_pk: &'a box_::PublicKey,
               server_ephemeral_sk: &'a box_::SecretKey)
               -> ServerFilter<'a, S, FilterFn, AsyncBool> {
        ServerFilter(ServerHandshakerWithFilter::new(stream,
                                                     filter_fn,
                                                     network_identifier,
                                                     server_longterm_pk,
                                                     server_longterm_sk,
                                                     &server_ephemeral_pk,
                                                     &server_ephemeral_sk))
    }
}

impl<'a, S, FilterFn, AsyncBool> Future for ServerFilter<'a, S, FilterFn, AsyncBool>
    where S: AsyncRead + AsyncWrite,
          FilterFn: FnOnce(&sign::PublicKey) -> AsyncBool,
          AsyncBool: Future<Item = bool>
{
    /// On success, the result contains the encrypted connection and the
    /// longterm public key of the client.
    type Item = Result<(BoxDuplex<S>, sign::PublicKey), (ServerHandshakeFailureWithFilter, S)>;
    type Error = (ServerHandshakeError<AsyncBool::Error>, S);

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let (res, stream) = try_ready!(self.0.poll());
        match res {
            Ok(outcome) => {
                Ok(Async::Ready(Ok((BoxDuplex::new(stream,
                                                   outcome.encryption_key(),
                                                   outcome.decryption_key(),
                                                   outcome.encryption_nonce(),
                                                   outcome.decryption_nonce()),
                                    outcome.peer_longterm_pk()))))
            }
            Err(failure) => Ok(Async::Ready(Err((failure, stream)))),
        }
    }
}
