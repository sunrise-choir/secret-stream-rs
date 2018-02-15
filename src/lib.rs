// TODO enforce docs
// TODO document that libsodium_init needs to be called before using this

/// A future that initiates a secret-handshake and then yields a channel that
/// encrypts/decrypts all data via box-stream.
pub struct Client {}
