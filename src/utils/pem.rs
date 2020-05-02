// This file is based on code from rustls 0.16.0. (Licensed Apache 2.0, MIT, ISC)

use crate::crypto::SigningAlgorithm;
use crate::utils::keys::KeyPairExt;
use err_derive::Error;
use ring::signature::{Ed25519KeyPair, RsaKeyPair};
use std::io::{BufRead, Cursor, Error as IoError, Read};

const RSA_START_MARK: &str = "-----BEGIN RSA PRIVATE KEY-----";
const RSA_END_MARK: &str = "-----END RSA PRIVATE KEY-----";
const PKCS8_START_MARK: &str = "-----BEGIN PRIVATE KEY-----";
const PKCS8_END_MARK: &str = "-----END PRIVATE KEY-----";

pub enum ParsedKeyPair {
    Ed25519(Ed25519KeyPair),
    Rsa(RsaKeyPair),
}

impl ParsedKeyPair {
    /// Get the signing algorithm for this key type.
    pub fn signing_alg(&self) -> SigningAlgorithm {
        use ParsedKeyPair::*;
        match self {
            Ed25519(ref inner) => inner.signing_alg(),
            Rsa(ref inner) => inner.signing_alg(),
        }
    }
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error(display = "IO error: {}", _0)]
    Io(#[error(source)] IoError),
    #[error(display = "invalid base64: {}", _0)]
    Base64(#[error(source)] base64::DecodeError),
    #[error(display = "invalid private key: {}", _0)]
    KeyRejected(#[error(from)] ring::error::KeyRejected),
}

enum State {
    Scan,
    InPkcs8,
    InRsa,
}

/// Parse all supported key pairs from a PEM stream.
pub fn parse_key_pairs(mut reader: impl BufRead) -> Result<Vec<ParsedKeyPair>, ParseError> {
    let mut key_pairs = Vec::new();
    let mut b64buf = String::new();
    let mut state = State::Scan;

    let mut raw_line = Vec::<u8>::new();
    loop {
        raw_line.clear();
        let len = reader.read_until(b'\n', &mut raw_line)?;

        if len == 0 {
            return Ok(key_pairs);
        }
        let line = String::from_utf8_lossy(&raw_line);

        match state {
            State::Scan => {
                if line.starts_with(PKCS8_START_MARK) {
                    state = State::InPkcs8;
                }
                if line.starts_with(RSA_START_MARK) {
                    state = State::InRsa;
                }
            }
            State::InPkcs8 => {
                if line.starts_with(PKCS8_END_MARK) {
                    state = State::Scan;
                    let der = base64::decode(&b64buf)?;
                    let key_pair = Ed25519KeyPair::from_pkcs8(&der)
                        .map(ParsedKeyPair::Ed25519)
                        .or_else(|_| RsaKeyPair::from_pkcs8(&der).map(ParsedKeyPair::Rsa))?;
                    key_pairs.push(key_pair);
                } else {
                    b64buf.push_str(line.trim());
                }
            }
            State::InRsa => {
                if line.starts_with(RSA_END_MARK) {
                    state = State::Scan;
                    let der = base64::decode(&b64buf)?;
                    let key_pair = RsaKeyPair::from_der(&der).map(ParsedKeyPair::Rsa)?;
                    key_pairs.push(key_pair);
                } else {
                    b64buf.push_str(line.trim());
                }
            }
        }
    }
}

/// Convert a PKCS #8 document to a PEM string.
pub fn from_der(der: &[u8]) -> String {
    let mut res = String::new();
    let b64 = base64::encode(der);
    let mut cursor = Cursor::new(b64.as_bytes());
    res.push_str(PKCS8_START_MARK);
    res.push('\n');
    let mut buf = [0_u8; 64];
    loop {
        let size = cursor.read(&mut buf[..]).unwrap();
        if size == 0 {
            break;
        }
        res.push_str(std::str::from_utf8(&buf[..size]).unwrap());
        res.push('\n');
    }
    res.push_str(PKCS8_END_MARK);
    res.push('\n');
    res
}
