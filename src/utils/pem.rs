// This file is based on code from rustls 0.16.0. (Licensed Apache 2.0, MIT, ISC)

use std::io::{BufRead, Error as IoError, Read};

use aws_lc_rs::{
    digest::{digest, SHA256},
    signature::{Ed25519KeyPair, RsaKeyPair},
};
use base64::prelude::*;
use thiserror::Error;

use crate::{crypto::SigningAlgorithm, utils::keys::KeyPairExt};

const ARMOR_BEGIN: &str = "-----BEGIN ";
const ARMOR_END: &str = "-----END ";
const ARMOR_TAIL: &str = "-----";

pub const PKCS8: &str = "PRIVATE KEY";
pub const RSA: &str = "RSA PRIVATE KEY";

pub struct PemEntry {
    pub raw: RawPem,
    pub key_pair: ParsedKeyPair,
}

impl PemEntry {
    fn new<F>(b64: &str, section: &'static str, decode: F) -> Result<Self, ParseError>
    where
        F: FnOnce(&[u8]) -> Result<ParsedKeyPair, ParseError>,
    {
        let data = BASE64_STANDARD.decode(b64).map_err(ParseError::Base64)?;
        let key_pair = decode(&data)?;
        let raw = RawPem { section, data };
        Ok(PemEntry { raw, key_pair })
    }
}

pub struct RawPem {
    pub section: &'static str,
    pub data: Vec<u8>,
}

impl RawPem {
    /// Return a fingerprint of the data.
    pub fn fingerprint(&self) -> String {
        let hash = BASE64_STANDARD.encode(digest(&SHA256, &self.data));
        format!("SHA256:{hash}")
    }

    /// Reformat the data as a PEM string.
    pub fn encode(&self) -> String {
        encode(&self.data, self.section)
    }
}

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
    #[error("unrecognized PEM section: {0}")]
    UnrecognizedSection(String),
    #[error("invalid base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("invalid private key: {0}")]
    KeyRejected(aws_lc_rs::error::KeyRejected),
}

enum State {
    Scan,
    InPkcs8,
    InRsa,
}

/// Parse all supported key pairs from a PEM stream.
pub fn parse_key_pairs(
    mut reader: impl BufRead,
) -> Result<Vec<Result<PemEntry, ParseError>>, IoError> {
    let mut entries = Vec::new();
    let mut b64buf = String::new();
    let mut state = State::Scan;

    let mut line = Vec::<u8>::new();
    loop {
        line.clear();
        let len = reader.read_until(b'\n', &mut line)?;

        if len == 0 {
            return Ok(entries);
        }

        match state {
            State::Scan => match get_section(&line, ARMOR_BEGIN) {
                Some(section) if section == PKCS8 => {
                    state = State::InPkcs8;
                }
                Some(section) if section == RSA => {
                    state = State::InRsa;
                }
                Some(other) => {
                    entries.push(Err(ParseError::UnrecognizedSection(other)));
                }
                None => {}
            },
            State::InPkcs8 if get_section(&line, ARMOR_END).as_deref() == Some(PKCS8) => {
                entries.push(PemEntry::new(&b64buf, PKCS8, |data| {
                    Ed25519KeyPair::from_pkcs8(data)
                        .map(ParsedKeyPair::Ed25519)
                        .or_else(|_| RsaKeyPair::from_pkcs8(data).map(ParsedKeyPair::Rsa))
                        .map_err(ParseError::KeyRejected)
                }));
                state = State::Scan;
                b64buf.clear();
            }
            State::InRsa if get_section(&line, ARMOR_END).as_deref() == Some(RSA) => {
                entries.push(PemEntry::new(&b64buf, RSA, |data| {
                    RsaKeyPair::from_der(data)
                        .map(ParsedKeyPair::Rsa)
                        .map_err(ParseError::KeyRejected)
                }));
                state = State::Scan;
                b64buf.clear();
            }
            State::InPkcs8 | State::InRsa => {
                let line = String::from_utf8_lossy(&line);
                b64buf.push_str(line.trim_end());
            }
        }
    }
}

fn get_section(line: &[u8], prefix: &str) -> Option<String> {
    let prefix = prefix.as_bytes();
    if !line.starts_with(prefix) {
        return None;
    }
    let line = String::from_utf8_lossy(&line[prefix.len()..]);
    let line = line.trim_end().strip_suffix(ARMOR_TAIL)?;
    Some(line.to_owned())
}

/// Format data as a PEM string.
pub fn encode(data: &[u8], section: &str) -> String {
    let mut res = String::new();
    let b64 = BASE64_STANDARD.encode(data);
    let mut cursor = b64.as_bytes();
    res.push_str(ARMOR_BEGIN);
    res.push_str(section);
    res.push_str(ARMOR_TAIL);
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
    res.push_str(ARMOR_END);
    res.push_str(section);
    res.push_str(ARMOR_TAIL);
    res.push('\n');
    res
}
