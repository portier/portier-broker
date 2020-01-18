// This file is based on code from rustls 0.16.0. (Licensed Apache 2.0, MIT, ISC)

use crate::crypto::SupportedKeyPair;
use ring::signature::{Ed25519KeyPair, RsaKeyPair};
use std::io::BufRead;

const RSA_START_MARK: &str = "-----BEGIN RSA PRIVATE KEY-----";
const RSA_END_MARK: &str = "-----END RSA PRIVATE KEY-----";
const PKCS8_START_MARK: &str = "-----BEGIN PRIVATE KEY-----";
const PKCS8_END_MARK: &str = "-----END PRIVATE KEY-----";

enum State {
    Scan,
    InPkcs8,
    InRsa,
}

/// Parse all supported key pairs from a PEM file.
pub fn parse_key_pairs(rd: &mut dyn BufRead) -> Result<Vec<SupportedKeyPair>, ()> {
    let mut key_pairs = Vec::new();
    let mut b64buf = String::new();
    let mut state = State::Scan;

    let mut raw_line = Vec::<u8>::new();
    loop {
        raw_line.clear();
        let len = rd.read_until(b'\n', &mut raw_line).map_err(|_| ())?;

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
                    let der = base64::decode(&b64buf).map_err(|_| ())?;
                    let key_pair = Ed25519KeyPair::from_pkcs8(&der)
                        .map(SupportedKeyPair::Ed25519)
                        .or_else(|_| RsaKeyPair::from_pkcs8(&der).map(SupportedKeyPair::Rsa))
                        .map_err(|_| ())?;
                    key_pairs.push(key_pair);
                } else {
                    b64buf.push_str(line.trim());
                }
            }
            State::InRsa => {
                if line.starts_with(RSA_END_MARK) {
                    state = State::Scan;
                    let der = base64::decode(&b64buf).map_err(|_| ())?;
                    let key_pair = RsaKeyPair::from_der(&der)
                        .map(SupportedKeyPair::Rsa)
                        .map_err(|_| ())?;
                    key_pairs.push(key_pair);
                } else {
                    b64buf.push_str(line.trim());
                }
            }
        }
    }
}
