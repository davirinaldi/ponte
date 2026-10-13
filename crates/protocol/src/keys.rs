//! Fixed-size values of the handshake (ADR-0008): device keys, signatures, nonces and
//! enrollment tokens.
//!
//! On the wire each one is lowercase hex of its exact length, so a value has one spelling
//! only. Whatever is compared, stored or signed on one side is byte for byte what the other
//! side sent. Nothing here does cryptography: these are the bytes, and whoever verifies a
//! signature also checks that the key is a valid one.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// The text was not lowercase hex of the expected length.
///
/// Deliberately says nothing about the text: it may have been a secret, and errors get logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("expected {expected_chars} lowercase hex characters")]
pub struct InvalidHex {
    expected_chars: usize,
}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

fn encode<const N: usize>(bytes: &[u8; N]) -> String {
    let mut text = String::with_capacity(N * 2);
    for byte in bytes {
        text.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}

fn decode<const N: usize>(text: &str) -> Result<[u8; N], InvalidHex> {
    let invalid = InvalidHex {
        expected_chars: N * 2,
    };
    // Bytes, not chars: the length check below then rules out anything that is not ASCII
    // hex without ever slicing a `str` in the middle of a character.
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if pairs.len() != N || !rest.is_empty() {
        return Err(invalid);
    }
    let mut bytes = [0; N];
    for (byte, &[high, low]) in bytes.iter_mut().zip(pairs) {
        *byte = hex_value(high).ok_or(invalid)? << 4 | hex_value(low).ok_or(invalid)?;
    }
    Ok(bytes)
}

/// Lowercase only: `A` and `a` would be two spellings of the same value.
const fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

struct HexVisitor<const N: usize>;

impl<const N: usize> de::Visitor<'_> for HexVisitor<N> {
    type Value = [u8; N];

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} lowercase hex characters", N * 2)
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<Self::Value, E> {
        // Not `E::invalid_value`: it would quote the text in the error.
        decode(text).map_err(E::custom)
    }
}

/// Text and wire form shared by every type in this module.
macro_rules! hex_wire_format {
    ($name:ident) => {
        impl FromStr for $name {
            type Err = InvalidHex;

            fn from_str(text: &str) -> Result<Self, Self::Err> {
                decode(text).map(Self)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&encode(&self.0))
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                deserializer.deserialize_str(HexVisitor).map(Self)
            }
        }
    };
}

/// A value that is safe to print and log.
macro_rules! public_bytes {
    ($(#[$meta:meta])* $name:ident, $len:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; $len]);

        impl $name {
            #[must_use]
            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&encode(&self.0))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({self})", stringify!($name))
            }
        }

        hex_wire_format!($name);
    };
}

public_bytes!(
    /// Ed25519 public key of a device. The private half never leaves the machine (RF-02).
    ///
    /// Any 32 bytes parse. Whether they are a usable key is for the verifier to decide.
    PublicKey,
    32
);

public_bytes!(
    /// Ed25519 signature over one of the transcripts in this crate.
    Signature,
    64
);

public_bytes!(
    /// Random value the server picks for one connection. The agent signs it, so a recorded
    /// handshake cannot be replayed.
    Nonce,
    32
);

/// Secret that lets a machine enroll (RF-01). Whoever holds it can register a device for
/// the customer it belongs to, so it is never printed: `Debug` is redacted and there is no
/// `Display`. Reading it takes a call that says so.
///
/// ```compile_fail
/// let token = ponte_protocol::EnrollmentToken::from_bytes([0; 32]);
/// println!("{token}");
/// ```
#[derive(Clone)]
pub struct EnrollmentToken([u8; 32]);

impl EnrollmentToken {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The secret itself, to hash or to sign. Never log it.
    #[must_use]
    pub const fn expose_secret(&self) -> &[u8; 32] {
        &self.0
    }

    /// The secret as it is written on the wire, for the one time it is shown to a person.
    #[must_use]
    pub fn expose_hex(&self) -> String {
        encode(&self.0)
    }
}

impl fmt::Debug for EnrollmentToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EnrollmentToken(<redacted>)")
    }
}

impl PartialEq for EnrollmentToken {
    /// Looks at every byte before answering, so the time taken does not tell how many
    /// leading bytes of a guess were right.
    fn eq(&self, other: &Self) -> bool {
        let difference = self
            .0
            .iter()
            .zip(&other.0)
            .fold(0, |difference, (a, b)| difference | (a ^ b));
        difference == 0
    }
}

impl Eq for EnrollmentToken {}

hex_wire_format!(EnrollmentToken);

#[cfg(test)]
mod tests {
    use serde::de::DeserializeOwned;
    use serde_json::json;

    use super::*;

    const KEY: &str = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
    const TOKEN: &str = "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

    /// Bytes `start`, `start + 1`, ... so that a swapped nibble or byte order shows up.
    fn counting<const N: usize>(start: u8) -> [u8; N] {
        let mut bytes = [0; N];
        let mut next = start;
        for byte in &mut bytes {
            *byte = next;
            next = next.wrapping_add(1);
        }
        bytes
    }

    #[test]
    fn public_values_are_lowercase_hex_on_the_wire() {
        let key = PublicKey::from_bytes(counting(0xa0));
        assert_eq!(serde_json::to_value(key).unwrap(), json!(KEY));
        assert_eq!(
            serde_json::from_value::<PublicKey>(json!(KEY)).unwrap(),
            key
        );
        assert_eq!(key.to_string(), KEY);
        assert_eq!(KEY.parse::<PublicKey>().unwrap(), key);
        assert_eq!(key.as_bytes(), &counting::<32>(0xa0));

        let nonce = Nonce::from_bytes(counting(0xa0));
        assert_eq!(serde_json::to_value(nonce).unwrap(), json!(KEY));
        assert_eq!(serde_json::from_value::<Nonce>(json!(KEY)).unwrap(), nonce);

        let signature = Signature::from_bytes(counting(0xa0));
        let wire = serde_json::to_value(signature).unwrap();
        assert_eq!(wire.as_str().unwrap().len(), 128);
        assert!(wire.as_str().unwrap().starts_with(KEY));
        assert_eq!(
            serde_json::from_value::<Signature>(wire).unwrap(),
            signature
        );
    }

    #[test]
    fn every_byte_value_round_trips() {
        let all: [u8; 256] = counting(0);
        let text = encode(&all);
        assert_eq!(text.len(), 512);
        assert!(text.starts_with("000102") && text.ends_with("fdfeff"));
        assert_eq!(decode::<256>(&text).unwrap(), all);
    }

    fn parses<T: DeserializeOwned + FromStr>(text: &str) -> bool {
        let from_wire = serde_json::from_value::<T>(json!(text)).is_ok();
        let from_str = text.parse::<T>().is_ok();
        assert_eq!(
            from_wire, from_str,
            "serde and FromStr disagree on {text:?}"
        );
        from_wire
    }

    /// One value has exactly one spelling. Anything else is rejected, not repaired.
    fn assert_only_exact_lowercase_hex<T: DeserializeOwned + FromStr>(bytes: usize) {
        let valid = "5a".repeat(bytes);
        assert!(parses::<T>(&valid));

        let malformed = [
            String::new(),
            valid[2..].to_owned(),
            valid[1..].to_owned(),
            format!("{valid}5a"),
            format!("{valid}5"),
            valid.to_uppercase(),
            valid.replacen("5a", "5A", 1),
            valid.replacen("5a", "5g", 1),
            valid.replacen("5a", "-5", 1),
            valid.replacen("5a", "+5", 1),
            valid.replacen("5a", " 5", 1),
            valid.replacen("5a", "é", 1),
            format!("0x{}", &valid[2..]),
            format!("{}\n", &valid[1..]),
            format!("{}\0", &valid[1..]),
            format!("{valid} "),
            format!(" {valid}"),
        ];
        for text in &malformed {
            assert!(!parses::<T>(text), "accepted {text:?}");
        }

        for not_text in [
            json!(null),
            json!(0x5a),
            json!([0x5a]),
            json!(vec![0x5a; bytes]),
            json!({ "hex": valid }),
        ] {
            assert!(
                serde_json::from_value::<T>(not_text.clone()).is_err(),
                "accepted {not_text}"
            );
        }
    }

    #[test]
    fn malformed_hex_is_rejected() {
        assert_only_exact_lowercase_hex::<PublicKey>(32);
        assert_only_exact_lowercase_hex::<Nonce>(32);
        assert_only_exact_lowercase_hex::<Signature>(64);
        assert_only_exact_lowercase_hex::<EnrollmentToken>(32);
    }

    /// A key is not a nonce is not a token, even though all three are 32 bytes: the length
    /// check must use each type's own size.
    #[test]
    fn a_signature_is_not_a_key() {
        let signature = "5a".repeat(64);
        assert!(!parses::<PublicKey>(&signature));
        assert!(!parses::<Nonce>(&signature));
        assert!(!parses::<EnrollmentToken>(&signature));
        assert!(!parses::<Signature>(KEY));
    }

    #[test]
    fn token_round_trips_on_the_wire() {
        let token = EnrollmentToken::from_bytes(counting(0xe0));
        assert_eq!(serde_json::to_value(&token).unwrap(), json!(TOKEN));
        assert_eq!(
            serde_json::from_value::<EnrollmentToken>(json!(TOKEN)).unwrap(),
            token
        );
        assert_eq!(TOKEN.parse::<EnrollmentToken>().unwrap(), token);
        assert_eq!(token.expose_hex(), TOKEN);
        assert_eq!(token.expose_secret(), &counting::<32>(0xe0));
    }

    /// The comparison is written by hand, so check it where a shortcut would show: tokens
    /// that differ in one bit, at either end or in the middle.
    #[test]
    fn tokens_differing_in_one_bit_are_not_equal() {
        let bytes: [u8; 32] = counting(0xe0);
        let token = EnrollmentToken::from_bytes(bytes);
        assert_eq!(token, token.clone());

        for position in [0, 15, 31] {
            for bit in [0x01, 0x80] {
                let mut other = bytes;
                other[position] ^= bit;
                assert_ne!(token, EnrollmentToken::from_bytes(other));
            }
        }
    }

    #[test]
    fn token_debug_is_redacted() {
        let token = EnrollmentToken::from_bytes(counting(0xe0));
        assert_eq!(format!("{token:?}"), "EnrollmentToken(<redacted>)");
        assert_eq!(format!("{token:#?}"), "EnrollmentToken(<redacted>)");
        assert_eq!(
            format!("{:?}", Some(&token)),
            "Some(EnrollmentToken(<redacted>))"
        );
    }

    /// A parse error ends up in a log. It must not carry what was being parsed: a token
    /// with one wrong character is still most of a token.
    #[test]
    fn parse_errors_do_not_quote_the_input() {
        let almost = TOKEN.replacen("e0", "E0", 1);
        let message = "expected 64 lowercase hex characters";

        // The whole text of each error is pinned: a check for the full token would miss
        // an error that quotes only its first characters.
        let from_str = almost.parse::<EnrollmentToken>().unwrap_err();
        assert_eq!(from_str.to_string(), message);
        assert_eq!(format!("{from_str:?}"), "InvalidHex { expected_chars: 64 }");

        let from_wire = serde_json::from_value::<EnrollmentToken>(json!(almost)).unwrap_err();
        assert_eq!(from_wire.to_string(), message);

        let text = format!("\"{almost}\"");
        let from_text = serde_json::from_str::<EnrollmentToken>(&text).unwrap_err();
        assert_eq!(
            from_text.to_string(),
            format!("{message} at line 1 column 66")
        );
    }
}
