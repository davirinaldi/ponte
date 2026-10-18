//! A manifest as it was signed (ADR-0010): the TOML a person reviewed, its validity, the
//! key that signed it and the signature.
//!
//! Nothing here parses the TOML or checks the signature. The agent verifies first and
//! parses after, and both belong outside this crate. What lives here is the shape of the
//! envelope and the rules on the signed text that every side must apply the same way.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, de};

use crate::{PublicKey, Signature};

/// Largest signed manifest text, in bytes (ADR-0011). The two example manifests are under
/// 1 KiB; a manifest needs to grow tenfold before it comes near.
pub const MAX_MANIFEST_BYTES: usize = 16 * 1024;

const BYTE_ORDER_MARK: char = '\u{feff}';

/// The exact TOML text that was signed: not empty, at most [`MAX_MANIFEST_BYTES`], with no
/// `\r` anywhere and no byte order mark in front.
///
/// The signature covers these bytes as they are (ADR-0010). A line ending or a mark that an
/// editor adds or strips without showing it would make the reviewed text and the signed
/// text differ, so `ponte-sign`, the server and the agent all refuse them, here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ManifestText(String);

/// The text was empty, too long, or had a `\r` or a byte order mark.
///
/// Says nothing about the text: errors get logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "expected 1 to {MAX_MANIFEST_BYTES} bytes of text with no carriage return or byte order mark"
)]
pub struct InvalidManifestText;

impl ManifestText {
    /// The signed bytes, as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ManifestText {
    type Err = InvalidManifestText;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.is_empty()
            || text.len() > MAX_MANIFEST_BYTES
            || text.contains('\r')
            || text.starts_with(BYTE_ORDER_MARK)
        {
            return Err(InvalidManifestText);
        }
        Ok(Self(text.to_owned()))
    }
}

impl<'de> Deserialize<'de> for ManifestText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ManifestTextVisitor;

        impl de::Visitor<'_> for ManifestTextVisitor {
            type Value = ManifestText;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("the text of a manifest")
            }

            fn visit_str<E: de::Error>(self, text: &str) -> Result<ManifestText, E> {
                // Not `E::invalid_value`: it would quote the text in the error.
                text.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_str(ManifestTextVisitor)
    }
}

/// A manifest with its validity and signature, as `ponte-sign` writes it and as it travels
/// in `RunAction` (ADR-0010).
///
/// `signature` is made with the private half of `public_key` over
/// [`manifest_transcript`](crate::manifest_transcript). `issued_at` and `expires_at` are
/// seconds since the Unix epoch. Which keys to trust and which windows to accept is for the
/// verifier to decide; a value of this type has been parsed, not verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedManifest {
    pub manifest: ManifestText,
    pub issued_at: u64,
    pub expires_at: u64,
    pub public_key: PublicKey,
    pub signature: Signature,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const PUBLIC_KEY: &str = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
    const SIGNATURE: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
                             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";

    fn parses(text: &str) -> bool {
        let from_wire = serde_json::from_value::<ManifestText>(json!(text)).is_ok();
        assert_eq!(from_wire, text.parse::<ManifestText>().is_ok(), "{text:?}");
        from_wire
    }

    #[test]
    fn manifests_as_written_are_accepted() {
        for text in [
            include_str!("../../../manifests/examples/erp-restart-service.toml"),
            include_str!("../../../manifests/examples/erp-clear-stale-lock.toml"),
            "id = \"a.b\"\n# comentário com acento\n\tversion = 1\n",
            "x",
        ] {
            assert!(parses(text), "{text:?}");
            let manifest: ManifestText = text.parse().unwrap();
            assert_eq!(manifest.as_str(), text);
            assert_eq!(serde_json::to_value(&manifest).unwrap(), json!(text));
        }
    }

    #[test]
    fn size_is_bounded() {
        // The limit of ADR-0011, in a number the rest of this test cannot move.
        assert_eq!(MAX_MANIFEST_BYTES, 16_384);
        assert!(parses(&"#".repeat(MAX_MANIFEST_BYTES)));
        assert!(!parses(&"#".repeat(MAX_MANIFEST_BYTES + 1)));
        // The limit is in bytes: 8,193 two-byte characters are over it.
        assert!(!parses(&"é".repeat(MAX_MANIFEST_BYTES / 2 + 1)));
        assert!(!parses(""));
    }

    /// What an editor adds or removes without showing it.
    #[test]
    fn invisible_differences_are_refused() {
        for text in [
            "id = \"a.b\"\r\nversion = 1\r\n",
            "id = \"a.b\"\rversion = 1",
            "id = \"a.b\"\nversion = 1\r",
            "\u{feff}id = \"a.b\"\n",
        ] {
            assert!(!parses(text), "accepted {text:?}");
        }
        for not_text in [json!(null), json!(1), json!(["id"]), json!({})] {
            assert!(serde_json::from_value::<ManifestText>(not_text).is_err());
        }
    }

    #[test]
    fn errors_do_not_quote_the_input() {
        let text = "secret = \"value\"\r\n";
        let message = InvalidManifestText.to_string();
        assert_eq!(
            text.parse::<ManifestText>().unwrap_err().to_string(),
            message
        );
        let error = serde_json::from_value::<ManifestText>(json!(text))
            .unwrap_err()
            .to_string();
        assert_eq!(error, message);
        assert!(!error.contains("secret"));
    }

    fn envelope() -> serde_json::Value {
        json!({
            "manifest": "id = \"erp.restart-service\"\n",
            "issued_at": 1_767_225_600_u64,
            "expires_at": 1_774_998_000_u64,
            "public_key": PUBLIC_KEY,
            "signature": SIGNATURE,
        })
    }

    /// Pins the envelope: `ponte-sign` writes it to files that outlive releases.
    #[test]
    fn envelope_format_is_stable() {
        let signed = SignedManifest {
            manifest: "id = \"erp.restart-service\"\n".parse().unwrap(),
            issued_at: 1_767_225_600,
            expires_at: 1_774_998_000,
            public_key: PUBLIC_KEY.parse().unwrap(),
            signature: SIGNATURE.parse().unwrap(),
        };
        assert_eq!(serde_json::to_value(&signed).unwrap(), envelope());
        assert_eq!(
            serde_json::from_value::<SignedManifest>(envelope()).unwrap(),
            signed
        );
    }

    #[test]
    fn envelope_is_strict() {
        let mut extra = envelope();
        extra["skip_signature_check"] = json!(true);
        assert!(serde_json::from_value::<SignedManifest>(extra).is_err());

        for field in [
            "manifest",
            "issued_at",
            "expires_at",
            "public_key",
            "signature",
        ] {
            let mut missing = envelope();
            missing.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<SignedManifest>(missing).is_err(),
                "{field}"
            );
        }
        for (field, value) in [
            ("issued_at", json!(-1)),
            ("issued_at", json!("2026-01-01T00:00:00Z")),
            ("expires_at", json!(1.5)),
            ("expires_at", json!(null)),
            ("public_key", json!(PUBLIC_KEY.to_uppercase())),
            ("signature", json!(&SIGNATURE[..64])),
            ("manifest", json!("id = 1\r\n")),
        ] {
            let mut wrong = envelope();
            wrong[field] = value;
            assert!(
                serde_json::from_value::<SignedManifest>(wrong).is_err(),
                "{field}"
            );
        }
    }
}
