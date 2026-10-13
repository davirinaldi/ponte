//! Protocol versions and their names in the WebSocket upgrade (ADR-0007).

use crate::{MIN_PROTOCOL_VERSION, PROTOCOL_VERSION};

const SUBPROTOCOL_PREFIX: &str = "ponte.v";

/// A protocol version this build speaks.
///
/// It cannot be built from a bare number. It comes from a subprotocol name, checked against
/// the range this build speaks, or from [`ProtocolVersion::supported`]. Code that needs the
/// version of one connection, like the transcripts, takes this type, so it is not handed
/// `PROTOCOL_VERSION` by mistake: that would work until the first bump and then lock out
/// every agent that has not updated yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion(u16);

impl ProtocolVersion {
    /// Every version this build speaks, newest first. That is the order of the agent's
    /// offer and of the server's preference.
    pub fn supported() -> impl Iterator<Item = Self> {
        (MIN_PROTOCOL_VERSION..=PROTOCOL_VERSION).rev().map(Self)
    }

    /// Reads one name from `Sec-WebSocket-Protocol`. `None` unless it is the exact name of
    /// a version this build speaks.
    #[must_use]
    pub fn from_subprotocol(name: &str) -> Option<Self> {
        let number = parse_name(name)?;
        (MIN_PROTOCOL_VERSION..=PROTOCOL_VERSION)
            .contains(&number)
            .then_some(Self(number))
    }

    /// The name of this version in `Sec-WebSocket-Protocol`, e.g. `ponte.v1`.
    #[must_use]
    pub fn subprotocol(self) -> String {
        name(self.0)
    }

    #[must_use]
    pub const fn number(self) -> u16 {
        self.0
    }

    /// A version this build may not speak, for tests of what depends on the number.
    #[cfg(test)]
    pub(crate) const fn for_test(number: u16) -> Self {
        Self(number)
    }
}

fn name(number: u16) -> String {
    format!("{SUBPROTOCOL_PREFIX}{number}")
}

/// `None` for anything [`name`] would not have written for a version from 1 up.
fn parse_name(name: &str) -> Option<u16> {
    let digits = name.strip_prefix(SUBPROTOCOL_PREFIX)?;
    // `str::parse` alone would also take `+1` and `01`, giving one version several names.
    if digits.starts_with('0') || !digits.bytes().all(|digit| digit.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subprotocol_names_are_stable() {
        assert_eq!(name(1), "ponte.v1");
        assert_eq!(name(12), "ponte.v12");
        assert_eq!(parse_name("ponte.v1"), Some(1));
        assert_eq!(parse_name("ponte.v65535"), Some(u16::MAX));
    }

    #[test]
    fn every_version_number_round_trips() {
        for number in 1..=u16::MAX {
            assert_eq!(parse_name(&name(number)), Some(number));
        }
    }

    /// The server echoes the name it picked and the agent compares it with what it
    /// offered, so a version has exactly one name. Anything else is not ours.
    #[test]
    fn other_subprotocols_are_not_versions() {
        for name in [
            "",
            "ponte",
            "ponte.v",
            "ponte.v0",
            "ponte.v01",
            "ponte.v+1",
            "ponte.v-1",
            "ponte.v1.0",
            "ponte.v1 ",
            " ponte.v1",
            "ponte.v1\0",
            "ponte.v1,ponte.v2",
            "ponte.v65536",
            "ponte.v99999999999999999999",
            "ponte.vx",
            "ponte.v١",
            "Ponte.v1",
            "ponte.V1",
            "ponte-v1",
            "v1",
            "1",
            "mqtt",
        ] {
            assert_eq!(parse_name(name), None, "{name:?}");
            assert_eq!(ProtocolVersion::from_subprotocol(name), None, "{name:?}");
        }
    }

    #[test]
    fn supported_versions_are_the_declared_range_newest_first() {
        let numbers: Vec<u16> = ProtocolVersion::supported()
            .map(ProtocolVersion::number)
            .collect();
        assert_eq!(numbers.first(), Some(&PROTOCOL_VERSION));
        assert_eq!(numbers.last(), Some(&MIN_PROTOCOL_VERSION));
        assert!(numbers.is_sorted_by(|a, b| a > b));

        for version in ProtocolVersion::supported() {
            assert_eq!(
                ProtocolVersion::from_subprotocol(&version.subprotocol()),
                Some(version)
            );
        }
    }

    /// A well-formed name of a version outside the range is no version at all: the server
    /// skips it in an offer and the agent refuses it as an answer.
    #[test]
    fn versions_outside_the_range_are_refused() {
        for number in (1..=u16::MAX)
            .filter(|number| !(MIN_PROTOCOL_VERSION..=PROTOCOL_VERSION).contains(number))
        {
            assert_eq!(ProtocolVersion::from_subprotocol(&name(number)), None);
        }
    }
}
