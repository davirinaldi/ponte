//! Lowercase hex for the fixed-size byte fields of the key file, one spelling per value
//! like the keys of `ponte_protocol`.

use serde::{Deserialize, Deserializer, Serializer, de};

const DIGITS: &[u8; 16] = b"0123456789abcdef";

pub(crate) fn encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|byte| {
            [
                char::from(DIGITS[usize::from(byte >> 4)]),
                char::from(DIGITS[usize::from(byte & 0x0f)]),
            ]
        })
        .collect()
}

pub(crate) fn decode<const N: usize>(text: &str) -> Option<[u8; N]> {
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if pairs.len() != N || !rest.is_empty() {
        return None;
    }
    let mut bytes = [0; N];
    for (byte, &[high, low]) in bytes.iter_mut().zip(pairs) {
        *byte = digit(high)? << 4 | digit(low)?;
    }
    Some(bytes)
}

const fn digit(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

pub(crate) fn serialize<S: Serializer, const N: usize>(
    bytes: &[u8; N],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&encode(bytes))
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
    deserializer: D,
) -> Result<[u8; N], D::Error> {
    let text = String::deserialize(deserializer)?;
    decode(&text)
        .ok_or_else(|| de::Error::custom(format!("expected {} lowercase hex characters", N * 2)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_with_one_spelling() {
        let bytes: [u8; 4] = [0x00, 0x7f, 0xa5, 0xff];
        assert_eq!(encode(&bytes), "007fa5ff");
        assert_eq!(decode::<4>("007fa5ff"), Some(bytes));
        for wrong in [
            "007FA5FF",
            "007fa5f",
            "007fa5ff00",
            "0x7fa5ff",
            "007fa5fg",
            "",
        ] {
            assert_eq!(decode::<4>(wrong), None, "{wrong}");
        }
    }
}
