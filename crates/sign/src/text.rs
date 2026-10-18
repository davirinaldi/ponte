//! Why a file is not text a manifest can be signed as, said so its author can fix it.
//!
//! `ManifestText` refuses without saying why, because its errors may be logged. Here the
//! text is the user's own file, so the message points at the problem. Each character is
//! tried against `ManifestText` itself, so this never disagrees with what the agent takes.

use ponte_protocol::{MAX_MANIFEST_BYTES, ManifestText};

/// The reason `text` is not a [`ManifestText`], or `None` if it is one.
pub(crate) fn why_not_manifest_text(text: &str) -> Option<String> {
    if text.parse::<ManifestText>().is_ok() {
        return None;
    }
    if text.is_empty() {
        return Some("the file is empty".to_owned());
    }
    if text.len() > MAX_MANIFEST_BYTES {
        return Some(format!(
            "the file has {} bytes; a manifest has at most {MAX_MANIFEST_BYTES}",
            text.len()
        ));
    }
    if text.starts_with('\u{feff}') {
        return Some(
            "the file starts with a byte order mark (BOM); save it as UTF-8 without a BOM"
                .to_owned(),
        );
    }
    if text.contains('\r') {
        return Some(
            "the file has Windows line endings (CR LF); save it with LF line endings".to_owned(),
        );
    }
    let (line, column, c) = text.lines().enumerate().find_map(|(line, content)| {
        content
            .chars()
            .enumerate()
            .find(|(_, c)| c.to_string().parse::<ManifestText>().is_err())
            .map(|(column, c)| (line + 1, column + 1, c))
    })?;
    let code = u32::from(c);
    if (0x300..=0x36f).contains(&code) {
        return Some(format!(
            "line {line}, column {column}: a combining accent (U+{code:04X}). The text is \
             decomposed (NFD), as some editors on macOS save it; save it in NFC, where an \
             accented letter such as `ç` is one character"
        ));
    }
    Some(format!(
        "line {line}, column {column}: character U+{code:04X} is not allowed in a manifest. \
         Only printable ASCII, tabs, Latin letters and the typographic dashes, quotes and \
         ellipsis are, so that the text a reviewer reads is the text that is signed"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn why(text: &str) -> String {
        why_not_manifest_text(text).unwrap()
    }

    #[test]
    fn valid_text_has_no_reason() {
        assert_eq!(why_not_manifest_text("id = \"a.b\"\n# ação\n"), None);
    }

    #[test]
    fn each_problem_is_named() {
        assert_eq!(why(""), "the file is empty");
        assert!(why(&"#".repeat(MAX_MANIFEST_BYTES + 1)).contains("at most 16384"));
        assert!(why("\u{feff}id = 1\n").contains("byte order mark"));
        assert!(why("id = 1\r\nx = 2\r\n").contains("LF line endings"));

        // `ç` written as `c` + U+0327, as some macOS editors save it.
        let decomposed = why("id = \"a.b\"\n# servic\u{327}o\n");
        assert!(decomposed.starts_with("line 2, column 9:"), "{decomposed}");
        assert!(decomposed.contains("U+0327"), "{decomposed}");
        assert!(decomposed.contains("NFC"), "{decomposed}");

        let hidden = why("id = \"a.b\" # x\u{200b}\n");
        assert!(hidden.starts_with("line 1, column 15:"), "{hidden}");
        assert!(hidden.contains("U+200B"), "{hidden}");
        assert!(why("a\u{0}b").contains("U+0000"));
    }
}
