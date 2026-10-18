/// Restricts file-touching primitives to a set of allowed root directories.
///
/// This is a *lexical* check over Windows-style absolute paths (`C:\...`), so it
/// behaves the same on every OS the tests run on. It rejects anything ambiguous:
/// relative paths, `..`, UNC and device paths (`\\server`, `\\?\`), alternate data
/// streams (`file:stream`), segments with trailing dots or spaces, which Windows
/// silently strips, legacy device names (`NUL`, `com1.txt`), wildcards and control
/// characters.
///
/// Case is folded for ASCII only. Unicode folding would read look-alike letters such as
/// U+212A KELVIN SIGN as `k`, which NTFS does not, so outside ASCII a path must spell
/// a root exactly as it was configured.
///
/// A lexical check cannot see symlinks or junctions. The agent must also resolve the
/// final path at execution time and re-check it (tracked in `docs/roadmap.md`).
#[derive(Debug, Clone, Default)]
pub struct PathPolicy {
    roots: Vec<Vec<String>>,
}

impl PathPolicy {
    /// Builds a policy from root directories. Invalid roots are returned as an error
    /// instead of being silently ignored.
    ///
    /// # Errors
    /// Returns the first root that is not a valid absolute Windows path.
    pub fn new<I, S>(roots: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let roots = roots
            .into_iter()
            .map(|root| normalize(root.as_ref()).ok_or_else(|| root.as_ref().to_owned()))
            .collect::<Result<_, _>>()?;
        Ok(Self { roots })
    }

    /// Whether `path` is inside (or equal to) one of the allowed roots.
    #[must_use]
    pub fn is_allowed(&self, path: &str) -> bool {
        let Some(segments) = normalize(path) else {
            return false;
        };
        self.roots.iter().any(|root| segments.starts_with(root))
    }
}

/// Splits an absolute Windows path into lowercase segments, or `None` if it is
/// relative or ambiguous.
pub(crate) fn normalize(path: &str) -> Option<Vec<String>> {
    let mut parts = path.split(['\\', '/']);

    let drive = parts.next()?;
    if !is_drive(drive) {
        return None;
    }

    let mut segments = vec![drive.to_ascii_lowercase()];
    for part in parts {
        match part {
            "" | "." => {}
            ".." => return None,
            p if !is_plain_segment(p) => return None,
            p => segments.push(p.to_ascii_lowercase()),
        }
    }
    Some(segments)
}

/// Whether `s` is a bare drive such as `C:`.
pub(crate) fn is_drive(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

/// Characters no file or directory name may contain: wildcards, the other characters
/// Windows forbids in names, and control characters.
fn is_forbidden_char(c: char) -> bool {
    c.is_control() || matches!(c, '<' | '>' | '"' | '|' | '?' | '*')
}

/// Whether Windows opens exactly the file or directory this segment names.
fn is_plain_segment(segment: &str) -> bool {
    !(segment.contains(':')
        || segment.ends_with('.')
        || segment.ends_with(' ')
        || segment.chars().any(is_forbidden_char)
        || is_reserved_device(segment))
}

/// Legacy DOS device names. Windows 10 opens the device for `C:\dir\NUL` and
/// `C:\dir\com1.txt` alike, whatever the directory or the extension.
fn is_reserved_device(segment: &str) -> bool {
    let stem = segment.split_once('.').map_or(segment, |(stem, _)| stem);
    let stem = stem.trim_end_matches(' ').to_ascii_uppercase();
    if matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }
    let Some(port) = stem
        .strip_prefix("COM")
        .or_else(|| stem.strip_prefix("LPT"))
    else {
        return false;
    };
    // One digit only, including the superscript digits Windows also reserves.
    let mut chars = port.chars();
    matches!(
        (chars.next(), chars.next()),
        (Some('0'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}'), None)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> PathPolicy {
        PathPolicy::new([r"C:\FakeErp", r"D:\Logs\erp"]).unwrap()
    }

    #[test]
    fn allows_paths_under_a_root() {
        let p = policy();
        assert!(p.is_allowed(r"C:\FakeErp\run\erp.lock"));
        assert!(p.is_allowed("c:/fakeerp/logs/error.log"));
        assert!(p.is_allowed(r"D:\Logs\erp\today.log"));
    }

    #[test]
    fn rejects_paths_outside_roots() {
        let p = policy();
        assert!(!p.is_allowed(r"C:\Windows\System32\config\SAM"));
        assert!(!p.is_allowed(r"C:\FakeErpEvil\x.txt"));
        assert!(!p.is_allowed(r"D:\Logs\other.log"));
    }

    #[test]
    fn rejects_ambiguous_paths() {
        let p = policy();
        for path in [
            r"C:\FakeErp\..\Windows\win.ini",
            r"FakeErp\run\erp.lock",
            r"\\server\share\FakeErp\x",
            r"\\?\C:\FakeErp\x",
            r"C:\FakeErp\x.txt:hidden",
            r"C:\FakeErp\x.txt.",
            r"C:\FakeErp\x.txt ",
            "",
        ] {
            assert!(!p.is_allowed(path), "should reject {path:?}");
        }
    }

    #[test]
    fn rejects_reserved_device_names() {
        let p = policy();
        for path in [
            r"C:\FakeErp\NUL",
            r"C:\FakeErp\nul",
            r"C:\FakeErp\CON",
            r"C:\FakeErp\prn",
            r"C:\FakeErp\aux.log",
            r"C:\FakeErp\logs\com1",
            r"C:\FakeErp\logs\COM1.txt",
            r"C:\FakeErp\logs\LPT9.tar.gz",
            r"C:\FakeErp\NUL .txt",
            "C:\\FakeErp\\COM\u{b9}",
            "C:\\FakeErp\\com\u{b2}.log",
            "C:\\FakeErp\\LPT\u{b3}",
            r"C:\FakeErp\CONIN$",
            r"C:\FakeErp\conout$",
            // A device name is not a directory either.
            r"C:\FakeErp\NUL\x.log",
        ] {
            assert!(!p.is_allowed(path), "should reject {path:?}");
        }
        // Names that merely look like devices are ordinary files.
        for path in [
            r"C:\FakeErp\null.log",
            r"C:\FakeErp\console.log",
            r"C:\FakeErp\com10.log",
            r"C:\FakeErp\com",
            r"C:\FakeErp\my.nul",
        ] {
            assert!(p.is_allowed(path), "should allow {path:?}");
        }
    }

    #[test]
    fn rejects_wildcards_and_control_characters() {
        let p = policy();
        for path in [
            r"C:\FakeErp\*.log",
            r"C:\FakeErp\erp?.lock",
            r#"C:\FakeErp\a"b"#,
            r"C:\FakeErp\a<b",
            r"C:\FakeErp\a>b",
            r"C:\FakeErp\a|b",
            "C:\\FakeErp\\a\0b",
            "C:\\FakeErp\\a\nb",
            "C:\\FakeErp\\a\u{7f}b",
        ] {
            assert!(!p.is_allowed(path), "should reject {path:?}");
        }
    }

    #[test]
    fn case_folding_is_ascii_only() {
        let p = policy();
        assert!(p.is_allowed(r"C:\FAKEERP\RUN\ERP.LOCK"));
        // U+212A KELVIN SIGN lowercases to `k`, yet NTFS keeps it apart from `K`:
        // this is another directory, one an unprivileged user may be able to create.
        assert!(!p.is_allowed("C:\\Fa\u{212a}eErp\\run\\erp.lock"));

        // Outside ASCII, a letter only matches itself.
        let accented = PathPolicy::new(["C:\\Gest\u{e3}o"]).unwrap();
        assert!(accented.is_allowed("c:\\GEST\u{e3}O\\erp.log"));
        assert!(!accented.is_allowed("C:\\GEST\u{c3}O\\erp.log"));
        // U+212B ANGSTROM SIGN and U+00C5 share a lowercase form but are different names.
        let angstrom = PathPolicy::new(["C:\\\u{c5}"]).unwrap();
        assert!(!angstrom.is_allowed("C:\\\u{212b}\\erp.log"));
    }

    #[test]
    fn invalid_root_is_an_error() {
        assert_eq!(
            PathPolicy::new([r"relative\dir"]).unwrap_err(),
            r"relative\dir"
        );
        assert_eq!(
            PathPolicy::new([r"C:\FakeErp\NUL"]).unwrap_err(),
            r"C:\FakeErp\NUL"
        );
    }
}
