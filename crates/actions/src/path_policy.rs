/// Restricts file-touching primitives to a set of allowed root directories.
///
/// This is a *lexical* check over Windows-style absolute paths (`C:\...`), so it
/// behaves the same on every OS the tests run on. It rejects anything ambiguous:
/// relative paths, `..`, UNC and device paths (`\\server`, `\\?\`), alternate data
/// streams (`file:stream`) and segments with trailing dots or spaces, which Windows
/// silently strips.
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
fn normalize(path: &str) -> Option<Vec<String>> {
    let mut parts = path.split(['\\', '/']);

    let drive = parts.next()?;
    let bytes = drive.as_bytes();
    if bytes.len() != 2 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' {
        return None;
    }

    let mut segments = vec![drive.to_ascii_lowercase()];
    for part in parts {
        match part {
            "" | "." => {}
            ".." => return None,
            p if p.contains(':') || p.ends_with('.') || p.ends_with(' ') => return None,
            p => segments.push(p.to_lowercase()),
        }
    }
    Some(segments)
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
    fn invalid_root_is_an_error() {
        assert_eq!(
            PathPolicy::new([r"relative\dir"]).unwrap_err(),
            r"relative\dir"
        );
    }
}
