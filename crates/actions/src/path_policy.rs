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
/// No root may be a whole drive, a system folder or a folder every user shares (see
/// [`RootRule`], ADR-0011), so a careless configuration cannot hand a manifest the
/// Windows folder or every profile on the machine.
///
/// A lexical check cannot see symlinks or junctions. The agent also checks the roots as
/// they resolve when it starts, and the final path of every file it opens (ADR-0011).
#[derive(Debug, Clone, Default)]
pub struct PathPolicy {
    roots: Vec<Vec<String>>,
}

/// A root the configuration names that ADR-0011 forbids. The root comes from the
/// administrator's configuration, not from a manifest, so the error names it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("root `{root}` {rule}")]
pub struct InvalidRoot {
    pub root: String,
    pub rule: RootRule,
}

/// Which rule of ADR-0011 a root breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RootRule {
    #[error(
        "is not an absolute Windows path with no `..`, UNC, device name, stream, wildcard or \
         trailing dot or space"
    )]
    NotAPath,
    #[error("is a whole drive")]
    Drive,
    #[error("has a short 8.3 name (`~`); write the long name")]
    ShortName,
    #[error(
        "is the Windows folder, `$Recycle.Bin`, `System Volume Information`, `Recovery` or \
         `Boot`, or lies inside one"
    )]
    SystemFolder,
    #[error("is a `Program Files` folder, `ProgramData` or the folder of user profiles")]
    SharedFolder,
    #[error("is the root of a user's profile; name a folder inside it")]
    ProfileRoot,
    #[error("is a delete root outside every allowed root")]
    OutsideAllowedRoots,
}

/// Folders at the root of a drive that no root may be or lie in.
const SYSTEM_FOLDERS: [&str; 5] = [
    "windows",
    "$recycle.bin",
    "system volume information",
    "recovery",
    "boot",
];
/// Folders at the root of a drive that no root may be, though folders inside them may.
const SHARED_FOLDERS: [&str; 6] = [
    "program files",
    "program files (x86)",
    "program files (arm)",
    "programdata",
    "users",
    "documents and settings",
];
/// Folders whose children are user profiles, which no root may be either.
const PROFILE_FOLDERS: [&str; 2] = ["users", "documents and settings"];

impl PathPolicy {
    /// Builds a policy from root directories. A root that breaks a rule is an error,
    /// never silently ignored.
    ///
    /// The rules are lexical and hold on every drive letter: nothing here knows which
    /// drive Windows is on, and a `Windows` folder on another drive is no place for a root
    /// either. The agent checks the folders Windows reports, and the roots as they
    /// resolve, when it starts.
    ///
    /// # Errors
    /// Returns the first root that is not a valid absolute Windows path or that names a
    /// forbidden folder.
    pub fn new<I, S>(roots: I) -> Result<Self, InvalidRoot>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let roots = roots
            .into_iter()
            .map(|root| {
                let root = root.as_ref();
                check_root(root).map_err(|rule| InvalidRoot {
                    root: root.to_owned(),
                    rule,
                })
            })
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

/// The segments of a root that ADR-0011 allows, or the rule it breaks.
fn check_root(root: &str) -> Result<Vec<String>, RootRule> {
    let segments = normalize(root).ok_or(RootRule::NotAPath)?;
    let Some(top) = segments.get(1) else {
        return Err(RootRule::Drive);
    };
    // `C:\PROGRA~1` is `Program Files` under another name. An installer writes long names.
    if segments.iter().any(|segment| segment.contains('~')) {
        return Err(RootRule::ShortName);
    }
    if SYSTEM_FOLDERS.contains(&top.as_str()) {
        return Err(RootRule::SystemFolder);
    }
    if segments.len() == 2 && SHARED_FOLDERS.contains(&top.as_str()) {
        return Err(RootRule::SharedFolder);
    }
    if segments.len() == 3 && PROFILE_FOLDERS.contains(&top.as_str()) {
        return Err(RootRule::ProfileRoot);
    }
    Ok(segments)
}

/// Where a manifest may look and where it may delete (ADR-0011): `allowed` bounds every
/// path a manifest names, `delete` bounds `delete_file`, and each delete root lies inside
/// (or is) an allowed root. A root wide enough to check that the ERP's database exists
/// then does not also let a manifest delete it.
#[derive(Debug, Clone, Default)]
pub struct Roots {
    allowed: PathPolicy,
    delete: PathPolicy,
}

impl Roots {
    /// # Errors
    /// A root breaks a rule of [`PathPolicy::new`], or a delete root lies outside every
    /// allowed root.
    pub fn new<A, D, S>(allowed: A, delete: D) -> Result<Self, InvalidRoot>
    where
        A: IntoIterator<Item = S>,
        D: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let allowed = PathPolicy::new(allowed)?;
        let delete: Vec<S> = delete.into_iter().collect();
        let delete = PathPolicy::new(&delete).and_then(|policy| {
            match delete
                .iter()
                .find(|root| !allowed.is_allowed(root.as_ref()))
            {
                Some(outside) => Err(InvalidRoot {
                    root: outside.as_ref().to_owned(),
                    rule: RootRule::OutsideAllowedRoots,
                }),
                None => Ok(policy),
            }
        })?;
        Ok(Self { allowed, delete })
    }

    /// Bounds every path a manifest names.
    #[must_use]
    pub const fn allowed(&self) -> &PathPolicy {
        &self.allowed
    }

    /// Bounds the paths `delete_file` may act on.
    #[must_use]
    pub const fn delete(&self) -> &PathPolicy {
        &self.delete
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

/// Characters a file or directory name may hold here: printable ASCII and Latin letters
/// (U+00A1 to U+017F, without the soft hyphen), less the wildcards and the other
/// characters Windows forbids in names.
///
/// An allow list, like the one of `ManifestText` and narrower: a TOML escape can put any
/// character into a parsed path, and an invisible, bidirectional or look-alike one would
/// let a reviewer read one name while the agent opens another.
fn is_path_char(c: char) -> bool {
    matches!(c, ' '..='~' | '\u{a1}'..='\u{ac}' | '\u{ae}'..='\u{17f}')
        && !matches!(c, '<' | '>' | '"' | '|' | '?' | '*')
}

/// Whether Windows opens exactly the file or directory this segment names.
fn is_plain_segment(segment: &str) -> bool {
    !(segment.contains(':')
        || segment.ends_with('.')
        || segment.ends_with(' ')
        || !segment.chars().all(is_path_char)
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

    /// What a TOML escape can put in a parsed path, and what reads as another name.
    #[test]
    fn rejects_invisible_and_look_alike_characters() {
        let p = policy();
        for c in [
            '\u{1b}',
            '\u{85}',
            '\u{a0}',
            '\u{ad}',
            '\u{303}',
            '\u{430}',
            '\u{200b}',
            '\u{202e}',
            '\u{2013}',
            '\u{feff}',
            '\u{e0041}',
        ] {
            let path = format!("C:\\FakeErp\\run\\erp{c}.lock");
            assert!(!p.is_allowed(&path), "should reject {c:?}");
            assert!(
                PathPolicy::new([format!("C:\\Fake{c}Erp")]).is_err(),
                "{c:?}"
            );
        }
        assert!(p.is_allowed("C:\\FakeErp\\Gest\u{e3}o \u{a7}1 (c\u{f3}pia).txt"));
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

    fn rule(root: &str) -> Option<RootRule> {
        PathPolicy::new([root]).err().map(|error| {
            assert_eq!(error.root, root);
            error.rule
        })
    }

    #[test]
    fn invalid_root_is_an_error() {
        for root in [
            r"relative\dir",
            r"C:\FakeErp\NUL",
            r"\\server\share\erp",
            "",
        ] {
            assert_eq!(rule(root), Some(RootRule::NotAPath), "{root:?}");
        }
        // One bad root refuses the whole list.
        assert!(PathPolicy::new([r"C:\FakeErp", "C:"]).is_err());
    }

    #[test]
    fn no_root_is_a_drive() {
        for root in ["C:", r"C:\", "d:/", r"Z:\.", r"C:\\"] {
            assert_eq!(rule(root), Some(RootRule::Drive), "{root:?}");
        }
    }

    #[test]
    fn no_root_is_or_lies_in_a_system_folder() {
        for root in [
            r"C:\Windows",
            r"c:\WINDOWS\Temp",
            r"C:\Windows\System32\config",
            r"D:\Windows",
            r"C:\$Recycle.Bin\S-1-5-21",
            r"C:\System Volume Information",
            r"C:\Recovery\WindowsRE",
            r"C:\Boot",
        ] {
            assert_eq!(rule(root), Some(RootRule::SystemFolder), "{root:?}");
        }
    }

    #[test]
    fn shared_folders_are_not_roots_but_folders_inside_them_are() {
        for root in [
            r"C:\Program Files",
            r"C:\program files (x86)",
            r"C:\Program Files (Arm)",
            r"C:\ProgramData",
            r"C:\Users",
            r"C:\Documents and Settings",
        ] {
            assert_eq!(rule(root), Some(RootRule::SharedFolder), "{root:?}");
        }
        for root in [
            r"C:\Users\joana",
            r"C:\Users\Public",
            r"C:\Users\Default",
            r"C:\Documents and Settings\joana",
        ] {
            assert_eq!(rule(root), Some(RootRule::ProfileRoot), "{root:?}");
        }
        for root in [
            r"C:\Program Files\FakeErp",
            r"C:\ProgramData\FakeErp\logs",
            r"C:\Users\joana\FakeErp",
            r"C:\FakeErp",
            r"D:\Logs\erp",
            r"C:\Windows2",
            r"C:\Data\Windows",
            r"C:\Data\Users\x",
        ] {
            assert_eq!(rule(root), None, "{root:?}");
        }
    }

    #[test]
    fn short_names_are_not_roots() {
        for root in [
            r"C:\PROGRA~1",
            r"C:\PROGRA~1\FakeErp",
            r"C:\FakeErp\LOGS~1",
            r"C:\WINDOW~1",
        ] {
            assert_eq!(rule(root), Some(RootRule::ShortName), "{root:?}");
        }
    }

    #[test]
    fn delete_roots_lie_inside_allowed_roots() {
        let roots = Roots::new([r"C:\FakeErp"], [r"C:\FakeErp\run"]).unwrap();
        assert!(roots.allowed().is_allowed(r"C:\FakeErp\data\erp.db"));
        assert!(!roots.delete().is_allowed(r"C:\FakeErp\data\erp.db"));
        assert!(roots.delete().is_allowed(r"C:\FakeErp\run\erp.lock"));

        // Equal to an allowed root is inside it.
        assert!(Roots::new([r"C:\FakeErp"], ["c:/fakeerp"]).is_ok());
        // No delete root at all: nothing is deleted.
        let roots = Roots::new(vec![r"C:\FakeErp"], vec![]).unwrap();
        assert!(!roots.delete().is_allowed(r"C:\FakeErp\run\erp.lock"));

        for delete in [r"C:\Other", r"C:\FakeErpEvil", r"D:\FakeErp"] {
            assert_eq!(
                Roots::new([r"C:\FakeErp"], [delete]).unwrap_err(),
                InvalidRoot {
                    root: delete.to_owned(),
                    rule: RootRule::OutsideAllowedRoots,
                }
            );
        }
        // A delete root obeys the root rules as well.
        assert_eq!(
            Roots::new([r"C:\FakeErp"], [r"C:\FakeErp\NUL"])
                .unwrap_err()
                .rule,
            RootRule::NotAPath
        );
        assert_eq!(
            Roots::new([r"C:\FakeErp"], [r"C:\"]).unwrap_err().rule,
            RootRule::Drive
        );
    }
}
