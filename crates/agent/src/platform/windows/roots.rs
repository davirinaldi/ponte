//! The roots as they resolve when the agent starts (ADR-0011, "Roots, kept apart").
//!
//! A root is opened following whatever junction or link it is or passes through, and its
//! final path is what the agent compares every path a manifest names with. The final path
//! must pass the same rules as the root as written (no drive, no Windows folder, no folder
//! every user shares, no profile root), with the folders Windows reports for itself, so a
//! root a user turned into a junction before the agent started cannot point at the system.
//! A delete root must still lie in an allowed root, and the agent's own files (its
//! executable's folder, the configuration, the data directory, the token) may not lie in a
//! root or hold one, as everything resolves.
//!
//! A root that does not exist when the agent starts stays unresolved: nothing under it is
//! used until the agent starts again. An agent can then start on a machine where the ERP
//! is not installed yet, and a root made later, by whoever, is never trusted.

use std::fs::{File, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::path::Path;

use ponte_actions::PathPolicy;
use tracing::warn;
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, SECURITY_IDENTIFICATION, SYNCHRONIZE,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, RRF_RT_REG_SZ, RegCloseKey, RegEnumKeyExW, RegGetValueW,
    RegOpenKeyExW,
};

use super::files::{self, Facts, Segments};
use crate::platform::RootProblem;

/// The roots that resolved when the agent started.
#[derive(Debug, Clone, Default)]
pub(crate) struct ResolvedRoots {
    pub(crate) allowed: Vec<Segments>,
    pub(crate) delete: Vec<Segments>,
}

/// Opens a folder or file following links, to learn where it resolves.
fn open_following(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES | SYNCHRONIZE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .security_qos_flags(SECURITY_IDENTIFICATION)
        .open(path)
}

/// Where `path` resolves, if it exists.
fn resolve(path: &Path) -> std::io::Result<Option<(Segments, Facts)>> {
    let file = match open_following(path) {
        Ok(file) => file,
        Err(error) if files::is_not_found(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    let facts = Facts::of(&file)?;
    let resolved = files::final_path(&file)?;
    Ok(Segments::of_final(&resolved).map(|segments| (segments, facts)))
}

/// A string value under `HKEY_LOCAL_MACHINE`, with its environment expanded. `None` if
/// there is no such value; `Err` if there is one that cannot be read.
fn registry_text(key: HKEY, subkey: &str, value: &str) -> Result<Option<String>, ()> {
    let subkey: Vec<u16> = subkey.encode_utf16().chain(Some(0)).collect();
    let value: Vec<u16> = value.encode_utf16().chain(Some(0)).collect();
    let mut buffer = vec![0_u16; 1024];
    let mut size = u32::try_from(buffer.len() * 2).map_err(|_| ())?;
    // SAFETY: both names are NUL-terminated; `buffer` is writable for `size` bytes.
    let error = unsafe {
        RegGetValueW(
            key,
            subkey.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if error == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if error != 0 {
        return Err(());
    }
    let units = usize::try_from(size).map_err(|_| ())? / 2;
    buffer.truncate(units);
    while buffer.last() == Some(&0) {
        buffer.pop();
    }
    String::from_utf16(&buffer).map(Some).map_err(|_| ())
}

const CURRENT_VERSION: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion";
const PROFILE_LIST: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

/// The profile of every account Windows knows, from the profile list.
fn profiles() -> Result<Vec<String>, ()> {
    let name: Vec<u16> = PROFILE_LIST.encode_utf16().chain(Some(0)).collect();
    let mut key: HKEY = std::ptr::null_mut();
    // SAFETY: `name` is NUL-terminated; `key` receives a handle closed below.
    if unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, name.as_ptr(), 0, KEY_READ, &mut key) } != 0 {
        return Err(());
    }
    let mut paths = Vec::new();
    let mut outcome = Ok(());
    for index in 0.. {
        let mut subkey = [0_u16; 256];
        let mut length = u32::try_from(subkey.len()).unwrap_or(0);
        // SAFETY: `key` is open; `subkey` has room for `length` units.
        let error = unsafe {
            RegEnumKeyExW(
                key,
                index,
                subkey.as_mut_ptr(),
                &mut length,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if error == ERROR_NO_MORE_ITEMS {
            break;
        }
        let Some(subkey) = (error == 0)
            .then(|| String::from_utf16(&subkey[..usize::try_from(length).unwrap_or(0)]).ok())
            .flatten()
        else {
            outcome = Err(());
            break;
        };
        match registry_text(key, &subkey, "ProfileImagePath") {
            Ok(Some(path)) => paths.push(path),
            Ok(None) => {}
            Err(()) => {
                outcome = Err(());
                break;
            }
        }
    }
    // SAFETY: the key was opened above and is closed once.
    unsafe { RegCloseKey(key) };
    outcome.map(|()| paths)
}

/// The folders Windows keeps for itself, as it reports them and as they resolve.
struct WindowsFolders {
    /// No root may be or lie in these.
    system: Vec<Segments>,
    /// No root may be these, though it may lie in them.
    shared: Vec<Segments>,
    /// No root may be a folder right inside these: a user's profile.
    profile_parents: Vec<Segments>,
}

impl WindowsFolders {
    fn read(windows: &[Segments]) -> Result<Self, RootProblem> {
        let read = |subkey, value| {
            registry_text(HKEY_LOCAL_MACHINE, subkey, value).map_err(|()| RootProblem::KnownFolders)
        };
        let mut shared = Vec::new();
        for value in [
            "ProgramFilesDir",
            "ProgramFilesDir (x86)",
            "ProgramW6432Dir",
        ] {
            shared.extend(read(CURRENT_VERSION, value)?);
        }
        shared.extend(read(PROFILE_LIST, "ProgramData")?);
        let profiles_folder =
            read(PROFILE_LIST, "ProfilesDirectory")?.ok_or(RootProblem::KnownFolders)?;
        shared.push(profiles_folder.clone());
        shared.extend(profiles().map_err(|()| RootProblem::KnownFolders)?);

        let mut folders = Self {
            system: windows.to_vec(),
            shared: Vec::new(),
            profile_parents: Vec::new(),
        };
        for text in &shared {
            folders.shared.extend(both_ways(text));
        }
        folders.profile_parents.extend(both_ways(&profiles_folder));
        Ok(folders)
    }

    /// The rule `root` breaks, if any.
    fn rule(&self, root: &Segments) -> Option<&'static str> {
        if self.system.iter().any(|folder| root.inside(folder)) {
            return Some("the Windows folder, or inside it");
        }
        let same = |folder: &Segments| folder.len() == root.len() && root.inside(folder);
        if self.shared.iter().any(same) {
            return Some(
                "a Program Files folder, ProgramData, the folder of profiles or a profile",
            );
        }
        if self
            .profile_parents
            .iter()
            .any(|folder| root.len() == folder.len() + 1 && root.inside(folder))
        {
            return Some("the root of a user's profile");
        }
        None
    }
}

/// A folder as Windows names it and, when it exists, as it resolves.
fn both_ways(text: &str) -> Vec<Segments> {
    let mut found: Vec<Segments> = Segments::of_written(text).into_iter().collect();
    if let Ok(Some((resolved, _))) = resolve(Path::new(text)) {
        found.push(resolved);
    }
    found
}

/// Resolves the roots and holds them to the rules of this module. `own` names the agent's
/// files: the setting, and the path.
pub(crate) fn resolve_roots(
    allowed: &[String],
    delete: &[String],
    own: &[(&'static str, &Path)],
    windows: &[Segments],
) -> Result<ResolvedRoots, RootProblem> {
    let mut roots = ResolvedRoots::default();
    if allowed.is_empty() && delete.is_empty() {
        return Ok(roots);
    }
    let folders = WindowsFolders::read(windows)?;
    for (setting, list, resolved) in [
        ("allowed_roots", allowed, &mut roots.allowed),
        ("delete_roots", delete, &mut roots.delete),
    ] {
        for (index, root) in list.iter().enumerate() {
            let not_a_folder = RootProblem::NotAFolder { setting, index };
            let Some((segments, facts)) = resolve(Path::new(root)).map_err(|_| not_a_folder)?
            else {
                warn!(
                    setting,
                    index,
                    "a root does not exist: nothing under it is used until the agent starts again"
                );
                continue;
            };
            if !facts.is_disk() || !facts.is_directory() {
                return Err(not_a_folder);
            }
            let text = segments.to_text().ok_or(not_a_folder)?;
            if let Err(error) = PathPolicy::new([&text]) {
                return Err(RootProblem::Lexical {
                    setting,
                    index,
                    rule: error.rule,
                });
            }
            if let Some(rule) = folders.rule(&segments) {
                return Err(RootProblem::Forbidden {
                    setting,
                    index,
                    rule,
                });
            }
            resolved.push(segments);
        }
    }
    for (index, root) in roots.delete.iter().enumerate() {
        if !roots.allowed.iter().any(|allowed| root.inside(allowed)) {
            return Err(RootProblem::DeleteOutside { index });
        }
    }
    let texts: Vec<String> = roots.allowed.iter().filter_map(Segments::to_text).collect();
    let policy = PathPolicy::new(&texts).map_err(|_| RootProblem::KnownFolders)?;
    for (what, path) in own {
        let resolved = match resolve(path) {
            Ok(Some((segments, _))) => segments,
            // Nothing there: nothing a manifest could reach through it either.
            Ok(None) => continue,
            Err(_) => return Err(RootProblem::Overlaps { what }),
        };
        let text = resolved.to_text().ok_or(RootProblem::Overlaps { what })?;
        if policy.overlaps(&text) != Ok(false) {
            return Err(RootProblem::Overlaps { what });
        }
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use ponte_actions::RootRule;

    use super::*;
    use crate::platform::windows::files::tests::junction;
    use crate::platform::windows::services::windows_folder;
    use crate::testkit::TempDir;

    fn text(path: &Path) -> String {
        path.to_str().unwrap().to_owned()
    }

    fn resolve_here(allowed: &[&Path], delete: &[&Path]) -> Result<ResolvedRoots, RootProblem> {
        let allowed: Vec<String> = allowed.iter().map(|path| text(path)).collect();
        let delete: Vec<String> = delete.iter().map(|path| text(path)).collect();
        resolve_roots(&allowed, &delete, &[], &windows_folder().unwrap())
    }

    /// A folder of its own under the temporary one, deep enough to be no profile root.
    fn erp() -> (TempDir, PathBuf, PathBuf) {
        let dir = TempDir::new();
        let erp = dir.path().join("FakeErp");
        let run = erp.join("run");
        std::fs::create_dir_all(&run).unwrap();
        (dir, erp, run)
    }

    #[test]
    fn roots_resolve_and_a_missing_one_stays_unresolved() {
        let (dir, erp, run) = erp();
        let roots = resolve_here(&[&erp], &[&run]).unwrap();
        assert_eq!((roots.allowed.len(), roots.delete.len()), (1, 1));
        assert!(roots.delete[0].inside(&roots.allowed[0]));

        let missing = dir.path().join("NotYet");
        let roots = resolve_here(&[&erp, &missing], &[]).unwrap();
        assert_eq!(roots.allowed.len(), 1);
        // Made after the start: still unresolved, until the agent starts again.
        std::fs::create_dir(&missing).unwrap();
        assert!(
            !roots
                .allowed
                .iter()
                .any(|root| root.to_text().unwrap().ends_with("NotYet"))
        );
        assert!(
            resolve_roots(&[], &[], &[], &[])
                .unwrap()
                .allowed
                .is_empty()
        );
    }

    /// A root a user turned into a junction before the agent started, pointing at the
    /// Windows folder or at another place no root may be, refuses the start.
    #[test]
    fn a_root_that_resolves_to_a_forbidden_folder_is_refused() {
        let windows = windows_folder().unwrap();
        let windows_text = windows[1].to_text().unwrap();
        let dir = TempDir::new();
        for (target, rule) in [
            (windows_text.clone(), RootRule::SystemFolder),
            (format!(r"{windows_text}\System32"), RootRule::SystemFolder),
            (r"C:\ProgramData".to_owned(), RootRule::SharedFolder),
            (r"C:\".to_owned(), RootRule::Drive),
        ] {
            let link = dir.path().join(format!("root-{}", target.len()));
            let _ = std::fs::remove_dir(&link);
            junction(&link, Path::new(&target));
            let problem = resolve_here(&[&link], &[]).unwrap_err();
            std::fs::remove_dir(&link).unwrap();
            assert_eq!(
                problem,
                RootProblem::Lexical {
                    setting: "allowed_roots",
                    index: 0,
                    rule
                },
                "{target}"
            );
        }
    }

    /// The folders Windows reports are what the rules name, wherever Windows put them.
    #[test]
    fn the_folders_windows_reports_are_refused_as_roots() {
        let folders = WindowsFolders::read(&windows_folder().unwrap()).unwrap();
        let profiles = registry_text(HKEY_LOCAL_MACHINE, PROFILE_LIST, "ProfilesDirectory")
            .unwrap()
            .unwrap();
        let profiles = Segments::of_written(&profiles).unwrap();
        assert!(folders.rule(&profiles).is_some());
        let user =
            Segments::of_written(&format!("{}\\someone", profiles.to_text().unwrap())).unwrap();
        assert_eq!(folders.rule(&user), Some("the root of a user's profile"));
        let inside =
            Segments::of_written(&format!("{}\\someone\\ERP", profiles.to_text().unwrap()))
                .unwrap();
        assert_eq!(folders.rule(&inside), None);
        let program_data = registry_text(HKEY_LOCAL_MACHINE, PROFILE_LIST, "ProgramData")
            .unwrap()
            .unwrap();
        let program_data = Segments::of_written(&program_data).unwrap();
        assert!(folders.rule(&program_data).is_some());
        let erp =
            Segments::of_written(&format!("{}\\FakeErp", program_data.to_text().unwrap())).unwrap();
        assert_eq!(folders.rule(&erp), None);
        assert!(!super::profiles().unwrap().is_empty());
    }

    #[test]
    fn a_delete_root_resolves_inside_an_allowed_root() {
        let (_dir, erp, _run) = erp();
        let (_other, elsewhere, _) = self::erp();
        // As written it lies inside; as it resolves, elsewhere.
        let link = erp.join("deletes");
        junction(&link, &elsewhere);
        assert_eq!(
            resolve_here(&[&erp], &[&link]).unwrap_err(),
            RootProblem::DeleteOutside { index: 0 }
        );
    }

    /// The agent's own files may not lie in a root as it resolves: a manifest could then
    /// delete the journal or the key.
    #[test]
    fn the_agents_own_files_lie_outside_the_roots_as_they_resolve() {
        let (_dir, erp, _run) = erp();
        let data = erp.join("ponte-data");
        std::fs::create_dir(&data).unwrap();
        let windows = windows_folder().unwrap();
        let allowed = [text(&erp)];
        assert_eq!(
            resolve_roots(&allowed, &[], &[("data_dir", &data)], &windows).unwrap_err(),
            RootProblem::Overlaps { what: "data_dir" }
        );
        // Through a junction elsewhere that points into the root, the same.
        let (_away, place, _) = self::erp();
        let alias = place.join("data");
        junction(&alias, &data);
        assert_eq!(
            resolve_roots(&allowed, &[], &[("data_dir", &alias)], &windows).unwrap_err(),
            RootProblem::Overlaps { what: "data_dir" }
        );
        assert!(resolve_roots(&allowed, &[], &[("data_dir", &place)], &windows).is_ok());
        // A file that is not there yet cannot be reached either.
        assert!(
            resolve_roots(
                &allowed,
                &[],
                &[("enrollment_token_file", &erp.join("token"))],
                &windows
            )
            .is_ok()
        );
    }

    #[test]
    fn a_root_that_is_a_file_is_refused() {
        let (_dir, erp, _run) = erp();
        let file = erp.join("erp.db");
        std::fs::write(&file, b"").unwrap();
        assert_eq!(
            resolve_here(&[&file], &[]).unwrap_err(),
            RootProblem::NotAFolder {
                setting: "allowed_roots",
                index: 0
            }
        );
    }
}
