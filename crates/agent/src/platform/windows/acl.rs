//! Who owns, and who may change, what the agent trusts (ADR-0011, "The configuration is a
//! root of trust"; ADR-0013).
//!
//! The configuration names the keys that decide what SYSTEM runs, and the data directory
//! holds the journal and the key. When the agent runs elevated, each of them must be
//! owned by SYSTEM or Administrators and grant nobody else the right to change it, and no
//! folder above may let anyone else delete, rename or re-permission what it holds. A path
//! is walked from the root of its drive, one folder at a time, each opened without
//! following a reparse point: a junction or a mount point anywhere on the way is refused,
//! so the folders checked are the folders the agent then uses.
//!
//! The rules, per folder or file:
//!
//! | Rule | Applies to | Owner | Nobody else may |
//! |---|---|---|---|
//! | `Own` | the configuration and its folder, the token and its folder, the data directory | SYSTEM, Administrators | write, append, delete, change the ACL or the owner |
//! | `Executable` | the agent's executable and its folder, a service's binary and its folder | SYSTEM, Administrators, TrustedInstaller | the same |
//! | `Above` | every folder above those, up to the drive | SYSTEM, Administrators, TrustedInstaller | delete or rename what it holds, change the ACL or the owner |
//!
//! Generic rights count as what they map to for files, and `MAXIMUM_ALLOWED` as everything.
//! Deny entries are ignored, since they only take rights away. For `Own` and `Executable`
//! an entry that only children inherit still counts, since it decides what the files the
//! agent makes there inherit; for `Above` it does not, since each folder below is checked
//! on its own. CREATOR OWNER and CREATOR GROUP are ignored when only inherited, and OWNER
//! RIGHTS is the owner, who already passed. An entry of any other kind, or no ACL at all,
//! is refused. Mandatory labels are not part of the rule.

use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, CopySid,
    DACL_SECURITY_INFORMATION, EqualSid, GENERIC_MAPPING, GetAce, GetAclInformation, GetLengthSid,
    GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, INHERIT_ONLY_ACE, MapGenericMask,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, DELETE, FILE_ALL_ACCESS, FILE_APPEND_DATA, FILE_DELETE_CHILD,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_EXECUTE,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA,
    GetVolumeInformationByHandleW, READ_CONTROL, SECURITY_IDENTIFICATION, SYNCHRONIZE, WRITE_DAC,
    WRITE_OWNER,
};

use super::files::{self, Facts, Segments};
use crate::platform::{Leaf, Untrusted as AclError};

/// Every folder the agent makes: SYSTEM and Administrators, and the folder's owner, which
/// is SYSTEM for the service and Administrators for an elevated console. Inherits nothing.
/// An ordinary console that makes one owns it, can use it, and a service then refuses it.
pub(crate) const PRIVATE_FOLDER: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)";

/// The types of entry in a DACL that this rule reads (`winnt.h`).
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;

/// The flag of a file system that keeps access lists (`winnt.h`).
const FILE_PERSISTENT_ACLS: u32 = 0x8;

/// `MAXIMUM_ALLOWED` in an entry grants whatever the object allows.
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

/// What `Own` and `Executable` let nobody else do: change the content or the folder's
/// entries, delete, change the ACL or the owner, or write attributes, which is all NTFS
/// asks of whoever makes a hard link to a file, or extended attributes.
const CHANGES: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_ATTRIBUTES
    | FILE_WRITE_EA
    | FILE_DELETE_CHILD
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | MAXIMUM_ALLOWED;
/// What `Above` lets nobody else do: delete or rename an entry, or change the ACL or the
/// owner. Creating new entries is allowed: `C:\` and `C:\ProgramData` allow it to everyone.
const REPLACES: u32 = FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | MAXIMUM_ALLOWED;

/// Which rule a folder or file is held to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    Own,
    Executable,
    Above,
}

/// A SID of our own, copied out of the buffer Windows made.
struct Sid(Vec<u8>);

impl Sid {
    fn parse(text: &str) -> Option<Self> {
        let text: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
        let mut sid: PSID = std::ptr::null_mut();
        // SAFETY: `text` is NUL-terminated and lives through the call; `sid` receives a
        // buffer from LocalAlloc, freed below.
        if unsafe { ConvertStringSidToSidW(text.as_ptr(), &mut sid) } == 0 {
            return None;
        }
        // SAFETY: `sid` is the valid SID just made.
        let length = unsafe { GetLengthSid(sid) };
        let mut copy = vec![0_u8; usize::try_from(length).ok()?];
        // SAFETY: `copy` has `length` bytes, and `sid` is valid until freed.
        let copied = unsafe { CopySid(length, copy.as_mut_ptr().cast(), sid) } != 0;
        // SAFETY: `sid` came from ConvertStringSidToSidW and is freed once.
        unsafe { LocalFree(sid) };
        copied.then_some(Self(copy))
    }

    fn is(&self, other: PSID) -> bool {
        // SAFETY: both are valid SIDs: ours, and one inside a descriptor that outlives
        // the call.
        unsafe { EqualSid(self.0.as_ptr().cast_mut().cast(), other) != 0 }
    }
}

/// The accounts the rules name.
struct Accounts {
    system: Sid,
    administrators: Sid,
    trusted_installer: Sid,
    creator_owner: Sid,
    creator_group: Sid,
    owner_rights: Sid,
}

fn accounts() -> Option<&'static Accounts> {
    static ACCOUNTS: OnceLock<Option<Accounts>> = OnceLock::new();
    ACCOUNTS
        .get_or_init(|| {
            Some(Accounts {
                system: Sid::parse("S-1-5-18")?,
                administrators: Sid::parse("S-1-5-32-544")?,
                trusted_installer: Sid::parse(
                    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
                )?,
                creator_owner: Sid::parse("S-1-3-0")?,
                creator_group: Sid::parse("S-1-3-1")?,
                owner_rights: Sid::parse("S-1-3-4")?,
            })
        })
        .as_ref()
}

impl Accounts {
    /// Who may own, and may change, what `rule` holds.
    fn trusted(&self, rule: Rule, sid: PSID) -> bool {
        self.system.is(sid)
            || self.administrators.is(sid)
            || (rule != Rule::Own && self.trusted_installer.is(sid))
    }
}

/// Whether `sid` is SYSTEM's.
pub(crate) fn is_system(sid: PSID) -> bool {
    !sid.is_null() && accounts().is_some_and(|accounts| accounts.system.is(sid))
}

/// A security descriptor Windows allocated, freed when dropped.
pub(crate) struct Descriptor(PSECURITY_DESCRIPTOR);

impl Descriptor {
    /// From its text form (SDDL).
    pub(crate) fn from_sddl(sddl: &str) -> io::Result<Self> {
        let text: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `text` is NUL-terminated and lives through the call; `descriptor`
        // receives a LocalAlloc buffer that `Drop` frees.
        let made = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if made == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(descriptor))
    }

    /// The owner and the DACL of the file `file` holds.
    pub(crate) fn of(file: &File) -> io::Result<Self> {
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: the handle belongs to `file` and was opened with READ_CONTROL; the
        // pointers it could fill into the descriptor are not asked for, and `descriptor`
        // receives a LocalAlloc buffer that `Drop` frees.
        let error = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        if error != 0 {
            return Err(io::Error::from_raw_os_error(
                i32::try_from(error).unwrap_or(i32::MAX),
            ));
        }
        Ok(Self(descriptor))
    }

    pub(crate) fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.0
    }

    /// Whether `rule` holds for this descriptor.
    pub(crate) fn check(&self, rule: Rule) -> Result<(), AclError> {
        let accounts = accounts().ok_or(AclError::Unreadable)?;
        let mut owner: PSID = std::ptr::null_mut();
        let mut defaulted = 0;
        // SAFETY: `self.0` is a valid descriptor; `owner` receives a pointer into it.
        if unsafe { GetSecurityDescriptorOwner(self.0, &mut owner, &mut defaulted) } == 0
            || owner.is_null()
        {
            return Err(AclError::Unreadable);
        }
        if !accounts.trusted(rule, owner) {
            return Err(AclError::Owner);
        }
        let (mut present, mut dacl) = (0, std::ptr::null_mut::<ACL>());
        // SAFETY: as above; `dacl` receives a pointer into the descriptor.
        if unsafe { GetSecurityDescriptorDacl(self.0, &mut present, &mut dacl, &mut defaulted) }
            == 0
        {
            return Err(AclError::Unreadable);
        }
        // No DACL at all lets everyone do everything.
        if present == 0 || dacl.is_null() {
            return Err(AclError::Unreadable);
        }
        let mut size = ACL_SIZE_INFORMATION::default();
        // SAFETY: `dacl` points into the descriptor, and `size` has the size passed.
        let read = unsafe {
            GetAclInformation(
                dacl,
                (&raw mut size).cast::<c_void>(),
                u32::try_from(size_of::<ACL_SIZE_INFORMATION>()).unwrap_or(u32::MAX),
                AclSizeInformation,
            )
        };
        if read == 0 {
            return Err(AclError::Unreadable);
        }
        let forbidden = if rule == Rule::Above {
            REPLACES
        } else {
            CHANGES
        };
        for index in 0..size.AceCount {
            let mut ace: *mut c_void = std::ptr::null_mut();
            // SAFETY: `index` is below the count the ACL gave; `ace` receives a pointer
            // into the ACL.
            if unsafe { GetAce(dacl, index, &mut ace) } == 0 || ace.is_null() {
                return Err(AclError::Unreadable);
            }
            // SAFETY: every entry starts with an ACE_HEADER.
            let header = unsafe { ace.cast::<ACE_HEADER>().read_unaligned() };
            match header.AceType {
                ACCESS_DENIED_ACE_TYPE => continue,
                ACCESS_ALLOWED_ACE_TYPE => {}
                // Object, callback and conditional entries are not read by this rule.
                _ => return Err(AclError::Unreadable),
            }
            // SAFETY: an entry of this type is an ACCESS_ALLOWED_ACE, its SID starting at
            // `SidStart`, inside the entry's size.
            let (mut mask, sid) = unsafe {
                let allowed = ace.cast::<ACCESS_ALLOWED_ACE>();
                (
                    (&raw const (*allowed).Mask).read_unaligned(),
                    (&raw mut (*allowed).SidStart).cast::<c_void>(),
                )
            };
            let inherit_only = u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0;
            if inherit_only && rule == Rule::Above {
                continue;
            }
            if accounts.trusted(rule, sid) || accounts.owner_rights.is(sid) {
                continue;
            }
            if inherit_only && (accounts.creator_owner.is(sid) || accounts.creator_group.is(sid)) {
                continue;
            }
            let mapping = GENERIC_MAPPING {
                GenericRead: FILE_GENERIC_READ,
                GenericWrite: FILE_GENERIC_WRITE,
                GenericExecute: FILE_GENERIC_EXECUTE,
                GenericAll: FILE_ALL_ACCESS,
            };
            // SAFETY: both point to values that live through the call.
            unsafe { MapGenericMask(&mut mask, &mapping) };
            // MAXIMUM_ALLOWED is not a generic right: it stays in the mask, and counts.
            if mask & forbidden != 0 {
                return Err(AclError::Grants);
            }
        }
        Ok(())
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: the descriptor came from LocalAlloc in one of the constructors and is
        // freed once.
        unsafe { LocalFree(self.0) };
    }
}

/// Opens one folder or file of a path to read its owner and ACL, without following a
/// reparse point.
fn open_for_rule(path: &str) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .security_qos_flags(SECURITY_IDENTIFICATION)
        .open(path)
}

/// Whether the volume `file` lies on keeps access lists (NTFS does; FAT does not).
fn keeps_acls(file: &File) -> bool {
    let mut flags = 0_u32;
    // SAFETY: the handle belongs to `file`; the buffers not asked for are null with a
    // size of 0, and `flags` receives the file system's flags.
    let read = unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut flags,
            std::ptr::null_mut(),
            0,
        )
    };
    read != 0 && flags & FILE_PERSISTENT_ACLS != 0
}

/// The text of a path's first `count` segments, as Windows opens it.
fn prefix(segments: &[String], count: usize) -> String {
    if count == 1 {
        format!("{}\\", segments[0])
    } else {
        segments[..count].join("\\")
    }
}

/// Holds `path`, and every folder above it up to its drive, to the rules of this module:
/// `leaf` says which rule the last part and its folder get.
pub(crate) fn check_chain(path: &Path, leaf: Leaf) -> Result<(), AclError> {
    let text = path.to_str().ok_or(AclError::NotAbsolute)?;
    let written = Segments::of_written(text).ok_or(AclError::NotAbsolute)?;
    let segments: Vec<String> = text
        .split(['\\', '/'])
        .filter(|segment| !segment.is_empty())
        .map(str::to_owned)
        .collect();
    if segments.len() != written.len()
        || segments
            .iter()
            .any(|segment| segment == "." || segment == "..")
    {
        return Err(AclError::NotAbsolute);
    }
    let last = segments.len();
    for count in 1..=last {
        let rule = match leaf {
            Leaf::Directory if count == last => Rule::Own,
            Leaf::File if count + 1 >= last => Rule::Own,
            Leaf::Executable if count + 1 >= last => Rule::Executable,
            Leaf::Directory | Leaf::File | Leaf::Executable | Leaf::Above => Rule::Above,
        };
        // The drive itself is held to `Above` whatever lies under it.
        let rule = if count == 1 { Rule::Above } else { rule };
        let file = open_for_rule(&prefix(&segments, count)).map_err(|error| {
            if files::is_not_found(&error) {
                AclError::Missing
            } else {
                AclError::Unreadable
            }
        })?;
        let facts = Facts::of(&file).map_err(|_| AclError::Unreadable)?;
        if !facts.is_disk() {
            return Err(AclError::NotDisk);
        }
        if count > 1 && facts.is_reparse_point() {
            return Err(AclError::ReparsePoint);
        }
        if count == last {
            if !keeps_acls(&file) {
                return Err(AclError::NoAcls);
            }
            let resolved = files::final_path(&file)
                .ok()
                .and_then(|path| Segments::of_final(&path))
                .ok_or(AclError::Moved)?;
            if resolved.len() != written.len() || !resolved.inside(&written) {
                return Err(AclError::Moved);
            }
        }
        Descriptor::of(&file)
            .map_err(|_| AclError::Unreadable)?
            .check(rule)?;
    }
    Ok(())
}

/// Creates `dir` and whatever is missing above it, each with [`PRIVATE_FOLDER`]. A folder
/// that already exists keeps its ACL: when the agent runs elevated, [`check_chain`] decides
/// whether it may be used.
pub(crate) fn create_private_dir(dir: &Path) -> io::Result<()> {
    let dir = std::path::absolute(dir)?;
    let mut missing = Vec::new();
    for folder in dir.ancestors() {
        match std::fs::symlink_metadata(folder) {
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::NotFound => missing.push(folder),
            Err(error) => return Err(error),
        }
    }
    if missing.is_empty() {
        return Ok(());
    }
    let descriptor = Descriptor::from_sddl(PRIVATE_FOLDER)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
        lpSecurityDescriptor: descriptor.as_ptr(),
        bInheritHandle: 0,
    };
    for folder in missing.into_iter().rev() {
        let path = files::wide(folder);
        // SAFETY: `path` is NUL-terminated, and `attributes` points to a descriptor that
        // lives through the call.
        if unsafe { CreateDirectoryW(path.as_ptr(), &attributes) } == 0 {
            let error = io::Error::last_os_error();
            // Made by someone else in the meantime: its ACL is checked like any other.
            if error.raw_os_error() != i32::try_from(ERROR_ALREADY_EXISTS).ok() {
                return Err(error);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use windows_sys::Win32::Security::{GetSecurityDescriptorControl, SE_DACL_PROTECTED};

    use std::path::PathBuf;

    use super::*;
    use crate::platform::Elevation;
    use crate::testkit::TempDir;

    fn rule(sddl: &str, rule: Rule) -> Result<(), AclError> {
        Descriptor::from_sddl(sddl).unwrap().check(rule)
    }

    const ADMINS_ONLY: &str = "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)";

    #[test]
    fn the_folder_the_agent_makes_passes_its_own_rule() {
        assert_eq!(rule(ADMINS_ONLY, Rule::Own), Ok(()));
        assert_eq!(
            rule("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", Rule::Own),
            Ok(())
        );
        // Users may read and run.
        assert_eq!(
            rule("O:SYD:(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)", Rule::Own),
            Ok(())
        );
        // A deny entry only takes rights away.
        assert_eq!(rule("O:SYD:(A;;FA;;;SY)(D;;FA;;;WD)", Rule::Own), Ok(()));
    }

    #[test]
    fn the_owner_must_be_system_or_administrators() {
        // The user of the machine, a service account, Everyone.
        for owner in ["BU", "S-1-5-21-1-2-3-1001", "LS", "WD"] {
            let sddl = format!("O:{owner}D:P(A;;FA;;;SY)");
            assert_eq!(rule(&sddl, Rule::Own), Err(AclError::Owner), "{owner}");
            assert_eq!(rule(&sddl, Rule::Above), Err(AclError::Owner), "{owner}");
        }
        let installer =
            "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:P(A;;FA;;;SY)";
        assert_eq!(rule(installer, Rule::Own), Err(AclError::Owner));
        assert_eq!(rule(installer, Rule::Above), Ok(()));
        assert_eq!(rule(installer, Rule::Executable), Ok(()));
    }

    /// Each right that lets another account change what the agent trusts, alone, and
    /// through the generic rights that include it.
    #[test]
    fn no_other_account_may_change_what_the_agent_trusts() {
        for right in [
            "0x2",
            "0x4",
            "0x40",
            "0x10000",
            "0x40000",
            "0x80000",
            "0x2000000",
            "GA",
            "GW",
            "FA",
            "FW",
            "SD",
            "WD",
            "WO",
            // Writing attributes is enough to make a hard link to a file, and extended
            // attributes travel with it.
            "0x100",
            "0x10",
        ] {
            for who in ["BU", "AU", "WD", "IU", "S-1-5-21-1-2-3-1001"] {
                let sddl = format!("O:SYD:(A;;FA;;;SY)(A;;{right};;;{who})");
                assert_eq!(
                    rule(&sddl, Rule::Own),
                    Err(AclError::Grants),
                    "{right} {who}"
                );
                assert_eq!(
                    rule(&sddl, Rule::Executable),
                    Err(AclError::Grants),
                    "{right} {who}"
                );
            }
        }
        // Reading and running change nothing.
        for right in ["FR", "FX", "0x80", "0x8", "GR", "GX"] {
            let sddl = format!("O:SYD:(A;;FA;;;SY)(A;;{right};;;BU)");
            assert_eq!(rule(&sddl, Rule::Own), Ok(()), "{right}");
        }
    }

    /// Above, others may add entries (as `C:\` and `C:\ProgramData` let them) but never
    /// remove, rename or re-permission one.
    #[test]
    fn above_others_may_add_but_never_replace() {
        for right in ["0x2", "0x4", "0x6", "FW", "GW", "0x100", "0x10"] {
            let sddl = format!("O:SYD:(A;;FA;;;SY)(A;;{right};;;BU)");
            assert_eq!(rule(&sddl, Rule::Above), Ok(()), "{right}");
        }
        for right in [
            "0x40",
            "0x10000",
            "0x40000",
            "0x80000",
            "0x2000000",
            "GA",
            "FA",
            "SD",
        ] {
            let sddl = format!("O:SYD:(A;;FA;;;SY)(A;;{right};;;BU)");
            assert_eq!(rule(&sddl, Rule::Above), Err(AclError::Grants), "{right}");
        }
    }

    /// An entry only children inherit decides what the agent's new files inherit, so it
    /// counts for the agent's own folders. Above, each folder below is checked by itself.
    #[test]
    fn inherited_entries_count_where_the_agent_makes_files() {
        let users = "O:SYD:(A;;FA;;;SY)(A;OICIIO;FA;;;BU)";
        assert_eq!(rule(users, Rule::Own), Err(AclError::Grants));
        assert_eq!(rule(users, Rule::Executable), Err(AclError::Grants));
        assert_eq!(rule(users, Rule::Above), Ok(()));
        // The creator of a child is whoever may create one, checked by the other entries.
        let creator = "O:SYD:(A;;FA;;;SY)(A;OICIIO;FA;;;CO)(A;OICIIO;FA;;;CG)";
        assert_eq!(rule(creator, Rule::Own), Ok(()));
        // An entry for CREATOR OWNER that applies to the folder itself is no such case.
        assert_eq!(
            rule("O:SYD:(A;;FA;;;SY)(A;;FA;;;CO)", Rule::Own),
            Err(AclError::Grants)
        );
    }

    #[test]
    fn no_acl_or_an_entry_of_another_kind_is_refused() {
        assert_eq!(
            rule("O:SYD:NO_ACCESS_CONTROL", Rule::Own),
            Err(AclError::Unreadable)
        );
        assert_eq!(rule("O:SY", Rule::Own), Err(AclError::Unreadable));
        // An object entry, and a callback entry.
        assert_eq!(
            rule(
                "O:SYD:(A;;FA;;;SY)(OA;;FR;bf967aba-0de6-11d0-a285-00aa003049e2;;BU)",
                Rule::Own
            ),
            Err(AclError::Unreadable)
        );
        assert_eq!(
            rule(
                "O:SYD:(A;;FA;;;SY)(XA;;FR;;;BU;(@User.Title==\"x\"))",
                Rule::Own
            ),
            Err(AclError::Unreadable)
        );
    }

    /// The folders Windows makes, as they come, pass the rule for folders above.
    #[test]
    fn the_folders_windows_makes_pass_as_folders_above() {
        for folder in [
            r"C:\",
            r"C:\ProgramData",
            r"C:\Program Files",
            r"C:\Windows",
        ] {
            let file = open_for_rule(folder).unwrap();
            assert_eq!(
                Descriptor::of(&file).unwrap().check(Rule::Above),
                Ok(()),
                "{folder}"
            );
        }
        // The executables of Windows pass the rule for executables, folders above and all.
        assert_eq!(
            check_chain(Path::new(r"C:\Windows\System32\cmd.exe"), Leaf::Executable),
            Ok(())
        );
    }

    /// `Documents and Settings` is a junction on every Windows: a path through it is not
    /// the path it looks like.
    #[test]
    fn a_reparse_point_on_the_way_is_refused() {
        assert_eq!(
            check_chain(
                Path::new(r"C:\Documents and Settings\Public"),
                Leaf::Directory
            ),
            Err(AclError::ReparsePoint)
        );
        // Any user may make a folder in `C:\ProgramData`: here, a junction where the data
        // directory would be, made before the agent is installed.
        let target = TempDir::new();
        let link = PathBuf::from(format!(
            r"C:\ProgramData\ponte-test-junction-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir(&link);
        super::files::tests::junction(&link, target.path());
        let checked = check_chain(&link, Leaf::Directory);
        std::fs::remove_dir(&link).unwrap();
        assert_eq!(checked, Err(AclError::ReparsePoint));
    }

    #[test]
    fn only_absolute_plain_paths_are_checked() {
        for path in [
            r"data",
            r"\ProgramData\Ponte",
            r"\\?\C:\ProgramData\Ponte",
            r"\??\C:\ProgramData\Ponte",
            r"\\server\share\Ponte",
            r"C:\ProgramData\..\Ponte",
            r"C:\ProgramData\.\Ponte",
            r"C:ProgramData",
        ] {
            assert_eq!(
                check_chain(Path::new(path), Leaf::Directory),
                Err(AclError::NotAbsolute),
                "{path}"
            );
        }
        assert_eq!(
            check_chain(
                Path::new(r"C:\ProgramData\ponte-surely-missing\x"),
                Leaf::File
            ),
            Err(AclError::Missing)
        );
    }

    /// A short 8.3 name resolves to its long name: the path checked would not be the path
    /// written. Only where the volume keeps short names.
    #[test]
    fn a_path_that_resolves_elsewhere_is_refused() {
        match check_chain(Path::new(r"C:\PROGRA~1"), Leaf::Directory) {
            Err(AclError::Missing) => {}
            other => assert_eq!(other, Err(AclError::Moved)),
        }
    }

    /// The folder that holds the configuration gets the strict rule, not the one for folders
    /// above: a folder made in `C:\ProgramData` by an administrator inherits "users may add
    /// files", which is fine above and not where the configuration lies. Only an elevated
    /// token makes such a folder owned by Administrators.
    #[test]
    fn the_folder_that_holds_a_file_is_held_to_the_strict_rule() {
        if crate::platform::elevation() != Elevation::Elevated {
            return;
        }
        let folder = PathBuf::from(format!(
            r"C:\ProgramData\ponte-test-holder-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&folder);
        std::fs::create_dir(&folder).unwrap();
        let file = folder.join("agent.toml");
        std::fs::write(&file, "").unwrap();
        let as_file = check_chain(&file, Leaf::File);
        let as_folder_above = Descriptor::of(&open_for_rule(folder.to_str().unwrap()).unwrap())
            .unwrap()
            .check(Rule::Above);
        std::fs::remove_dir_all(&folder).unwrap();
        assert_eq!(as_file, Err(AclError::Grants));
        assert_eq!(as_folder_above, Ok(()));
    }

    /// A user's own folders are never trusted: here the profile, which its user controls,
    /// fails as a folder above before anything below it is read.
    #[test]
    fn a_folder_a_user_controls_is_refused() {
        let dir = TempDir::new();
        let file = dir.path().join("agent.toml");
        std::fs::write(&file, "").unwrap();
        assert!(matches!(
            check_chain(&file, Leaf::File),
            Err(AclError::Owner | AclError::Grants)
        ));
        // A folder a user made in `C:\ProgramData` is theirs.
        let made = PathBuf::from(format!(
            r"C:\ProgramData\ponte-test-folder-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&made).unwrap();
        let checked = check_chain(&made, Leaf::Directory);
        std::fs::remove_dir(&made).unwrap();
        if crate::platform::elevation() == Elevation::NotElevated {
            assert_eq!(checked, Err(AclError::Owner));
        } else {
            // Made by an elevated administrator, it inherits the ACL of ProgramData, where
            // every user may write: refused all the same.
            assert_eq!(checked, Err(AclError::Grants));
        }
    }

    #[test]
    fn a_private_folder_has_the_protected_acl() {
        let dir = TempDir::new();
        let made = dir.path().join("one").join("two");
        create_private_dir(&made).unwrap();
        create_private_dir(&made).unwrap();
        for folder in [dir.path().join("one"), made] {
            let file = open_for_rule(folder.to_str().unwrap()).unwrap();
            let descriptor = Descriptor::of(&file).unwrap();
            let mut control = 0_u16;
            let mut revision = 0_u32;
            // SAFETY: the descriptor is valid; both outputs live through the call.
            let read = unsafe {
                GetSecurityDescriptorControl(descriptor.as_ptr(), &mut control, &mut revision)
            };
            assert_ne!(read, 0);
            assert_ne!(control & SE_DACL_PROTECTED, 0, "it inherits nothing");
            let mut owner: PSID = std::ptr::null_mut();
            let (mut present, mut dacl, mut defaulted) = (0, std::ptr::null_mut::<ACL>(), 0);
            // SAFETY: as above.
            unsafe {
                GetSecurityDescriptorOwner(descriptor.as_ptr(), &mut owner, &mut defaulted);
                GetSecurityDescriptorDacl(
                    descriptor.as_ptr(),
                    &mut present,
                    &mut dacl,
                    &mut defaulted,
                );
            }
            let mut size = ACL_SIZE_INFORMATION::default();
            // SAFETY: `dacl` is the DACL of the descriptor; `size` has the size passed.
            unsafe {
                GetAclInformation(
                    dacl,
                    (&raw mut size).cast(),
                    u32::try_from(size_of::<ACL_SIZE_INFORMATION>()).unwrap(),
                    AclSizeInformation,
                );
            }
            // SYSTEM, Administrators and the owner; the owner's entry is made concrete
            // for the folder itself, and stays for what it holds.
            assert!((3..=4).contains(&size.AceCount), "{}", size.AceCount);
        }
    }
}
