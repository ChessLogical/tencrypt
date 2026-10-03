//! Windows 10/11 implementation for a local NTFS volume.
//!
//! FileRenameInfoEx performs a handle-based rename with POSIX replacement
//! semantics. The Win32 call receives a full destination path and a null
//! RootDirectory; its wrapper does not reliably support directory-relative
//! names. There is deliberately no ReplaceFileW fallback: its documented
//! partial-failure states can move or remove the original filename.

use super::{CommitOutcome, temporary_name, validate_basename};
use anyhow::{Context, Result, bail, ensure};
use std::ffi::{OsStr, OsString, c_void};
use std::fs::File;
use std::io::Write;
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_HANDLE_EOF, ERROR_MORE_DATA, GENERIC_READ,
    GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateFileW, DELETE, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_BASIC_INFO, FILE_DISPOSITION_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_SEQUENTIAL_SCAN,
    FILE_READ_ATTRIBUTES, FILE_RENAME_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_STREAM_INFO, FILE_TRAVERSE, FILE_TYPE_DISK, FileBasicInfo, FileDispositionInfo,
    FileRenameInfoEx, FileStreamInfo, GetDriveTypeW, GetFileInformationByHandle,
    GetFileInformationByHandleEx, GetFileType, GetVolumeInformationByHandleW, GetVolumePathNameW,
    LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx, OPEN_EXISTING,
    SetFileInformationByHandle,
};
use windows_sys::Win32::System::IO::OVERLAPPED;
use windows_sys::Win32::System::SystemServices::{FILE_NAMED_STREAMS, FILE_PERSISTENT_ACLS};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::System::WindowsProgramming::{
    DRIVE_FIXED, DRIVE_REMOVABLE, FILE_RENAME_FLAG_POSIX_SEMANTICS,
    FILE_RENAME_FLAG_REPLACE_IF_EXISTS,
};

fn handle(file: &File) -> HANDLE {
    file.as_raw_handle()
}

fn wide_path(path: &Path) -> Result<Vec<u16>> {
    ensure!(
        path.is_absolute(),
        "the executable directory must be an absolute path"
    );
    let mut units: Vec<u16> = path.as_os_str().encode_wide().collect();
    ensure!(!units.contains(&0), "a path contains a NUL character");
    // Explicit extended-length paths work without relying on a process manifest
    // or on the machine-wide long-path registry setting.
    let extended: Vec<u16> = "\\\\?\\".encode_utf16().collect();
    if !units.starts_with(&extended) {
        if units.starts_with(&[b'\\' as u16, b'\\' as u16]) {
            let mut prefixed: Vec<u16> = "\\\\?\\UNC\\".encode_utf16().collect();
            prefixed.extend_from_slice(&units[2..]);
            units = prefixed;
        } else {
            let mut prefixed = extended;
            prefixed.extend_from_slice(&units);
            units = prefixed;
        }
    }
    units.push(0);
    Ok(units)
}

fn open_file(path: &Path, access: u32, share: u32, flags: u32) -> Result<File> {
    let path = wide_path(path)?;
    // SAFETY: path is NUL-terminated, optional pointers are null, and the handle
    // is either INVALID_HANDLE_VALUE or a newly owned synchronous file handle.
    let raw = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            share,
            null(),
            OPEN_EXISTING,
            flags | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error()).context("cannot open the requested file");
    }
    // SAFETY: this call takes sole ownership of the successful CreateFile handle.
    Ok(unsafe { File::from_raw_handle(raw) })
}

fn raw_info(file: &File) -> Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the file handle remains open for this metadata-only query.
    let file_type = unsafe { GetFileType(handle(file)) };
    ensure!(
        file_type == FILE_TYPE_DISK,
        "only ordinary disk files are supported"
    );
    // SAFETY: info is a writable output structure and the handle remains open.
    if unsafe { GetFileInformationByHandle(handle(file), &mut info) } == 0 {
        return Err(std::io::Error::last_os_error()).context("cannot inspect the open file");
    }
    ensure!(
        info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "reparse points, symbolic links, and cloud placeholders are not supported"
    );
    Ok(info)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Snapshot {
    volume: u32,
    index: u64,
    length: u64,
    links: u32,
    attributes: u32,
    created: i64,
    modified: i64,
    changed: i64,
}

impl Snapshot {
    fn read(file: &File) -> Result<Self> {
        let info = raw_info(file)?;
        ensure!(
            info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0,
            "only regular files are supported"
        );
        ensure!(
            info.nNumberOfLinks == 1,
            "files with more than one hard link are not supported"
        );
        let mut basic = FILE_BASIC_INFO::default();
        // SAFETY: correctly aligned output matches FileBasicInfo and its size.
        if unsafe {
            GetFileInformationByHandleEx(
                handle(file),
                FileBasicInfo,
                (&mut basic as *mut FILE_BASIC_INFO).cast(),
                size_of::<FILE_BASIC_INFO>() as u32,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error())
                .context("cannot inspect the file timestamps");
        }
        Ok(Self {
            volume: info.dwVolumeSerialNumber,
            index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
            length: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
            links: info.nNumberOfLinks,
            attributes: basic.FileAttributes,
            created: basic.CreationTime,
            modified: basic.LastWriteTime,
            changed: basic.ChangeTime,
        })
    }

    fn same_identity(&self, other: &Self) -> bool {
        self.volume == other.volume && self.index == other.index
    }
}

fn directory(path: &Path) -> Result<File> {
    // Omit delete sharing so the opened parent itself cannot be renamed while
    // the transaction is active. Traversal/read-attribute access suffices to
    // inspect and retain this directory without requiring administrator.
    let file = open_file(
        path,
        FILE_TRAVERSE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_FLAG_BACKUP_SEMANTICS,
    )
    .context("cannot open the executable directory")?;
    let info = raw_info(&file)?;
    ensure!(
        info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0,
        "the executable directory is not a directory"
    );
    let mut filesystem = [0u16; 32];
    let mut flags = 0u32;
    // SAFETY: valid directory handle, output arrays and lengths; unused optional
    // output parameters are null.
    if unsafe {
        GetVolumeInformationByHandleW(
            handle(&file),
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            &mut flags,
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("a local NTFS volume is required");
    }
    let end = filesystem
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(filesystem.len());
    ensure!(
        String::from_utf16_lossy(&filesystem[..end]) == "NTFS"
            && flags & FILE_PERSISTENT_ACLS != 0
            && flags & FILE_NAMED_STREAMS != 0,
        "the Windows binary requires a local NTFS volume with access-control support"
    );
    let mut volume_path = vec![0u16; 32_768];
    let full = wide_path(path)?;
    // SAFETY: input and output buffers remain valid for the synchronous call.
    if unsafe {
        GetVolumePathNameW(
            full.as_ptr(),
            volume_path.as_mut_ptr(),
            volume_path.len() as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("cannot verify that the NTFS volume is local");
    }
    // SAFETY: GetVolumePathNameW supplied a NUL-terminated volume root.
    let drive_type = unsafe { GetDriveTypeW(volume_path.as_ptr()) };
    ensure!(
        matches!(drive_type, DRIVE_FIXED | DRIVE_REMOVABLE),
        "network volumes and RAM disks are not supported; use a local NTFS disk"
    );
    Ok(file)
}

fn lock_exclusive(file: &File) -> Result<()> {
    let mut overlapped = OVERLAPPED::default();
    // SAFETY: OVERLAPPED is initialized with offset zero and remains valid for
    // this synchronous, fail-immediately operation. Closing File unlocks it.
    if unsafe {
        LockFileEx(
            handle(file),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("the file is in use by another process");
    }
    Ok(())
}

/// Owns memory allocated by a Win32 LocalAlloc-based API.
struct LocalAllocation(*mut c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: this object exclusively owns the allocation returned by a
        // documented LocalFree-compatible Win32 API.
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn owner_only_descriptor() -> Result<LocalAllocation> {
    let mut token = null_mut();
    // SAFETY: GetCurrentProcess returns a borrowed pseudo-handle; token receives
    // a newly owned token handle on success.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error())
            .context("cannot identify the current Windows user");
    }
    // SAFETY: OpenProcessToken returned a new owned handle.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut required = 0u32;
    // SAFETY: the zero-sized null query requests only the required buffer size.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            null_mut(),
            0,
            &mut required,
        );
    }
    ensure!(
        required as usize >= size_of::<TOKEN_USER>(),
        "cannot determine the current user's security identifier"
    );
    let mut buffer = vec![0usize; (required as usize).div_ceil(size_of::<usize>())];
    // SAFETY: usize storage has TOKEN_USER's required alignment and at least the
    // size requested by GetTokenInformation; token remains open.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("cannot read the current user's security identifier");
    }
    // SAFETY: a successful TokenUser query initialized TOKEN_USER in this buffer;
    // its SID points into the same live allocation.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut sid_text = null_mut();
    // SAFETY: user.User.Sid is the valid SID returned by GetTokenInformation.
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid_text) } == 0 {
        return Err(std::io::Error::last_os_error())
            .context("cannot format the current user's security identifier");
    }
    let _sid_allocation = LocalAllocation(sid_text.cast());
    // SAFETY: ConvertSidToStringSidW returns a valid NUL-terminated UTF-16 SID
    // string allocated by Windows and kept alive by _sid_allocation.
    let sid = unsafe {
        let mut length = 0usize;
        while *sid_text.add(length) != 0 {
            length += 1;
        }
        String::from_utf16(std::slice::from_raw_parts(sid_text, length))
            .context("Windows returned an invalid security identifier string")?
    };
    let sddl: Vec<u16> = format!("O:{sid}D:P(A;;FA;;;{sid})\0")
        .encode_utf16()
        .collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: sddl is NUL-terminated and descriptor is a valid output pointer.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("cannot create a private file security descriptor");
    }
    Ok(LocalAllocation(descriptor))
}

fn reject_alternate_streams(file: &File) -> Result<()> {
    // NTFS stream names are bounded. A 64 KiB aligned buffer comfortably holds
    // the default stream; an oversized result necessarily has extra streams and
    // is rejected without allowing an attacker-controlled allocation.
    let mut buffer = vec![0usize; 65_536 / size_of::<usize>()];
    let capacity = buffer.len() * size_of::<usize>();
    // SAFETY: buffer is properly aligned writable storage of the supplied size.
    if unsafe {
        GetFileInformationByHandleEx(
            handle(file),
            FileStreamInfo,
            buffer.as_mut_ptr().cast(),
            capacity as u32,
        )
    } == 0
    {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(ERROR_HANDLE_EOF as i32) {
            return Ok(());
        }
        if err.raw_os_error() == Some(ERROR_MORE_DATA as i32) {
            bail!("the file has alternate data streams; process an ordinary file without streams");
        }
        return Err(err).context("cannot verify that the file has no alternate data streams");
    }
    let mut offset = 0usize;
    loop {
        ensure!(
            offset
                .checked_add(size_of::<FILE_STREAM_INFO>())
                .is_some_and(|end| end <= capacity),
            "invalid stream information returned by Windows"
        );
        // SAFETY: checked bounds include the structure. read_unaligned avoids
        // relying on alignment of offsets supplied by the filesystem.
        let info = unsafe {
            std::ptr::read_unaligned(
                buffer
                    .as_ptr()
                    .cast::<u8>()
                    .add(offset)
                    .cast::<FILE_STREAM_INFO>(),
            )
        };
        let name_start = offset + offset_of!(FILE_STREAM_INFO, StreamName);
        let name_len = info.StreamNameLength as usize;
        ensure!(
            name_len.is_multiple_of(2)
                && name_start
                    .checked_add(name_len)
                    .is_some_and(|end| end <= capacity),
            "invalid stream name returned by Windows"
        );
        let mut name = Vec::with_capacity(name_len / 2);
        for n in 0..name_len / 2 {
            // SAFETY: each UTF-16 unit is within the checked stream-name range.
            name.push(unsafe {
                std::ptr::read_unaligned(
                    buffer
                        .as_ptr()
                        .cast::<u8>()
                        .add(name_start + n * 2)
                        .cast::<u16>(),
                )
            });
        }
        ensure!(
            OsString::from_wide(&name) == OsStr::new("::$DATA"),
            "files with alternate data streams are not supported; export the streams first"
        );
        if info.NextEntryOffset == 0 {
            break;
        }
        let step = info.NextEntryOffset as usize;
        ensure!(
            step >= size_of::<FILE_STREAM_INFO>() && step <= capacity - offset,
            "invalid stream offset returned by Windows"
        );
        offset += step;
    }
    Ok(())
}

fn inspect_name(path: &Path) -> Result<Snapshot> {
    // Metadata-only access does not conflict with the staging writer. Sharing
    // allows the existing handles while our original/source checks remain open.
    let named = open_file(
        path,
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_FLAG_SEQUENTIAL_SCAN,
    )?;
    Snapshot::read(&named)
}

fn revalidate(path: &Path, source: &File, expected: &Snapshot) -> Result<()> {
    ensure!(
        Snapshot::read(source)? == *expected,
        "the source changed during processing; replacement cancelled"
    );
    ensure!(
        inspect_name(path)? == *expected,
        "the source name or contents changed during processing; replacement cancelled"
    );
    reject_alternate_streams(source)?;
    Ok(())
}

struct Staging {
    file: File,
    path: PathBuf,
    identity: Snapshot,
    published: bool,
}

impl Staging {
    fn new(dir: &Path) -> Result<Self> {
        let security = owner_only_descriptor()?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: security.0,
            bInheritHandle: 0,
        };
        for _ in 0..32 {
            let path = dir.join(temporary_name()?);
            let wide = wide_path(&path)?;
            // SAFETY: attributes and its security descriptor outlive CreateFile;
            // CREATE_NEW never opens or truncates an existing file. The DACL is
            // installed atomically with creation, before plaintext is written.
            let raw = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE | DELETE,
                    FILE_SHARE_READ | FILE_SHARE_DELETE,
                    &attributes,
                    CREATE_NEW,
                    FILE_ATTRIBUTE_NORMAL
                        | FILE_FLAG_OPEN_REPARSE_POINT
                        | FILE_FLAG_SEQUENTIAL_SCAN,
                    null_mut(),
                )
            };
            if raw == INVALID_HANDLE_VALUE {
                let err = std::io::Error::last_os_error();
                if matches!(err.raw_os_error(), Some(code) if code == ERROR_FILE_EXISTS as i32 || code == ERROR_ALREADY_EXISTS as i32)
                {
                    continue;
                }
                return Err(err).context("cannot create a private replacement beside the source");
            }
            // SAFETY: successful CreateFileW returned a new owned file handle.
            let file = unsafe { File::from_raw_handle(raw) };
            let identity = match Snapshot::read(&file) {
                Ok(identity) => identity,
                Err(err) => {
                    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
                    // SAFETY: the matching structure marks this newly created,
                    // empty file for removal when its owned handle closes.
                    unsafe {
                        SetFileInformationByHandle(
                            handle(&file),
                            FileDispositionInfo,
                            (&disposition as *const FILE_DISPOSITION_INFO).cast(),
                            size_of::<FILE_DISPOSITION_INFO>() as u32,
                        );
                    }
                    return Err(err);
                }
            };
            return Ok(Self {
                file,
                path,
                identity,
                published: false,
            });
        }
        bail!("could not allocate an unused random staging filename")
    }

    fn revalidate(&self) -> Result<()> {
        let current = Snapshot::read(&self.file)?;
        ensure!(
            self.identity.same_identity(&current),
            "the replacement file identity changed"
        );
        ensure!(
            inspect_name(&self.path)? == current,
            "the private replacement name or contents changed"
        );
        Ok(())
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        // SAFETY: a valid structure is passed to its matching information class.
        // Mark our own handle for deletion; never delete a pathname that another
        // process could have replaced. Dropping File then closes this handle.
        unsafe {
            SetFileInformationByHandle(
                handle(&self.file),
                FileDispositionInfo,
                (&disposition as *const FILE_DISPOSITION_INFO).cast(),
                size_of::<FILE_DISPOSITION_INFO>() as u32,
            );
        }
    }
}

fn replace_by_handle(staging: &File, destination_path: &Path) -> Result<()> {
    // SetFileInformationByHandle converts FileName into an absolute NT path
    // before calling NtSetInformationFile. A non-null RootDirectory survives
    // that conversion and can produce ERROR_INVALID_PARAMETER (87). Supply an
    // absolute Win32 path and null root, retaining the parent handle separately.
    let name = wide_path(destination_path)?;
    // wide_path includes the NUL terminator; FileNameLength excludes it and is
    // measured in UTF-16 bytes, including both halves of any surrogate pair.
    let bytes = (name.len() - 1)
        .checked_mul(size_of::<u16>())
        .context("filename is too long")?;
    // Match the variable-length FILE_RENAME_INFO layout used by Rust 1.99's
    // Windows filesystem implementation: header offset + name + terminator.
    let required = offset_of!(FILE_RENAME_INFO, FileName)
        .checked_add(bytes)
        .and_then(|size| size.checked_add(size_of::<u16>()))
        .context("filename is too long")?;
    let mut storage = vec![0usize; required.div_ceil(size_of::<usize>())];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: usize allocation meets the structure's alignment; it holds the
    // header and the whole variable-length UTF-16 name, followed by a zero.
    unsafe {
        (*info).Anonymous.Flags =
            FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS;
        (*info).RootDirectory = null_mut();
        (*info).FileNameLength = u32::try_from(bytes).context("filename is too long")?;
        let destination = (info as *mut u8)
            .add(offset_of!(FILE_RENAME_INFO, FileName))
            .cast::<u16>();
        std::ptr::copy_nonoverlapping(name.as_ptr(), destination, name.len());
    }
    // SAFETY: the initialized variable-length FILE_RENAME_INFO and all handles
    // remain valid until the synchronous operation returns.
    if unsafe {
        SetFileInformationByHandle(
            handle(staging),
            FileRenameInfoEx,
            info.cast(),
            u32::try_from(required).context("filename is too long")?,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("atomic NTFS rename failed; original retained (Windows 10/11 with FileRenameInfoEx support is required)");
    }
    Ok(())
}

pub struct Transaction {
    // Keep the validated parent open without delete sharing through commit.
    // The Win32 rename receives its absolute pathname, not this handle.
    _directory: File,
    source_path: PathBuf,
    source: File,
    original: Snapshot,
    staging: Staging,
}

impl Transaction {
    pub fn open(dir: &Path, name: &OsStr) -> Result<Self> {
        validate_basename(name)?;
        let opened_dir = directory(dir)?;
        let source_path = dir.join(name);
        // Deny write sharing throughout processing, while retaining delete
        // sharing so the final POSIX-style rename can replace this open file.
        let source = open_file(
            &source_path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            FILE_FLAG_SEQUENTIAL_SCAN,
        )?;
        lock_exclusive(&source)?;
        let original = Snapshot::read(&source)?;
        let executable = std::env::current_exe().context("cannot identify this executable")?;
        let executable_info =
            inspect_name(&executable).context("cannot inspect this executable")?;
        ensure!(
            !original.same_identity(&executable_info),
            "the running executable cannot be encrypted or decrypted"
        );
        revalidate(&source_path, &source, &original)?;
        let staging = Staging::new(dir)?;
        Ok(Self {
            _directory: opened_dir,
            source_path,
            source,
            original,
            staging,
        })
    }

    pub fn source_len(&self) -> u64 {
        self.original.length
    }
    pub fn source_mut(&mut self) -> &mut File {
        &mut self.source
    }
    #[cfg(test)]
    pub fn output_mut(&mut self) -> &mut File {
        &mut self.staging.file
    }
    pub fn streams(&mut self) -> (&mut File, &mut File) {
        (&mut self.source, &mut self.staging.file)
    }

    pub fn commit(mut self) -> Result<CommitOutcome> {
        self.staging
            .file
            .flush()
            .context("cannot finish writing the replacement")?;
        self.staging
            .file
            .sync_all()
            .context("cannot synchronize the replacement; original retained")?;
        self.staging.revalidate()?;
        revalidate(&self.source_path, &self.source, &self.original)?;
        replace_by_handle(&self.staging.file, &self.source_path)?;
        self.staging.published = true;
        // The rename has committed. A later flush error is a warning, never a
        // reason to delete the replacement or claim the original is untouched.
        // Windows has no portable equivalent of fsync(parent-directory); even
        // with both file flushes, power-loss guarantees are filesystem-specific.
        let durability_warning = self.staging.file.sync_all().err().map(|err| {
            format!("replacement completed, but its final synchronization failed ({err}); persistence after power loss is uncertain")
        });
        Ok(CommitOutcome { durability_warning })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Read;

    #[test]
    fn native_transaction_replaces_and_keeps_old_handle_valid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data");
        fs::write(&path, b"original").unwrap();
        let mut old = open_file(
            &path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            0,
        )
        .unwrap();
        let mut transaction = Transaction::open(dir.path(), OsStr::new("data")).unwrap();
        transaction.output_mut().write_all(b"replacement").unwrap();
        transaction.commit().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"replacement");
        let mut bytes = Vec::new();
        old.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"original");
    }

    #[test]
    fn native_commit_uses_absolute_unicode_destination_outside_working_directory() {
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("destination résumé 🔒");
        fs::create_dir(&destination).unwrap();
        // canonicalize returns the extended-length Windows path. The original
        // replacement test also exercises a normal temporary-directory path.
        let destination = fs::canonicalize(destination).unwrap();
        let caller = fs::canonicalize(std::env::current_dir().unwrap()).unwrap();
        assert!(destination.is_absolute());
        assert_ne!(destination, caller);
        let name = OsStr::new("résumé 🔒.bin");
        let path = destination.join(name);
        fs::write(&path, b"original").unwrap();

        let mut transaction = Transaction::open(&destination, name).unwrap();
        transaction.output_mut().write_all(b"replacement").unwrap();
        transaction.commit().unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"replacement");
        assert_eq!(fs::read_dir(&destination).unwrap().count(), 1);
    }

    #[test]
    fn abort_preserves_source_and_cleans_staging() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data");
        fs::write(&path, b"original").unwrap();
        let mut transaction = Transaction::open(dir.path(), OsStr::new("data")).unwrap();
        transaction.output_mut().write_all(b"unfinished").unwrap();
        drop(transaction);
        assert_eq!(fs::read(path).unwrap(), b"original");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn rejects_extra_streams_hardlinks_and_simultaneous_operations() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data");
        fs::write(&path, b"original").unwrap();
        fs::write(dir.path().join("data:secret"), b"alternate").unwrap();
        assert!(Transaction::open(dir.path(), OsStr::new("data")).is_err());
        fs::remove_file(dir.path().join("data:secret")).unwrap();
        fs::hard_link(&path, dir.path().join("linked")).unwrap();
        assert!(Transaction::open(dir.path(), OsStr::new("data")).is_err());
        fs::remove_file(dir.path().join("linked")).unwrap();
        let _held = Transaction::open(dir.path(), OsStr::new("data")).unwrap();
        assert!(Transaction::open(dir.path(), OsStr::new("data")).is_err());
        assert!(std::fs::OpenOptions::new().write(true).open(&path).is_err());
    }
}
