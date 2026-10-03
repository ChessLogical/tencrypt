use super::{CommitOutcome, temporary_name, validate_basename};
use anyhow::{Context, Result, bail, ensure};
use std::ffi::{CString, OsStr};
use std::fs::{File, Metadata, OpenOptions};
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Snapshot {
    device: u64,
    inode: u64,
    length: u64,
    mode: u32,
    owner: u32,
    group: u32,
    links: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl Snapshot {
    fn read(file: &File) -> Result<Self> {
        let meta = file.metadata().context("cannot inspect the open file")?;
        ensure!(meta.is_file(), "only regular files are supported");
        ensure!(
            meta.nlink() == 1,
            "files with more than one hard link are not supported"
        );
        Ok(Self::from_metadata(&meta))
    }

    fn from_metadata(meta: &Metadata) -> Self {
        Self {
            device: meta.dev(),
            inode: meta.ino(),
            length: meta.len(),
            mode: meta.mode(),
            owner: meta.uid(),
            group: meta.gid(),
            links: meta.nlink(),
            modified: (meta.mtime(), meta.mtime_nsec()),
            changed: (meta.ctime(), meta.ctime_nsec()),
        }
    }

    fn same_identity(&self, other: &Self) -> bool {
        self.device == other.device && self.inode == other.inode
    }
}

fn directory(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("cannot open the executable directory: {}", path.display()))?;
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: fstatfs receives a live descriptor and enough aligned writable
    // memory for its result. It initializes the structure on success.
    if unsafe { libc::fstatfs(file.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("cannot inspect the local filesystem");
    }
    // SAFETY: the successful fstatfs call initialized this structure.
    let kind = unsafe { filesystem.assume_init() }.f_type as u64;
    // Fail closed for NFS/SMB/FUSE and unrecognized filesystems: network rename
    // can succeed at the server yet report an error after reconnection. OverlayFS
    // is supported only with local backing; the mount's type cannot establish
    // that property. Memory-backed tmpfs/ramfs naturally have no reboot durability.
    ensure!(
        matches!(
            kind,
            0x0000_ef53 // ext2/ext3/ext4
        | 0x5846_5342 // XFS
        | 0x9123_683e // Btrfs
        | 0xf2f5_2010 // F2FS
        | 0x0102_1994 // tmpfs
        | 0x8584_58f6 // ramfs
        | 0x794c_7630 // OverlayFS, with local backing
        ),
        "unsupported filesystem (type 0x{kind:x}); use local ext2/3/4, XFS, Btrfs, F2FS, tmpfs/ramfs, or OverlayFS with local backing"
    );
    Ok(file)
}

fn c_name(name: &OsStr) -> Result<CString> {
    validate_basename(name)?;
    CString::new(name.as_bytes()).context("the filename contains a NUL byte")
}

fn open_at(dir: &File, name: &CString, flags: i32, mode: libc::mode_t) -> Result<File> {
    // SAFETY: the descriptor and NUL-terminated name remain valid for this call.
    // O_NOFOLLOW rejects a symlink in the last component, and O_NONBLOCK keeps
    // opening an unexpected FIFO from hanging before the regular-file check.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            mode,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("cannot open the requested file");
    }
    // SAFETY: openat returned a new descriptor now owned solely by File.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn lock(file: &File, exclusive: bool) -> Result<()> {
    let operation = if exclusive {
        libc::LOCK_EX
    } else {
        libc::LOCK_SH
    } | libc::LOCK_NB;
    // SAFETY: this descriptor is a live File. The advisory lock is released when
    // it is closed, including on every error and normal process termination.
    if unsafe { libc::flock(file.as_raw_fd(), operation) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("the file is busy or its filesystem does not support file locking");
    }
    Ok(())
}

fn revalidate(dir: &File, name: &CString, source: &File, expected: &Snapshot) -> Result<()> {
    ensure!(
        Snapshot::read(source)? == *expected,
        "the source changed during processing; replacement cancelled"
    );
    let named = open_at(dir, name, libc::O_RDONLY, 0)
        .context("the source name disappeared or was replaced during processing")?;
    ensure!(
        Snapshot::read(&named)? == *expected,
        "the source name or contents changed during processing; replacement cancelled"
    );
    Ok(())
}

/// An owned private staging name in the opened parent directory.
struct Staging {
    dir: File,
    name: CString,
    file: File,
    identity: Snapshot,
    published: bool,
}

impl Staging {
    fn new(dir: &File) -> Result<Self> {
        // Obtain the cleanup descriptor before creating anything, so an fd-limit
        // error cannot strand a newly created staging name.
        let owned_dir = dir
            .try_clone()
            .context("cannot retain the staging directory")?;
        for _ in 0..32 {
            let name = CString::new(temporary_name()?).expect("generated ASCII filename");
            let file = match open_at(
                dir,
                &name,
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                0o600,
            ) {
                Ok(file) => file,
                Err(err)
                    if err
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::AlreadyExists) =>
                {
                    continue;
                }
                Err(err) => {
                    return Err(err)
                        .context("cannot create a private replacement beside the source");
                }
            };
            // SAFETY: this new file is owned by this process's user. Establish
            // exact owner read/write permissions even under a restrictive umask,
            // before writing any data. Group/other access remains absent.
            if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
                let err = std::io::Error::last_os_error();
                // SAFETY: this is the newly created, still-empty staging name.
                unsafe {
                    libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0);
                }
                return Err(err).context("cannot set private replacement permissions");
            }
            // Capture ownership immediately so subsequent errors clean up.
            let identity = match Snapshot::read(&file) {
                Ok(identity) => identity,
                Err(err) => {
                    // SAFETY: this just-created exclusive name is still empty;
                    // remove it before returning the initial inspection error.
                    unsafe {
                        libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0);
                    }
                    return Err(err);
                }
            };
            return Ok(Self {
                dir: owned_dir,
                name,
                file,
                identity,
                published: false,
            });
        }
        bail!("could not allocate an unused random staging filename")
    }

    fn verify_private(&self) -> Result<()> {
        let current = Snapshot::read(&self.file)?;
        ensure!(
            self.identity.same_identity(&current),
            "the replacement file identity changed"
        );
        ensure!(
            current.mode & 0o7777 == 0o600,
            "the private replacement permissions changed"
        );
        let named = open_at(&self.dir, &self.name, libc::O_RDONLY, 0)?;
        ensure!(
            current == Snapshot::read(&named)?,
            "the replacement name or contents changed"
        );
        Ok(())
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        // Remove only our inode. A same-user attacker is out of scope, but this
        // extra check avoids deleting an unrelated name after an accidental move.
        let owns_name = open_at(&self.dir, &self.name, libc::O_RDONLY, 0)
            .and_then(|file| Snapshot::read(&file))
            .is_ok_and(|current| self.identity.same_identity(&current));
        if owns_name {
            // SAFETY: both dirfd and this basename remain valid for the call.
            unsafe {
                libc::unlinkat(self.dir.as_raw_fd(), self.name.as_ptr(), 0);
            }
        }
    }
}

pub struct Transaction {
    dir: File,
    name: CString,
    source: File,
    original: Snapshot,
    staging: Staging,
}

impl Transaction {
    pub fn open(dir: &Path, name: &OsStr) -> Result<Self> {
        let name = c_name(name)?;
        let dir = directory(dir)?;
        let source = open_at(&dir, &name, libc::O_RDONLY, 0)?;
        lock(&source, true)?;
        let original = Snapshot::read(&source)?;
        let executable = std::env::current_exe().context("cannot identify this executable")?;
        let executable_meta =
            std::fs::metadata(&executable).context("cannot inspect this executable")?;
        ensure!(
            original.device != executable_meta.dev() || original.inode != executable_meta.ino(),
            "the running executable cannot be encrypted or decrypted"
        );
        revalidate(&dir, &name, &source, &original)?;
        let staging = Staging::new(&dir)?;
        Ok(Self {
            dir,
            name,
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
        self.staging.verify_private()?;
        revalidate(&self.dir, &self.name, &self.source, &self.original)?;
        // SAFETY: both names are validated single components within live dirfds.
        // A same-directory rename atomically exchanges the visible name; the
        // source stays open and locked until this method returns.
        if unsafe {
            libc::renameat(
                self.dir.as_raw_fd(),
                self.staging.name.as_ptr(),
                self.dir.as_raw_fd(),
                self.name.as_ptr(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error())
                .context("atomic replacement failed; original retained");
        }
        self.staging.published = true;
        let durability_warning = self.dir.sync_all().err().map(|err| {
            format!("replacement completed, but synchronizing the directory failed ({err}); persistence after power loss is uncertain")
        });
        Ok(CommitOutcome { durability_warning })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Read;
    use std::os::unix::fs::{PermissionsExt, symlink};

    struct TestDir(std::path::PathBuf);
    impl TestDir {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(temporary_name().unwrap());
            fs::create_dir(&dir).unwrap();
            Self(dir)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn abort_keeps_original_and_removes_private_staging() {
        let dir = TestDir::new();
        fs::write(dir.path().join("data"), b"original").unwrap();
        let mut tx = Transaction::open(dir.path(), OsStr::new("data")).unwrap();
        tx.output_mut().write_all(b"unfinished plaintext").unwrap();
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
        drop(tx);
        assert_eq!(fs::read(dir.path().join("data")).unwrap(), b"original");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn commit_replaces_atomically_with_private_permissions() {
        let dir = TestDir::new();
        let path = dir.path().join("data");
        fs::write(&path, b"original").unwrap();
        let held_original = File::open(&path).unwrap();
        let mut tx = Transaction::open(dir.path(), OsStr::new("data")).unwrap();
        tx.output_mut().write_all(b"replacement").unwrap();
        tx.commit().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"replacement");
        let mut original_bytes = Vec::new();
        (&held_original).read_to_end(&mut original_bytes).unwrap();
        assert_eq!(original_bytes, b"original");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn modified_or_renamed_source_is_not_overwritten() {
        let dir = TestDir::new();
        let path = dir.path().join("data");
        fs::write(&path, b"original").unwrap();
        let mut tx = Transaction::open(dir.path(), OsStr::new("data")).unwrap();
        tx.output_mut().write_all(b"replacement").unwrap();
        fs::write(&path, b"concurrent edit").unwrap();
        assert!(tx.commit().is_err());
        assert_eq!(fs::read(&path).unwrap(), b"concurrent edit");
        let mut tx = Transaction::open(dir.path(), OsStr::new("data")).unwrap();
        tx.output_mut().write_all(b"replacement").unwrap();
        fs::rename(&path, dir.path().join("moved")).unwrap();
        fs::write(&path, b"another file").unwrap();
        assert!(tx.commit().is_err());
        assert_eq!(fs::read(&path).unwrap(), b"another file");
    }

    #[test]
    fn rejects_symlinks_hardlinks_and_concurrent_transactions() {
        let dir = TestDir::new();
        let path = dir.path().join("data");
        fs::write(&path, b"original").unwrap();
        symlink("data", dir.path().join("link")).unwrap();
        assert!(Transaction::open(dir.path(), OsStr::new("link")).is_err());
        fs::hard_link(&path, dir.path().join("hardlink")).unwrap();
        assert!(Transaction::open(dir.path(), OsStr::new("data")).is_err());
        fs::remove_file(dir.path().join("hardlink")).unwrap();
        let _held = Transaction::open(dir.path(), OsStr::new("data")).unwrap();
        assert!(Transaction::open(dir.path(), OsStr::new("data")).is_err());
    }
}
