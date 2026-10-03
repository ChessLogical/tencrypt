//! Exercise the released CLI contract through a copied executable. In particular,
//! the executable directory, rather than the caller's working directory, owns
//! the files. Each test uses an isolated directory without runtime key files.

#![cfg(any(
    all(target_os = "linux", feature = "linux-bin"),
    all(target_os = "windows", feature = "windows-bin")
))]

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;

use tempfile::TempDir;

#[cfg(target_os = "linux")]
const BUILT_EXECUTABLE: &str = env!("CARGO_BIN_EXE_tencrypt-linux");
#[cfg(target_os = "windows")]
const BUILT_EXECUTABLE: &str = env!("CARGO_BIN_EXE_tencrypt-windows");

#[cfg(target_os = "linux")]
const EXECUTABLE_NAME: &str = "tencrypt-linux";
#[cfg(target_os = "windows")]
const EXECUTABLE_NAME: &str = "tencrypt-windows.exe";

const CHUNK_SIZE: usize = 1024 * 1024;
const HEADER_SIZE: usize = 64;

// Coordinate executable copying with process creation. On Linux, a concurrent
// fork can briefly inherit another test's writable executable-copy descriptor,
// making execve fail with ETXTBSY before the CLI ever starts. Hold this guard
// through spawn (which reports exec success), then allow children to run in
// parallel. This changes test setup only, not the program's locking behavior.
static EXECUTABLE_SETUP: Mutex<()> = Mutex::new(());

struct Fixture {
    root: TempDir,
    directory: PathBuf,
    executable: PathBuf,
    caller_directory: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("tencrypt CLI tests ")
            .tempdir()
            .expect("create isolated test directory");
        let directory = root.path().join("program directory");
        let caller_directory = root.path().join("unrelated caller directory");
        fs::create_dir(&directory).expect("create executable directory");
        fs::create_dir(&caller_directory).expect("create caller directory");
        let executable = directory.join(EXECUTABLE_NAME);
        {
            let _guard = EXECUTABLE_SETUP.lock().unwrap();
            fs::copy(BUILT_EXECUTABLE, &executable).expect("copy CLI executable");
        }
        Self {
            root,
            directory,
            executable,
            caller_directory,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.join(name)
    }

    fn entries(&self) -> Vec<OsString> {
        let mut entries: Vec<_> = fs::read_dir(&self.directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        entries.sort();
        entries
    }

    fn run(&self, arguments: &[&str]) -> Output {
        let child = {
            let _guard = EXECUTABLE_SETUP.lock().unwrap();
            Command::new(&self.executable)
                .args(arguments)
                .current_dir(&self.caller_directory)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap_or_else(|error| panic!("cannot run CLI with {arguments:?}: {error}"))
        };
        child.wait_with_output().expect("collect CLI output")
    }

    fn expects_code(&self, arguments: &[&str], code: i32) -> Output {
        let output = self.run(arguments);
        assert_eq!(
            output.status.code(),
            Some(code),
            "arguments: {arguments:?}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn succeeds(&self, arguments: &[&str]) -> Output {
        self.expects_code(arguments, 0)
    }

    fn operation_fails_unchanged(&self, arguments: &[&str], path: &Path) {
        let original = fs::read(path).expect("read source before rejected operation");
        let entries = self.entries();
        self.expects_code(arguments, 1);
        assert_eq!(
            fs::read(path).expect("source must still exist after rejected operation"),
            original,
            "a failed operation changed the source: {arguments:?}"
        );
        assert_eq!(
            self.entries(),
            entries,
            "failed operation left a staging file"
        );
    }

    fn rejected_unchanged(&self, arguments: &[&str], path: &Path) {
        let original = fs::read(path).expect("read source before rejected operation");
        let entries = self.entries();
        let output = self.run(arguments);
        assert!(
            !output.status.success(),
            "unsafe input was accepted: {arguments:?}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read(path).expect("source must still exist after rejected operation"),
            original,
            "a rejected operation changed the source: {arguments:?}"
        );
        assert_eq!(
            self.entries(),
            entries,
            "rejected operation left a staging file"
        );
    }
}

fn sample_bytes(length: usize) -> Vec<u8> {
    // Deterministic binary input with differing contents across chunk boundaries.
    let mut state = 0x8a2d_53e7_u32;
    (0..length)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

fn tag_length(algorithm: u8) -> usize {
    if matches!(algorithm, 3 | 4 | 8 | 9) {
        32
    } else {
        16
    }
}

fn assert_container(ciphertext: &[u8], algorithm: u8, plaintext_length: usize) {
    assert!(ciphertext.len() >= HEADER_SIZE);
    assert_eq!(&ciphertext[..8], b"TENCRYPT");
    assert_eq!(ciphertext[8], 1, "format version");
    assert_eq!(ciphertext[9], algorithm, "stored algorithm");
    assert_eq!(&ciphertext[10..12], &[0; 2], "flags");
    assert_eq!(
        u32::from_le_bytes(ciphertext[12..16].try_into().unwrap()) as usize,
        CHUNK_SIZE,
        "record size"
    );
    assert_eq!(
        u64::from_le_bytes(ciphertext[16..24].try_into().unwrap()),
        plaintext_length as u64,
        "stored plaintext length"
    );
    assert_eq!(&ciphertext[56..64], &[0; 8], "reserved header bytes");
    let records = plaintext_length.div_ceil(CHUNK_SIZE).max(1);
    assert_eq!(
        ciphertext.len(),
        HEADER_SIZE + plaintext_length + records * tag_length(algorithm),
        "every record, including an empty file, must have an authentication tag"
    );
}

#[test]
fn information_commands_work_and_syntax_has_distinct_exit_status() {
    let fixture = Fixture::new();
    let help = fixture.succeeds(&["--help"]);
    assert!(!help.stdout.is_empty());
    let version = fixture.succeeds(&["--version"]);
    assert!(String::from_utf8_lossy(&version.stdout).contains(env!("CARGO_PKG_VERSION")));
    let listing = fixture.succeeds(&["--list"]);
    let listing = String::from_utf8_lossy(&listing.stdout).to_lowercase();
    for name in ["xchacha20", "serpent", "threefish", "1024", "eax"] {
        assert!(listing.contains(name), "algorithm listing omits {name}");
    }

    for arguments in [
        &[][..],
        &["--unknown"][..],
        &["--init-keys"][..],
        &["0", "E", "file.bin"][..],
        &["11", "E", "file.bin"][..],
        &["-1", "E", "file.bin"][..],
        &["one", "E", "file.bin"][..],
        &["1", "X", "file.bin"][..],
        &["1", "E"][..],
        &["1", "E", "file.bin", "extra"][..],
    ] {
        fixture.expects_code(arguments, 2);
    }
    assert_eq!(fs::read_dir(&fixture.directory).unwrap().count(), 1);
    assert_eq!(fs::read_dir(&fixture.caller_directory).unwrap().count(), 0);
}

#[test]
fn another_copy_of_the_binary_decrypts_without_runtime_key_files() {
    let first = Fixture::new();
    let second = Fixture::new();
    let name = "portable ciphertext.bin";
    let plaintext = sample_bytes(8193);
    fs::write(first.path(name), &plaintext).unwrap();
    first.succeeds(&["4", "E", name]);
    fs::copy(first.path(name), second.path(name)).unwrap();
    second.succeeds(&["4", "D", name]);
    assert_eq!(fs::read(second.path(name)).unwrap(), plaintext);

    for fixture in [&first, &second] {
        assert_eq!(
            fs::read_dir(&fixture.directory).unwrap().count(),
            2,
            "only the executable and processed file should be required"
        );
        assert_eq!(fs::read_dir(&fixture.caller_directory).unwrap().count(), 0);
    }
}

#[test]
fn all_ten_suites_round_trip_empty_and_binary_files() {
    let fixture = Fixture::new();
    for algorithm in 1..=10_u8 {
        let selection = algorithm.to_string();
        let name = format!("suite {algorithm} binary 雪.bin");
        let path = fixture.path(&name);

        for length in [0, 1025] {
            let plaintext = sample_bytes(length);
            fs::write(&path, &plaintext).unwrap();
            fixture.succeeds(&[&selection, "E", &name]);
            let ciphertext = fs::read(&path).unwrap();
            assert_container(&ciphertext, algorithm, length);
            assert_ne!(ciphertext, plaintext);

            if length == 0 {
                let mut bad_tag = ciphertext.clone();
                *bad_tag.last_mut().unwrap() ^= 1;
                fs::write(&path, bad_tag).unwrap();
                fixture.operation_fails_unchanged(&[&selection, "D", &name], &path);
                fs::write(&path, ciphertext).unwrap();
            }

            fixture.succeeds(&[&selection, "D", &name]);
            assert_eq!(fs::read(&path).unwrap(), plaintext, "suite {algorithm}");
        }
    }
}

#[test]
fn uses_executable_directory_and_randomizes_repeated_encryptions() {
    let fixture = Fixture::new();
    let name = "a file with spaces.bin";
    let path = fixture.path(name);
    let caller_path = fixture.caller_directory.join(name);
    let plaintext = sample_bytes(8096);
    fs::write(&path, &plaintext).unwrap();
    fs::write(&caller_path, b"unrelated same-named file").unwrap();

    fixture.succeeds(&["1", "E", name]);
    let first = fs::read(&path).unwrap();
    fixture.succeeds(&["1", "D", name]);
    assert_eq!(fs::read(&path).unwrap(), plaintext);
    fixture.succeeds(&["1", "E", name]);
    let second = fs::read(&path).unwrap();
    assert_ne!(first, second, "fresh encryption must use fresh randomness");
    assert_ne!(&first[24..56], &second[24..56], "fresh per-file salt");
    fixture.succeeds(&["1", "D", name]);
    assert_eq!(fs::read(&path).unwrap(), plaintext);
    assert_eq!(fs::read(caller_path).unwrap(), b"unrelated same-named file");

    let only_in_caller = fixture.caller_directory.join("only-in-caller.bin");
    fs::write(&only_in_caller, b"must stay here").unwrap();
    fixture.operation_fails_unchanged(&["1", "E", "only-in-caller.bin"], &only_in_caller);
}

#[test]
fn corrupt_truncated_appended_and_wrong_suite_inputs_remain_unchanged() {
    let fixture = Fixture::new();
    let name = "authenticated.bin";
    let path = fixture.path(name);
    let plaintext = sample_bytes(4097);
    fs::write(&path, &plaintext).unwrap();
    fixture.succeeds(&["1", "E", name]);
    let valid = fs::read(&path).unwrap();

    fixture.operation_fails_unchanged(&["2", "D", name], &path);
    fixture.operation_fails_unchanged(&["1", "E", name], &path);

    let mut mutations = Vec::new();
    for offset in [0, 8, 9, 10, 12, 16, 24, 56, HEADER_SIZE, valid.len() - 1] {
        let mut bytes = valid.clone();
        bytes[offset] ^= 1;
        mutations.push(bytes);
    }
    for length in [0, 7, HEADER_SIZE - 1, HEADER_SIZE, valid.len() - 1] {
        mutations.push(valid[..length].to_vec());
    }
    let mut appended = valid.clone();
    appended.extend_from_slice(b"unexpected trailing bytes");
    mutations.push(appended);

    for mutation in mutations {
        fs::write(&path, mutation).unwrap();
        fixture.operation_fails_unchanged(&["1", "D", name], &path);
    }
    fs::write(&path, valid).unwrap();
    fixture.succeeds(&["1", "D", name]);
    assert_eq!(fs::read(&path).unwrap(), plaintext);
}

#[test]
fn multiple_records_round_trip_and_record_swaps_are_rejected() {
    let fixture = Fixture::new();
    // Cover both AEAD records and the wider-block encrypt-then-MAC construction.
    for algorithm in [1_u8, 4] {
        let selection = algorithm.to_string();
        let name = format!("multi-record-{algorithm}.bin");
        let path = fixture.path(&name);
        let plaintext = sample_bytes(2 * CHUNK_SIZE + 37);
        fs::write(&path, &plaintext).unwrap();
        fixture.succeeds(&[&selection, "E", &name]);
        let valid = fs::read(&path).unwrap();
        assert_container(&valid, algorithm, plaintext.len());

        let record_length = CHUNK_SIZE + tag_length(algorithm);
        let mut swapped = valid.clone();
        swapped[HEADER_SIZE..HEADER_SIZE + record_length]
            .copy_from_slice(&valid[HEADER_SIZE + record_length..HEADER_SIZE + 2 * record_length]);
        swapped[HEADER_SIZE + record_length..HEADER_SIZE + 2 * record_length]
            .copy_from_slice(&valid[HEADER_SIZE..HEADER_SIZE + record_length]);
        fs::write(&path, swapped).unwrap();
        fixture.operation_fails_unchanged(&[&selection, "D", &name], &path);

        // A failure in the final record must not expose partially decrypted data
        // by replacing the source after authenticating just the earlier records.
        let mut damaged_last_record = valid.clone();
        *damaged_last_record.last_mut().unwrap() ^= 0x80;
        fs::write(&path, damaged_last_record).unwrap();
        fixture.operation_fails_unchanged(&[&selection, "D", &name], &path);

        fs::write(&path, valid).unwrap();
        fixture.succeeds(&[&selection, "D", &name]);
        assert_eq!(fs::read(&path).unwrap(), plaintext);
    }
}

#[test]
fn magic_prefixed_plaintext_and_unencrypted_decryption_input_remain_unchanged() {
    let fixture = Fixture::new();
    let name = "source.bin";
    let path = fixture.path(name);
    fs::write(
        &path,
        b"TENCRYPT is deliberately reserved as an input prefix",
    )
    .unwrap();
    fixture.operation_fails_unchanged(&["1", "E", name], &path);
    fs::write(&path, b"ordinary plaintext is not a valid ciphertext").unwrap();
    fixture.operation_fails_unchanged(&["1", "D", name], &path);
}

#[test]
fn paths_and_the_executable_cannot_be_encryption_targets() {
    let fixture = Fixture::new();
    let outside = fixture.root.path().join("outside.bin");
    fs::write(&outside, b"outside the executable directory").unwrap();
    fixture.rejected_unchanged(&["1", "E", "../outside.bin"], &outside);
    fixture.rejected_unchanged(&["1", "E", outside.to_str().unwrap()], &outside);

    let subdirectory = fixture.path("subdirectory");
    fs::create_dir(&subdirectory).unwrap();
    let nested = subdirectory.join("nested.bin");
    fs::write(
        &nested,
        b"nested files require moving beside the executable",
    )
    .unwrap();
    fixture.rejected_unchanged(&["1", "E", "subdirectory/nested.bin"], &nested);

    fixture.rejected_unchanged(&["1", "E", EXECUTABLE_NAME], &fixture.executable);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_rejects_symbolic_links_and_hard_links() {
    use std::os::unix::fs::{MetadataExt, symlink};

    let fixture = Fixture::new();
    let original = fixture.path("original.bin");
    let alias = fixture.path("alias.bin");
    fs::write(&original, b"linked data must stay unchanged").unwrap();
    symlink("original.bin", &alias).unwrap();
    fixture.rejected_unchanged(&["1", "E", "alias.bin"], &original);
    assert!(
        fs::symlink_metadata(&alias)
            .unwrap()
            .file_type()
            .is_symlink()
    );

    fs::remove_file(&alias).unwrap();
    fs::hard_link(&original, &alias).unwrap();
    fixture.rejected_unchanged(&["1", "E", "alias.bin"], &original);
    fixture.rejected_unchanged(&["1", "E", "original.bin"], &original);
    assert_eq!(fs::read(&alias).unwrap(), fs::read(&original).unwrap());
    assert_eq!(fs::metadata(&original).unwrap().nlink(), 2);
    assert_eq!(
        fs::metadata(&original).unwrap().ino(),
        fs::metadata(&alias).unwrap().ino()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_replaced_files_are_private_and_success_replaces_the_inode() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let fixture = Fixture::new();
    let name = "permissions.bin";
    let path = fixture.path(name);
    let plaintext = sample_bytes(511);
    fs::write(&path, &plaintext).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();
    let initial_inode = fs::metadata(&path).unwrap().ino();
    fixture.succeeds(&["1", "E", name]);
    let encrypted_metadata = fs::metadata(&path).unwrap();
    assert_eq!(encrypted_metadata.mode() & 0o777, 0o600);
    assert_ne!(encrypted_metadata.ino(), initial_inode);

    fixture.succeeds(&["1", "D", name]);
    let decrypted_metadata = fs::metadata(&path).unwrap();
    assert_eq!(decrypted_metadata.mode() & 0o777, 0o600);
    assert_ne!(decrypted_metadata.ino(), encrypted_metadata.ino());
    assert_eq!(fs::read(path).unwrap(), plaintext);
}

#[cfg(target_os = "windows")]
#[test]
fn windows_rejects_alternate_stream_and_backslash_paths() {
    let fixture = Fixture::new();
    let path = fixture.path("source.bin");
    fs::write(&path, b"ordinary data stream must stay unchanged").unwrap();
    fixture.rejected_unchanged(&["1", "E", "source.bin:hidden"], &path);

    let outside = fixture.root.path().join("outside.bin");
    fs::write(&outside, b"outside data must stay unchanged").unwrap();
    fixture.rejected_unchanged(&["1", "E", "..\\outside.bin"], &outside);
}
