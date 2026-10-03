//! Tencrypt: one authenticated, atomic file operation per invocation.

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
compile_error!("Tencrypt supports Linux and Windows only");

pub mod crypto;
mod embedded_keys;
mod format;
mod platform;

use std::ffi::{OsStr, OsString};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, Result, bail, ensure};
use crypto::Algorithm;

#[derive(Clone, Copy)]
enum Operation {
    Encrypt,
    Decrypt,
}

enum Command {
    Help,
    List,
    Version,
    Process {
        algorithm: Algorithm,
        operation: Operation,
        filename: OsString,
    },
}

fn parse_args(args: Vec<OsString>) -> Result<Command> {
    if args.len() == 1 {
        match args[0].to_str() {
            Some("--help" | "-h") => return Ok(Command::Help),
            Some("--list") => return Ok(Command::List),
            Some("--version" | "-V") => return Ok(Command::Version),
            _ => {}
        }
    }
    ensure!(
        args.len() == 3,
        "expected an algorithm number, E or D, and one filename"
    );
    let id = args[0]
        .to_str()
        .context("algorithm number must be valid text")?
        .parse::<u8>()
        .context("algorithm must be a number from 1 to 10")?;
    let algorithm = Algorithm::from_id(id)?;
    let operation = match args[1].to_str() {
        Some("E" | "e") => Operation::Encrypt,
        Some("D" | "d") => Operation::Decrypt,
        _ => bail!("operation must be E (encrypt) or D (decrypt)"),
    };
    platform::validate_basename(&args[2])?;
    Ok(Command::Process {
        algorithm,
        operation,
        filename: args[2].clone(),
    })
}

fn binary_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "tencrypt-windows.exe"
    } else {
        "tencrypt-linux"
    }
}

fn usage() {
    let binary = binary_name();
    println!(
        "Tencrypt {} — one file, one operation, then exit",
        env!("CARGO_PKG_VERSION")
    );
    println!("\nUsage: {binary} <1..10> <E|D> <filename>");
    println!("       {binary} --list | --help | --version");
    println!("\nExample: {binary} 1 E \"notes.txt\"");
    println!("         {binary} 1 D \"notes.txt\"");
    println!("\nPlace the file beside the executable. Use its filename without a directory.");
    println!("The complete result replaces that same filename atomically after verification.");
    println!("Each algorithm's key is embedded at compile time; no runtime key file is used.");
    println!("\nAlgorithms:");
    list_algorithms();
}

fn list_algorithms() {
    for algorithm in Algorithm::ALL {
        println!(
            "{:>2}  {:<40}  {}-byte embedded key",
            algorithm.id(),
            algorithm.name(),
            algorithm.key_len()
        );
    }
}

fn process(algorithm: Algorithm, operation: Operation, filename: &OsStr) -> Result<()> {
    let executable = std::env::current_exe()
        .context("could not locate the running executable")?
        .canonicalize()
        .context("could not resolve the running executable path")?;
    let directory = executable
        .parent()
        .context("executable has no parent directory")?;
    protect_executable(filename, &executable)?;

    let mut transaction = platform::Transaction::open(directory, filename)
        .with_context(|| format!("could not start a transaction for {filename:?}"))?;
    let input_len = transaction.source_len();
    if matches!(operation, Operation::Encrypt) && input_len >= format::MAGIC.len() as u64 {
        let mut prefix = [0; 8];
        transaction
            .source_mut()
            .read_exact(&mut prefix)
            .context("could not inspect the source file")?;
        ensure!(
            &prefix != format::MAGIC,
            "file already has a Tencrypt header; decrypt it before encrypting it again"
        );
        transaction
            .source_mut()
            .seek(SeekFrom::Start(0))
            .context("could not rewind the source file")?;
    }

    let (source, output) = transaction.streams();
    let key = embedded_keys::key(algorithm);
    let output_len = match operation {
        Operation::Encrypt => format::encrypt(algorithm, key, input_len, source, output)?,
        Operation::Decrypt => format::decrypt(algorithm, key, input_len, source, output)?,
    };
    let committed = transaction
        .commit()
        .context("could not commit the file replacement")?;
    let verb = match operation {
        Operation::Encrypt => "Encrypted",
        Operation::Decrypt => "Decrypted",
    };
    println!(
        "{verb} {filename:?} using {} ({input_len} -> {output_len} bytes).",
        algorithm.name()
    );
    if let Some(warning) = committed.durability_warning {
        eprintln!("The replacement completed, but durability could not be confirmed: {warning}");
    }
    Ok(())
}

fn protect_executable(filename: &OsStr, executable: &Path) -> Result<()> {
    let text = filename
        .to_str()
        .context("the filename must be valid Unicode")?;
    if executable
        .file_name()
        .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case(text))
        || text.eq_ignore_ascii_case("tencrypt-linux")
        || text.eq_ignore_ascii_case("tencrypt-windows.exe")
    {
        bail!("the executable cannot be used as an input file");
    }
    if text.starts_with(".tencrypt-") && text.ends_with(".tmp") {
        bail!("Tencrypt temporary files cannot be used as input files");
    }
    Ok(())
}

/// Shared entry point for the two platform-specific binaries.
pub fn entry() -> ExitCode {
    let command = match parse_args(std::env::args_os().skip(1).collect()) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("Error: {error:#}");
            eprintln!("Usage: {} <1..10> <E|D> <filename>", binary_name());
            eprintln!("Run with --help for all algorithms and examples.");
            return ExitCode::from(2);
        }
    };
    let result = match command {
        Command::Help => {
            usage();
            Ok(())
        }
        Command::List => {
            list_algorithms();
            Ok(())
        }
        Command::Version => {
            println!("{} {}", binary_name(), env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::Process {
            algorithm,
            operation,
            filename,
        } => process(algorithm, operation, &filename),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_keys_match_every_suite_and_are_distinct() {
        for algorithm in Algorithm::ALL {
            let key = embedded_keys::key(algorithm);
            assert_eq!(key.len(), algorithm.key_len());
            assert!(key.iter().any(|byte| *byte != 0));
            for other in Algorithm::ALL {
                if other != algorithm {
                    assert_ne!(key, embedded_keys::key(other));
                }
            }
        }
    }
}
