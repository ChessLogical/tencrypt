//! Platform-specific single-file transactions.
//!
//! Only a basename inside an already trusted directory is accepted. The source
//! remains open and locked while a private replacement is written, checked, and
//! flushed. Commit performs one filesystem rename; it never truncates or first
//! removes the source. As with ordinary file tools, an actively hostile process
//! running as the same user is outside the threat model.

use anyhow::{Context, Result, bail};
use std::ffi::OsStr;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
pub use linux::Transaction;
#[cfg(target_os = "windows")]
pub use windows::Transaction;

/// A successful return always means the replacement has already happened.
/// A durability warning must not be described as an unchanged original file.
#[derive(Debug, Default)]
pub struct CommitOutcome {
    pub durability_warning: Option<String>,
}

/// Apply the same unambiguous filename rules on both operating systems.
pub fn validate_basename(name: &OsStr) -> Result<()> {
    let text = name
        .to_str()
        .context("the filename must be valid Unicode")?;
    if text.is_empty()
        || text == "."
        || text == ".."
        || text.ends_with(['.', ' '])
        || text.chars().any(|c| {
            c.is_control() || matches!(c, '/' | '\\' | ':' | '"' | '<' | '>' | '|' | '?' | '*')
        })
    {
        bail!(
            "provide a plain filename, without directories, device syntax, or a trailing dot/space"
        );
    }
    let stem = text
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    let numbered_device = stem
        .strip_prefix("COM")
        .or_else(|| stem.strip_prefix("LPT"))
        .is_some_and(|suffix| {
            matches!(
                suffix,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        });
    if matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || numbered_device
    {
        bail!("Windows device names are not supported as filenames");
    }
    Ok(())
}

fn temporary_name() -> Result<String> {
    use std::fmt::Write;
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).context("the operating system random generator failed")?;
    let mut name = String::from(".tencrypt-");
    for byte in random {
        // Writing to a String cannot fail.
        write!(name, "{byte:02x}").expect("String formatting failed");
    }
    name.push_str(".tmp");
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_paths_streams_and_device_names() {
        for bad in [
            "",
            ".",
            "..",
            "../file",
            "dir/file",
            "dir\\file",
            "C:file",
            "file:stream",
            "file.",
            "file ",
            "NUL",
            "con.txt",
            "COM1",
            "lpt².txt",
        ] {
            assert!(
                validate_basename(OsStr::new(bad)).is_err(),
                "accepted {bad:?}"
            );
        }
        for good in [
            "report.txt",
            "a file.pdf",
            "Résumé.bin",
            "COM10.dat",
            ".notes",
        ] {
            validate_basename(OsStr::new(good)).unwrap();
        }
    }
}
