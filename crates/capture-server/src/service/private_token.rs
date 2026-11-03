//! Reads a bearer token the server holds in a private file: its capture
//! service credential, or the token capture-api presents to the customer API.

use std::{io::Read as _, path::Path};

use anyhow::{Context as _, Result, ensure};

/// capture-api's service tokens are 32 to 512 bytes.
pub(crate) const MIN_TOKEN_BYTES: usize = 32;
pub(crate) const MAX_TOKEN_BYTES: usize = 512;
/// The token and at most a trailing line ending.
pub(crate) const MAX_TOKEN_FILE_BYTES: u64 = 1024;

/// Reads `path`, a regular file that group and others cannot access, holding
/// one token of printable ASCII and at most a trailing line ending. Errors
/// describe the file, never its contents; callers add which file it is.
pub(crate) fn read(path: &Path) -> Result<String> {
    let file = std::fs::File::open(path).context("opening the file")?;
    let metadata = file.metadata().context("inspecting the file")?;
    ensure!(metadata.is_file(), "it is not a regular file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "it must not be accessible by group or others"
        );
    }
    let mut bytes = Vec::new();
    file.take(MAX_TOKEN_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("reading the file")?;
    ensure!(
        bytes.len() as u64 <= MAX_TOKEN_FILE_BYTES,
        "it is larger than {MAX_TOKEN_FILE_BYTES} bytes"
    );
    let token = match bytes.strip_suffix(b"\n") {
        Some(line) => line.strip_suffix(b"\r").unwrap_or(line),
        None => &bytes,
    };
    ensure!(
        (MIN_TOKEN_BYTES..=MAX_TOKEN_BYTES).contains(&token.len())
            && token.iter().all(u8::is_ascii_graphic),
        "it must hold one token of {MIN_TOKEN_BYTES} to {MAX_TOKEN_BYTES} printable ASCII characters"
    );
    Ok(String::from_utf8(token.to_vec()).expect("printable ASCII is UTF-8"))
}
