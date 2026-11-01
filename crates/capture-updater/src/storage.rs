use std::{
    fs,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};

use crate::platform::replace_file;

/// Writes a private release-adjacent file without exposing partial contents.
pub fn write_private_file_atomically(path: &Path, contents: &[u8]) -> Result<()> {
    let pending = write_private_pending_file(path, contents)?;
    pending.replace(path)?;
    Ok(())
}

fn write_private_pending_file(path: &Path, contents: &[u8]) -> Result<PendingFile> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| anyhow::anyhow!("private configuration path has no parent"))?;
    create_private_directory(parent)?;
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("private configuration path has no file name"))?
        .to_string_lossy();
    let partial = parent.join(format!(
        ".{file_name}.{}.{}.partial",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    let pending = PendingFile::new(partial);
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options
        .open(pending.path())
        .with_context(|| format!("create {}", pending.path().display()))?;
    output
        .write_all(contents)
        .with_context(|| format!("write {}", pending.path().display()))?;
    output
        .sync_all()
        .with_context(|| format!("sync {}", pending.path().display()))?;
    drop(output);
    #[cfg(windows)]
    restrict_windows_acl(pending.path(), "F")?;
    Ok(pending)
}

fn create_private_directory(path: &Path) -> Result<()> {
    let existed = path
        .try_exists()
        .with_context(|| format!("inspect {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .with_context(|| format!("create {}", path.display()))?;
        if !existed {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .with_context(|| format!("restrict {}", path.display()))?;
        }
    }
    #[cfg(all(not(unix), not(windows)))]
    fs::create_dir_all(path).with_context(|| format!("create {}", path.display()))?;
    #[cfg(windows)]
    {
        fs::create_dir_all(path).with_context(|| format!("create {}", path.display()))?;
        if !existed {
            restrict_windows_acl(path, "(OI)(CI)F")?;
        }
    }
    Ok(())
}

#[cfg(windows)]
fn restrict_windows_acl(path: &Path, permission: &str) -> Result<()> {
    use std::process::Command;

    let output = Command::new("whoami")
        .output()
        .context("determine the current Windows account for private-file permissions")?;
    if !output.status.success() {
        anyhow::bail!(
            "could not determine the current Windows account for private-file permissions"
        );
    }
    let identity = String::from_utf8(output.stdout)
        .context("current Windows account name is not UTF-8")?
        .trim()
        .to_owned();
    if identity.is_empty() {
        anyhow::bail!("current Windows account name is empty");
    }
    let grant = format!("{identity}:{permission}");
    let status = Command::new("icacls")
        .arg(path)
        .args([
            "/inheritance:r",
            "/grant:r",
            grant.as_str(),
            "/remove:g",
            "*S-1-1-0",
            "*S-1-5-11",
            "*S-1-5-18",
            "*S-1-5-32-544",
            "*S-1-5-32-545",
            "/Q",
        ])
        .status()
        .with_context(|| format!("restrict permissions on {}", path.display()))?;
    if !status.success() {
        anyhow::bail!("could not restrict permissions on {}", path.display());
    }
    Ok(())
}

struct PendingFile {
    path: PathBuf,
}

impl PendingFile {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn replace(self, destination: &Path) -> Result<()> {
        replace_file(&self.path, destination)
            .with_context(|| format!("atomically replace {}", destination.display()))
    }
}

impl Drop for PendingFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn private_write_preserves_an_existing_parent_directory_mode() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let destination = directory.path().join("private-credentials");

        write_private_file_atomically(&destination, b"secret").unwrap();

        assert_eq!(
            fs::metadata(directory.path()).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(
            fs::metadata(destination).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
