//! Executable naming, atomic replacement, and platform process handling.

use std::{fs, path::Path};

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[cfg(unix)]
use anyhow::Context as _;

#[cfg(not(windows))]
use anyhow::bail;
#[cfg(windows)]
use anyhow::ensure;

#[cfg(windows)]
use crate::{
    install::{
        InstallPaths, apply_update_transaction, lock_install_directory, recover_interrupted_update,
    },
    release::validate_identifier,
    storage,
};

#[cfg(windows)]
pub(crate) const WINDOWS_RESULT_NAME: &str = ".capture-runtime-update-result.json";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsUpdateResult {
    pub state: String,
    pub build_id: String,
    pub message: String,
}

pub(crate) fn cli_file_name() -> &'static str {
    if cfg!(windows) {
        "capture.exe"
    } else {
        "capture"
    }
}

pub(crate) fn make_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("marking {} executable", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(not(windows))]
pub(crate) fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(windows)]
pub(crate) fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let source = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: both pointers reference NUL-terminated UTF-16 buffers that stay
    // alive for the duration of the call.
    let replaced = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if replaced == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
pub(crate) fn sync_directory(path: &Path) -> Result<()> {
    fs::File::open(path)
        .with_context(|| format!("opening {} for sync", path.display()))?
        .sync_all()
        .with_context(|| format!("syncing {}", path.display()))
}

#[cfg(not(unix))]
pub(crate) fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(windows)]
pub fn run_windows_apply_helper(
    parent_pid: u32,
    install_directory: &Path,
    staging_directory: &Path,
    build_id: &str,
) -> Result<()> {
    let result =
        run_windows_apply_helper_inner(parent_pid, install_directory, staging_directory, build_id);
    let report = WindowsUpdateResult {
        state: if result.is_ok() { "updated" } else { "failed" }.into(),
        build_id: build_id.into(),
        message: if result.is_ok() {
            "The staged Windows update completed.".into()
        } else {
            "The staged Windows update failed safely. Run capture update again.".into()
        },
    };
    let report_path = install_directory.join(WINDOWS_RESULT_NAME);
    if let Ok(bytes) = serde_json::to_vec(&report) {
        let _ = storage::write_private_file_atomically(&report_path, &bytes);
    }
    result
}

#[cfg(windows)]
pub(crate) fn run_windows_apply_helper_inner(
    parent_pid: u32,
    install_directory: &Path,
    staging_directory: &Path,
    build_id: &str,
) -> Result<()> {
    wait_for_process(parent_pid);
    validate_identifier(build_id, "helper build ID")?;
    let install = InstallPaths::from_directory(install_directory);
    ensure!(
        staging_directory.parent() == Some(install_directory),
        "the helper staging directory is outside the installation directory"
    );
    let _lock = lock_install_directory(&install)?;
    recover_interrupted_update(&install)?;
    apply_update_transaction(&install, &staging_directory.join(cli_file_name()), build_id)?;
    schedule_windows_helper_cleanup(staging_directory);
    Ok(())
}

#[cfg(windows)]
pub fn windows_update_result() -> Option<WindowsUpdateResult> {
    let executable = std::env::current_exe().ok()?;
    let path = executable.parent()?.join(WINDOWS_RESULT_NAME);
    serde_json::from_slice(&fs::read(path).ok()?).ok()
}

#[cfg(not(windows))]
pub fn windows_update_result() -> Option<WindowsUpdateResult> {
    None
}

#[cfg(not(windows))]
pub fn run_windows_apply_helper(
    _parent_pid: u32,
    _install_directory: &Path,
    _staging_directory: &Path,
    _build_id: &str,
) -> Result<()> {
    bail!("the Windows update helper is unavailable on this operating system")
}

#[cfg(windows)]
pub(crate) fn wait_for_process(pid: u32) {
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        Storage::FileSystem::SYNCHRONIZE,
        System::Threading::{INFINITE, OpenProcess, WaitForSingleObject},
    };
    let handle = unsafe { OpenProcess(SYNCHRONIZE, 0, pid) };
    if !handle.is_null() {
        unsafe {
            WaitForSingleObject(handle, INFINITE);
            CloseHandle(handle);
        }
    }
}

#[cfg(windows)]
pub(crate) fn schedule_windows_helper_cleanup(staging_directory: &Path) {
    fn schedule(path: &Path) {
        use std::os::windows::ffi::OsStrExt as _;
        use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_DELAY_UNTIL_REBOOT, MoveFileExW};
        let path = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        unsafe {
            MoveFileExW(path.as_ptr(), std::ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT);
        }
    }
    if let Ok(helper) = std::env::current_exe() {
        schedule(&helper);
    }
    schedule(staging_directory);
}
