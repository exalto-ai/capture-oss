use std::{
    env,
    path::{Component, Path, PathBuf},
};

use anyhow::{Result, bail};
pub use capture_updater::write_private_file_atomically;

pub(super) fn config_file(name: &str) -> Result<PathBuf> {
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        bail!("configuration file name must be one path component");
    }
    let base = if let Some(path) = env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(path)
    } else if let Some(path) = env::var_os("APPDATA") {
        PathBuf::from(path)
    } else if let Some(path) = env::var_os("HOME") {
        PathBuf::from(path).join(".config")
    } else {
        bail!("could not determine a configuration directory")
    };
    Ok(base.join("ai.exalto.capture").join(name))
}
