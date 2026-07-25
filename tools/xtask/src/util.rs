//! Process and filesystem plumbing shared by every stage of the orchestrator.
//!
//! Every external tool the build shells out to goes through [`run_command`],
//! which turns a non-zero exit into a described error so a failing sub-tool is
//! always visible with its command context rather than swallowed. The rest are
//! the small filesystem helpers (`copy_file`, `require_file`, `recreate_dir`,
//! `locate`) the stages reuse.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

/// Resolve the workspace root from this crate's compile-time manifest dir
/// (`tools/xtask` → two levels up). All build paths are anchored here.
pub(crate) fn workspace_root() -> Result<PathBuf, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map(Path::to_path_buf)
        .ok_or_else(|| "cannot determine workspace root".to_owned())
}

/// Run an external command, mapping a spawn failure or a non-zero exit into a
/// `description`-tagged error. Child stdout/stderr are inherited so the
/// sub-tool's own diagnostics reach the operator.
pub(crate) fn run_command(command: &mut Command, description: &str) -> Result<(), String> {
    let status = command
        .status()
        .map_err(|error| format!("{description}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{description} failed with {status}"))
    }
}

pub(crate) fn copy_file(source: &Path, destination: &Path) -> Result<(), String> {
    require_file(source)?;
    fs::copy(source, destination).map_err(|error| {
        format!(
            "copy {} to {}: {error}",
            source.display(),
            destination.display()
        )
    })?;
    Ok(())
}

pub(crate) fn require_file(path: &Path) -> Result<(), String> {
    if path.is_file() {
        Ok(())
    } else {
        Err(format!("required file is missing: {}", path.display()))
    }
}

pub(crate) fn recreate_dir(path: &Path) -> Result<(), String> {
    if path.exists() {
        fs::remove_dir_all(path).map_err(|error| format!("remove {}: {error}", path.display()))?;
    }
    fs::create_dir_all(path).map_err(|error| format!("create {}: {error}", path.display()))
}

/// Return the first existing candidate path, or a `description`-tagged error
/// naming all the candidates that were tried.
pub(crate) fn locate(candidates: &[&str], description: &str) -> Result<PathBuf, String> {
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .ok_or_else(|| format!("{description} not found in {candidates:?}"))
}

pub(crate) fn set_permissions_0700(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("chmod 0700 {}: {error}", path.display()))
}
