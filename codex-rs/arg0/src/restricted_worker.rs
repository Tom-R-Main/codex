//! Fixed, image-owned Arg0 identity for private-bootstrap workers. No writable
//! aliases or install-context/environment discovery participates in this path.
use crate::Arg0DispatchPaths;
#[cfg(unix)]
use std::path::Path;
#[cfg(any(target_os = "linux", test))]
use std::path::PathBuf;

#[cfg(target_os = "linux")]
const PROVIDER: &str = "/usr/local/bin/codex";
#[cfg(target_os = "linux")]
const SANDBOX: &str = "/usr/local/bin/codex-linux-sandbox";
#[cfg(target_os = "linux")]
const WRAPPER: &str = "/usr/local/bin/codex-execve-wrapper";

pub(crate) fn requested() -> bool {
    std::env::var_os("CODEX_RESTRICTED_WORKER").is_some()
}
fn refused() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "protected worker executable identity refused",
    )
}

pub(crate) fn paths() -> std::io::Result<Arg0DispatchPaths> {
    if std::env::var_os("CODEX_RESTRICTED_WORKER").as_deref() != Some(std::ffi::OsStr::new("1"))
        || std::env::args_os().skip(1).collect::<Vec<_>>()
            != [std::ffi::OsString::from("app-server")]
    {
        return Err(refused());
    }
    fixed_paths()
}

#[cfg(target_os = "linux")]
fn fixed_paths() -> std::io::Result<Arg0DispatchPaths> {
    if std::env::current_exe().map_err(|_| refused())? != Path::new(PROVIDER) {
        return Err(refused());
    }
    for directory in ["/", "/usr", "/usr/local", "/usr/local/bin"] {
        check_entry(Path::new(directory), 0, true)?;
    }
    check_entry(Path::new(PROVIDER), 0, false)?;
    check_alias(Path::new(SANDBOX), Path::new(PROVIDER), 0)?;
    check_alias(Path::new(WRAPPER), Path::new(PROVIDER), 0)?;
    Ok(Arg0DispatchPaths {
        codex_self_exe: Some(PathBuf::from(PROVIDER)),
        codex_linux_sandbox_exe: Some(PathBuf::from(SANDBOX)),
        main_execve_wrapper_exe: Some(PathBuf::from(WRAPPER)),
    })
}

#[cfg(not(target_os = "linux"))]
fn fixed_paths() -> std::io::Result<Arg0DispatchPaths> {
    Err(refused())
}

#[cfg(unix)]
fn check_entry(path: &Path, owner: u32, directory: bool) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path).map_err(|_| refused())?;
    if metadata.uid() != owner
        || metadata.mode() & 0o022 != 0
        || if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file() || metadata.mode() & 0o111 == 0
        }
    {
        return Err(refused());
    }
    Ok(())
}

#[cfg(unix)]
fn check_alias(alias: &Path, provider: &Path, owner: u32) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(alias).map_err(|_| refused())?;
    if !metadata.file_type().is_symlink()
        || metadata.uid() != owner
        || std::fs::read_link(alias).map_err(|_| refused())? != provider
    {
        return Err(refused());
    }
    Ok(())
}

#[cfg(test)]
#[path = "restricted_worker_tests.rs"]
mod tests;
