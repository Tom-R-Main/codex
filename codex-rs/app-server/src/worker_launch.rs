//! Private native bootstrap. This is not a model-visible or JSON-RPC endpoint.

use codex_arg0::Arg0DispatchPaths;
use codex_core::WORKER_MATERIALIZATION_MAX_BYTES;
use codex_core::WorkerLaunchMaterialization;
use codex_core::materialize_worker_launch;
use codex_core::project_worker_launch;
use codex_core::worker_materialization_error;
use codex_core::worker_request_runtime;
use serde_json::Value;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::time::Instant;

/// FD0 for the helper and FD3 for the provider must be connected AF_UNIX stream
/// sockets owned exclusively by the trusted launcher. EOF terminates one JSON
/// frame. Ordinary pipes/files/terminals are refused, not polled or reopened.
#[cfg(unix)]
fn take_private_socket(fd: std::os::fd::RawFd) -> io::Result<std::os::unix::net::UnixStream> {
    use std::os::fd::FromRawFd;
    use std::os::fd::OwnedFd;
    use std::os::unix::fs::FileTypeExt;
    if !matches!(fd, 0 | 1 | 3)
        || !std::fs::metadata(format!("/dev/fd/{fd}"))
            .is_ok_and(|metadata| metadata.file_type().is_socket())
    {
        return Err(worker_materialization_error());
    }
    // SAFETY: Only fixed private bootstrap descriptors 0, 1 and 3 are passed by
    // the entrypoints below. The launcher transfers sole ownership of an open
    // descriptor before any code in this process uses it; this function takes
    // that ownership exactly once and closes it on every return path.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let stream = std::os::unix::net::UnixStream::from(owned);
    stream
        .peer_addr()
        .map_err(|_| worker_materialization_error())?;
    Ok(stream)
}

#[cfg(unix)]
async fn read_private_frame(fd: std::os::fd::RawFd, deadline: Instant) -> io::Result<Value> {
    read_socket_frame(take_private_socket(fd)?, deadline).await
}

#[cfg(unix)]
async fn read_socket_frame(
    stream: std::os::unix::net::UnixStream,
    deadline: Instant,
) -> io::Result<Value> {
    stream
        .peer_addr()
        .map_err(|_| worker_materialization_error())?;
    stream
        .set_nonblocking(true)
        .map_err(|_| worker_materialization_error())?;
    let stream =
        tokio::net::UnixStream::from_std(stream).map_err(|_| worker_materialization_error())?;
    let mut bytes = Vec::new();
    tokio::time::timeout_at(
        deadline,
        stream
            .take((WORKER_MATERIALIZATION_MAX_BYTES + 1) as u64)
            .read_to_end(&mut bytes),
    )
    .await
    .map_err(|_| worker_materialization_error())?
    .map_err(|_| worker_materialization_error())?;
    if bytes.len() > WORKER_MATERIALIZATION_MAX_BYTES {
        return Err(worker_materialization_error());
    }
    serde_json::from_slice(&bytes).map_err(|_| worker_materialization_error())
}

#[cfg(not(unix))]
async fn read_private_frame(_fd: i32, _deadline: Instant) -> io::Result<Value> {
    Err(worker_materialization_error())
}

pub(crate) async fn take_worker_launch(
    paths: &Arg0DispatchPaths,
) -> io::Result<Option<Arc<WorkerLaunchMaterialization>>> {
    if !codex_core::worker_is_restricted() {
        return Ok(None);
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let frame = read_private_frame(3, deadline).await?;
    if frame.as_object().is_none_or(|object| object.len() != 2)
        || frame["version"] != 1
        || frame.get("materialization").is_none()
    {
        return Err(worker_materialization_error());
    }
    let request = &frame["materialization"];
    let runtime = worker_request_runtime(request)?;
    let home = codex_core::config::find_codex_home().map_err(|_| worker_materialization_error())?;
    let cwd = std::env::current_dir().map_err(|_| worker_materialization_error())?;
    if !runtime.matches_process(
        &cwd,
        &home,
        paths.codex_self_exe.as_deref(),
        paths.codex_linux_sandbox_exe.as_deref(),
        paths.main_execve_wrapper_exe.as_deref(),
    ) {
        return Err(worker_materialization_error());
    }
    codex_core::validate_worker_bootstrap_identity(request)?;
    let materialized = tokio::time::timeout_at(deadline, materialize_worker_launch(request))
        .await
        .map_err(|_| worker_materialization_error())??;
    let config = materialized.load_config(&Default::default(), /*fallback_cwd*/ None)?;
    codex_core::validate_worker_config(&config).map_err(|_| worker_materialization_error())?;
    Ok(Some(Arc::new(materialized)))
}

/// Controller helper: stdin and stdout are private connected AF_UNIX sockets;
/// output is a credential-free native receipt. No auth manager, thread, MCP startup or inference.
#[cfg(unix)]
pub async fn run_worker_config_materializer() -> io::Result<()> {
    // One monotonic deadline covers input, native construction and output.
    let deadline = Instant::now() + Duration::from_secs(5);
    let output = take_private_socket(1)?;
    let frame = read_private_frame(0, deadline).await?;
    if frame.as_object().is_none_or(|object| object.len() != 3) || frame["version"] != 1 {
        return Err(worker_materialization_error());
    }
    let request = frame
        .get("request")
        .ok_or_else(worker_materialization_error)?;
    let runtime = worker_request_runtime(request)?;
    if std::env::current_dir().map_err(|_| worker_materialization_error())? != runtime.cwd
        || codex_core::config::find_codex_home()
            .map_err(|_| worker_materialization_error())?
            .as_path()
            != runtime.codex_home.as_path()
    {
        return Err(worker_materialization_error());
    }
    let materialized = tokio::time::timeout_at(deadline, async {
        match frame["operation"].as_str() {
            Some("project") => project_worker_launch(request).await,
            Some("materialize") => materialize_worker_launch(request).await,
            _ => Err(worker_materialization_error()),
        }
    })
    .await
    .map_err(|_| worker_materialization_error())??;
    let bytes =
        serde_json::to_vec(&materialized.receipt).map_err(|_| worker_materialization_error())?;
    // The receipt has credential-free TOML plus hashes; it never echoes input.
    if bytes.len() > 98_304 {
        return Err(worker_materialization_error());
    }
    write_socket_receipt(output, &bytes, deadline).await
}

#[cfg(unix)]
async fn write_socket_receipt(
    stream: std::os::unix::net::UnixStream,
    bytes: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    stream
        .peer_addr()
        .map_err(|_| worker_materialization_error())?;
    stream
        .set_nonblocking(true)
        .map_err(|_| worker_materialization_error())?;
    let mut stream =
        tokio::net::UnixStream::from_std(stream).map_err(|_| worker_materialization_error())?;
    if Instant::now() >= deadline {
        return Err(worker_materialization_error());
    }
    // Tokio's reactor owns the nonblocking socket. Dropping this future and
    // socket closes it; no blocking-pool OS write survives the total deadline.
    tokio::time::timeout_at(deadline, async {
        stream.write_all(bytes).await?;
        stream.shutdown().await
    })
    .await
    .map_err(|_| worker_materialization_error())?
    .map_err(|_| worker_materialization_error())
}

#[cfg(not(unix))]
pub async fn run_worker_config_materializer() -> io::Result<()> {
    Err(worker_materialization_error())
}

#[cfg(test)]
#[path = "worker_launch_tests.rs"]
pub(crate) mod tests;
