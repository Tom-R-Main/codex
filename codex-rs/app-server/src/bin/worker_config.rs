fn main() -> std::io::Result<()> {
    if std::env::args_os().len() != 1 { return Err(codex_core::worker_materialization_error()); }
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(codex_app_server::run_worker_config_materializer())
}
