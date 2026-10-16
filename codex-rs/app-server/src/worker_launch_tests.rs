use super::*;
use sha2::{Digest, Sha256};

fn canonical(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(object.into_iter().map(|(key, value)| (key, canonical(value)))
            .collect::<std::collections::BTreeMap<_, _>>().into_iter().collect()),
        Value::Array(items) => Value::Array(items.into_iter().map(canonical).collect()),
        value => value,
    }
}

pub(crate) async fn sealed_manager_fixture(root: &std::path::Path) -> (crate::config_manager::ConfigManager, codex_core::config::Config) {
    let home = root.join("home");
    std::fs::create_dir(&home).unwrap();
    std::fs::write(home.join("config.toml"), "invalid ambient TOML = [").unwrap();
    let source = concat!("model='worker-model'\nmodel_provider='gateway'\ncli_auth_credentials_store='ephemeral'\n",
        "approval_policy='never'\nsandbox_mode='read-only'\nallow_login_shell=false\n",
        "model_reasoning_effort='low'\nmodel_reasoning_summary='auto'\n",
        "[features]\nplugins=false\napps=false\nhooks=false\ncode_mode=false\ncode_mode_only=false\n",
        "code_mode_prewarm=false\ncode_mode_host=false\nshell_snapshot=false\nshell_snapshot_v2=false\n",
        "[model_providers.gateway]\nname='fixture'\nbase_url='http://127.0.0.1:9191/v1'\nwire_api='responses'\n",
        "[cloud.skills]\nenabled=false\n[orchestrator.mcp]\nenabled=false\n");
    let runtime = serde_json::json!({"cwd":root,"codexHome":home,"sqliteHome":root.join("sqlite"),"codexSelfExe":root.join("codex"),
        "codexLinuxSandboxExe":null,"mainExecveWrapperExe":null,"zshPath":root.join("zsh")});
    let source_hash = format!("{:x}", Sha256::digest(source.as_bytes()));
    let authorization = format!("Bearer {}", "a".repeat(43));
    let mut request = serde_json::json!({"version":1,"runtime":runtime,
        "template":{"template":source,"templateSha256":source_hash,"baseConfigurationSha256":source_hash,
            "runtime":runtime,"bindingSha256":"b".repeat(64),"model":"worker-model","modelProviderId":"gateway",
            "modelProviderSha256":null,"server":"sift-worker"},
        "input":{"baseConfiguration":source,"authorization":authorization,"endpoint":"http://127.0.0.1:9000/mcp",
            "bindingSha256":"b".repeat(64),"model":"worker-model","launchId":"launch","incarnationId":"incarnation"},
        "serverConfig":{"url":"http://127.0.0.1:9000/mcp","http_headers":{"Authorization":authorization},
            "environment_id":"local","enabled":true,"tool_timeout_sec":null,"enabled_tools":["execute"]},
        "projection":null,"configSha256":null,"serverConfigSha256":null});
    request["requestSha256"] = serde_json::json!(format!("{:x}", Sha256::digest(serde_json::to_vec(&canonical(request.clone())).unwrap())));
    let materialized = Arc::new(project_worker_launch(&request).await.unwrap());
    let native = materialized.load_config(&Default::default(), None).unwrap();
    let manager = crate::config_manager::ConfigManager::new_for_tests(home, vec![], Default::default(), Default::default())
        .with_sealed_worker(Some(materialized));
    (manager, native)
}

#[tokio::test]
async fn sealed_manager_reuses_native_loaded_state_for_startup_thread_resume_and_layers() {
    let root = tempfile::tempdir().unwrap();
    let (manager, native) = sealed_manager_fixture(root.path()).await;
    assert_eq!(manager.load_startup_config(None).await.unwrap(), native);
    assert_eq!(manager.load_latest_config(None).await.unwrap(), native);
    assert_eq!(manager.load_latest_config_with_session_layers(&native.config_layer_stack, root.path()).await.unwrap(), native);
    assert_eq!(manager.load_retained_session_config(&native.config_layer_stack, root.path()).await.unwrap(), native);
    let layers = manager.load_config_layers(None).await.unwrap();
    assert!(!toml::to_string(&layers.effective_config()).unwrap().contains("Authorization"));
    assert!(manager.load_with_overrides(Some(std::collections::HashMap::from([
        ("model".to_string(), serde_json::json!("other")),
    ])), Default::default()).await.is_err());
}

#[cfg(unix)]
async fn frame(bytes: Vec<u8>) -> io::Result<Value> {
    let (reader, writer) = std::os::unix::net::UnixStream::pair().unwrap();
    writer.set_nonblocking(true).unwrap();
    let mut writer = tokio::net::UnixStream::from_std(writer).unwrap();
    let write = tokio::spawn(async move { let _ = writer.write_all(&bytes).await; });
    let result = read_socket_frame(reader, Instant::now() + Duration::from_secs(5)).await;
    write.await.unwrap();
    result
}

#[cfg(unix)]
#[tokio::test]
async fn private_socket_reads_exactly_one_bounded_json_frame() {
    assert_eq!(frame(br#"{"version":1}"#.to_vec()).await.unwrap(), serde_json::json!({"version":1}));
    assert!(frame(br#"{"version":1}{}"#.to_vec()).await.is_err());
    assert!(frame(vec![b' '; WORKER_MATERIALIZATION_MAX_BYTES + 1]).await.is_err());
    assert!(frame(vec![0xff]).await.is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn stalled_bootstrap_times_out_and_closes_its_owned_socket() {
    let (reader, writer) = std::os::unix::net::UnixStream::pair().unwrap();
    writer.set_nonblocking(true).unwrap();
    let mut writer = tokio::net::UnixStream::from_std(writer).unwrap();
    assert!(read_socket_frame(reader, Instant::now() + Duration::from_secs(5)).await.is_err());
    assert!(writer.write_all(b"late").await.is_err());
}


#[cfg(unix)]
#[tokio::test]
async fn unread_full_receipt_socket_closes_at_the_remaining_total_deadline() {
    use std::io::{Read, Write};
    let (mut output, mut unread_peer) = std::os::unix::net::UnixStream::pair().unwrap();
    output.set_nonblocking(true).unwrap();
    // Fill the actual OS send buffer, independent of platform buffer sizes.
    let padding = [b'x'; 8192];
    loop {
        match output.write(&padding) {
            Ok(_) => {},
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("fixture socket failed: {error}"),
        }
    }
    loop {
        match output.write(b"x") {
            Ok(_) => {},
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("fixture socket failed: {error}"),
        }
    }
    let start = Instant::now();
    // Input/loading already consumed the rest of the five-second total budget.
    let deadline = start + Duration::from_millis(30);
    assert!(write_socket_receipt(output, b"{}", deadline).await.is_err());
    assert!(start.elapsed() < Duration::from_secs(1));
    unread_peer.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
    let mut drained = Vec::new();
    unread_peer.read_to_end(&mut drained).unwrap(); // EOF proves no writer survived.
    assert!(!drained.ends_with(b"{}"));
}

#[cfg(unix)]
#[tokio::test]
async fn receipt_socket_writes_a_complete_frame_then_eof() {
    let (output, peer) = std::os::unix::net::UnixStream::pair().unwrap();
    peer.set_nonblocking(true).unwrap();
    let mut peer = tokio::net::UnixStream::from_std(peer).unwrap();
    write_socket_receipt(output, b"{}", Instant::now() + Duration::from_secs(1)).await.unwrap();
    let mut bytes = Vec::new();
    peer.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, b"{}");
}
