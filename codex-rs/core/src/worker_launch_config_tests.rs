use super::*;
use pretty_assertions::assert_eq;

fn rehash(request: &mut Value) {
    let mut body = request.clone();
    body.as_object_mut().unwrap().remove("requestSha256");
    request["requestSha256"] = json!(digest(&body).unwrap());
}

fn request(root: &Path, gateway: &str) -> Value {
    let source = format!(r#"model = "worker-model"
model_provider = "sift_gateway"
cli_auth_credentials_store = "ephemeral"
approval_policy = "never"
sandbox_mode = "read-only"
allow_login_shell = false
model_reasoning_effort = "low"
model_reasoning_summary = "auto"
web_search = "disabled"
[features]
plugins = false
apps = false
hooks = false
code_mode = false
code_mode_only = false
code_mode_prewarm = false
code_mode_host = false
shell_snapshot = false
shell_snapshot_v2 = false
[model_providers.sift_gateway]
name = "controller gateway fixture"
base_url = "{gateway}"
wire_api = "responses"
[cloud.skills]
enabled = false
[orchestrator.mcp]
enabled = false
"#);
    let runtime = json!({"cwd":root,"codexHome":root.join("home"),"sqliteHome":root.join("sqlite"),"codexSelfExe":root.join("codex"),
        "codexLinuxSandboxExe":null,"mainExecveWrapperExe":null,"zshPath":root.join("zsh")});
    let authorization = format!("Bearer {}", "a".repeat(43));
    let mut request = json!({"version":1,"runtime":runtime,
        "template":{"template":source,"templateSha256":hash(&source),"baseConfigurationSha256":hash(&source),
            "runtime":runtime,"bindingSha256":"b".repeat(64),"model":"worker-model","modelProviderId":"sift_gateway",
            "modelProviderSha256":null,"server":"sift-worker"},
        "input":{"baseConfiguration":source,"authorization":authorization,"endpoint":"http://127.0.0.1:9000/mcp",
            "bindingSha256":"b".repeat(64),"model":"worker-model","launchId":"launch-1","incarnationId":"process-1"},
        "serverConfig":{"url":"http://127.0.0.1:9000/mcp","http_headers":{"Authorization":authorization},
            "environment_id":"local","enabled":true,"tool_timeout_sec":null,"enabled_tools":["execute"]},
        "projection":null,"configSha256":null,"serverConfigSha256":null,"requestSha256":null});
    rehash(&mut request);
    request
}

async fn seal(request: &mut Value) -> WorkerLaunchMaterialization {
    let observed = project_worker_launch(request).await.unwrap();
    request["projection"] = observed.receipt["projection"].clone();
    request["configSha256"] = observed.receipt["configSha256"].clone();
    request["serverConfigSha256"] = observed.receipt["serverConfigSha256"].clone();
    request["template"]["modelProviderSha256"] = observed.receipt["modelProviderSha256"].clone();
    rehash(request);
    materialize_worker_launch(request).await.unwrap()
}

#[tokio::test]
async fn real_typed_loader_projects_then_verifies_without_ambient_auth_or_network() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("home")).unwrap();
    std::fs::write(root.path().join("home/config.toml"), "invalid ambient config = [").unwrap();
    std::fs::write(root.path().join("home/auth.json"), "invalid auth store fixture").unwrap();
    std::fs::create_dir(root.path().join(".codex")).unwrap();
    std::fs::write(root.path().join(".codex/config.toml"), "invalid project config = [").unwrap();
    let gateway = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    gateway.set_nonblocking(true).unwrap();
    let mut request = request(root.path(), &format!("http://{}/v1", gateway.local_addr().unwrap()));
    let loaded = seal(&mut request).await;
    let config = loaded.load_config(&ConfigOverrides::default(), Some(root.path())).unwrap();
    assert_eq!(loaded.receipt["configSha256"], effective_config_sha256(&config).unwrap());
    assert_eq!(gateway.accept().unwrap_err().kind(), io::ErrorKind::WouldBlock);
    assert!(!loaded.configuration.contains("Bearer "));
    assert!(!serde_json::to_string(&loaded.receipt).unwrap().contains("Bearer "));
    assert!(!toml::to_string(&config.config_layer_stack.effective_config()).unwrap().contains("Authorization"));
    let McpServerTransportConfig::StreamableHttp { http_headers: Some(headers), .. } =
        &config.mcp_servers.get()["sift-worker"].transport else { panic!("expected typed in-memory header"); };
    assert_eq!(headers.get("Authorization").unwrap(), request["input"]["authorization"].as_str().unwrap());
    assert_eq!(loaded.load_config(&ConfigOverrides::default(), Some(root.path())).unwrap(), config);
    assert!(loaded.load_config(&ConfigOverrides { model: Some("replacement".to_string()), ..Default::default() }, None).is_err());
    assert!(loaded.load_config(&ConfigOverrides::default(), Some(&root.path().join("drift"))).is_err());
}

#[tokio::test]
async fn checksum_replay_and_actual_semantic_changes_cannot_copy_requested_digests() {
    let root = tempfile::tempdir().unwrap();
    let mut request = request(root.path(), "http://127.0.0.1:9191/v1");
    seal(&mut request).await;
    let mut changed = request.clone();
    changed["input"]["authorization"] = json!(format!("Bearer {}", "c".repeat(43)));
    changed["serverConfig"]["http_headers"]["Authorization"] = changed["input"]["authorization"].clone();
    assert!(materialize_worker_launch(&changed).await.is_err());
    rehash(&mut changed);
    assert!(materialize_worker_launch(&changed).await.is_err());
    let mut changed = request.clone();
    let source = changed["template"]["template"].as_str().unwrap().replace("web_search = \"disabled\"", "web_search = \"cached\"");
    changed["template"]["template"] = json!(source);
    changed["template"]["templateSha256"] = json!(hash(&source));
    rehash(&mut changed);
    assert!(materialize_worker_launch(&changed).await.is_err());
    assert!(project_worker_launch(&changed).await.is_ok());
}

#[tokio::test]
async fn file_indirection_is_refused_before_any_attempt_to_load_it() {
    let root = tempfile::tempdir().unwrap();
    for field in ["model_instructions_file", "experimental_compact_prompt_file", "model_catalog_json"] {
        let mut request = request(root.path(), "http://127.0.0.1:9191/v1");
        let source = format!("{field} = '/must-not-read/fixture'\n{}", request["template"]["template"].as_str().unwrap());
        request["template"]["template"] = json!(source);
        request["template"]["templateSha256"] = json!(hash(&source));
        rehash(&mut request);
        let error = project_worker_launch(&request).await.err().unwrap();
        assert_eq!(error.to_string(), "protected worker materialization refused");
    }
}

#[test]
fn runtime_paths_use_literal_absolute_identity_and_refuse_drift() {
    let mut request = request(Path::new("/workspace"), "http://127.0.0.1:9191/v1");
    let runtime = worker_request_runtime(&request).unwrap();
    assert!(runtime.matches_process(Path::new("/workspace"), Path::new("/workspace/home"),
        Some(Path::new("/workspace/codex")), None, None));
    assert!(!runtime.matches_process(Path::new("/different"), Path::new("/workspace/home"),
        Some(Path::new("/workspace/codex")), None, None));
    request["runtime"]["cwd"] = json!("/workspace/../workspace");
    assert!(worker_request_runtime(&request).is_err());
}


#[tokio::test]
async fn raw_executor_token_cannot_escape_via_template_or_receipt() {
    let root = tempfile::tempdir().unwrap();
    for injected in ["base_instructions", "developer_instructions"] {
        let mut request = request(root.path(), "http://127.0.0.1:9191/v1");
        let raw = request["input"]["authorization"].as_str().unwrap()[7..].to_string();
        let source = format!("{injected} = '{raw}'\n{}", request["template"]["template"].as_str().unwrap());
        request["template"]["template"] = json!(source);
        request["template"]["templateSha256"] = json!(hash(&source));
        rehash(&mut request);
        let error = project_worker_launch(&request).await.err().unwrap();
        assert_eq!(error.to_string(), "protected worker materialization refused");
        assert!(!error.to_string().contains(&raw));
    }
    let mut request = request(root.path(), "http://127.0.0.1:9191/v1");
    request["template"]["model"] = json!("a".repeat(43));
    rehash(&mut request);
    assert!(project_worker_launch(&request).await.is_err());
}

#[tokio::test]
async fn sqlite_storage_is_native_pinned_and_included_in_actual_projection() {
    let root = tempfile::tempdir().unwrap();
    let mut request = request(root.path(), "http://127.0.0.1:9191/v1");
    let first = seal(&mut request).await;
    let config = first.load_config(&Default::default(), None).unwrap();
    assert_eq!(config.sqlite.home(), root.path().join("sqlite"));
    assert!(first.configuration.contains("sqlite_home"));
    request["runtime"]["sqliteHome"] = json!(root.path().join("sqlite-other"));
    request["template"]["runtime"] = request["runtime"].clone();
    rehash(&mut request);
    assert!(materialize_worker_launch(&request).await.is_err());
    let second = project_worker_launch(&request).await.unwrap();
    assert_ne!(first.receipt["projection"]["executionSha256"], second.receipt["projection"]["executionSha256"]);
    assert_ne!(first.receipt["configSha256"], second.receipt["configSha256"]);
}

#[test]
fn sqlite_environment_does_not_redirect_sealed_native_storage() {
    let root = tempfile::tempdir().unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "worker_launch_config::tests::sqlite_environment_child", "--ignored"])
        .env("CODEX_SQLITE_HOME", root.path().join("ambient-sqlite"))
        .env("CODEX_SQLITE_HOME_TEST_ROOT", root.path())
        .status().unwrap();
    assert!(status.success());
    assert_eq!(std::fs::read_to_string(root.path().join("sqlite-child-receipt")).unwrap(), "pinned");
    assert!(!root.path().join("ambient-sqlite").exists());
}

#[tokio::test]
#[ignore = "run only by isolated environment parent fixture"]
async fn sqlite_environment_child() {
    let Some(root) = std::env::var_os("CODEX_SQLITE_HOME_TEST_ROOT") else { return; };
    let root = std::path::PathBuf::from(root);
    let mut request = request(&root, "http://127.0.0.1:9191/v1");
    let loaded = seal(&mut request).await;
    assert_eq!(loaded.load_config(&Default::default(), None).unwrap().sqlite.home(), root.join("sqlite"));
    std::fs::write(root.join("sqlite-child-receipt"), "pinned").unwrap();
}
