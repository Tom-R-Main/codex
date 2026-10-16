use super::*;
use pretty_assertions::assert_eq;
use serde_json::json;

fn policy_json() -> serde_json::Value {
    json!({
        "version": 1, "launchId": "controller-launch-nonce",
        "incarnationId":"controller-process-nonce", "bindingSha256":"c".repeat(64),
        "executorProtocolVersion":"sift-worker-executor-v1", "server": "sift-worker", "namespace": "mcp__sift_worker",
        "tool": "execute", "rawTool": "execute", "endpoint": "http://127.0.0.1:9000/mcp",
        "serverConfigSha256": "a".repeat(64), "model": "worker-model",
        "modelProviderId":"test-provider", "modelProviderSha256":"b".repeat(64)
    })
}

fn policy() -> WorkerPolicy {
    serde_json::from_value(policy_json()).unwrap()
}

#[test]
fn restricted_launch_rejects_missing_or_unsupported_policy() {
    let valid = policy_json().to_string();
    assert!(parse_launch(None, None).unwrap().is_none());
    assert!(parse_launch(Some("1"), Some(&valid)).unwrap().is_some());
    for (marker, body) in [
        (Some("1"), None), (None, Some(valid.as_str())),
        (Some("0"), Some(valid.as_str())), (Some("1"), Some("{}")),
        (Some("1"), Some("not json")),
    ] {
        assert!(parse_launch(marker, body).is_err());
    }
    for (key, value) in [
        ("version", json!(2)), ("tool", json!("")),
        ("bindingSha256", json!("")), ("incarnationId", json!("")),
        ("executorProtocolVersion", json!("unknown")),
        ("namespace", json!("functions")), ("serverConfigSha256", json!("A".repeat(64))),
        ("serverConfigSha256", json!("a".repeat(63))),
        ("endpoint", json!("file:///tmp/executor")),
        ("endpoint", json!("http://token@localhost/mcp")),
        ("endpoint", json!("http://localhost/mcp?credential=opaque")),
        ("unrecognized", json!(true)),
    ] {
        let mut invalid = policy_json();
        invalid[key] = value;
        assert!(parse_launch(Some("1"), Some(&invalid.to_string())).is_err(), "{key}");
    }
    assert!(parse_launch(Some("1"), Some(&" ".repeat(8193))).is_err());
}

#[test]
fn exact_executor_identity_refuses_native_alias_and_dynamic_impersonation() {
    let policy = policy();
    let exact = ToolName::namespaced("mcp__sift_worker", "execute");
    assert!(policy.allows(&exact, Some("sift-worker")));
    for (name, server) in [
        (exact.clone(), None), // A dynamic tool with the same name is not MCP-backed.
        (exact.clone(), Some("another-server")),
        (ToolName::plain("execute"), Some("sift-worker")),
        (ToolName::namespaced("mcp__sift_worker", "execute_extra"), Some("sift-worker")),
        (ToolName::plain("shell"), None),
        (ToolName::plain("exec_command"), None),
        (ToolName::plain("write_stdin"), None),
        (ToolName::plain("apply_patch"), None),
        (ToolName::plain("view_image"), None),
        (ToolName::namespaced("collaboration", "spawn_agent"), None),
        (ToolName::plain("exec"), None),
        (ToolName::plain("wait"), None),
    ] {
        assert!(!policy.allows(&name, server), "{name}");
    }
}

#[test]
fn canonical_digest_binds_nested_values_without_exposing_them() {
    let first = json!({"z":[{"b":2,"a":1}], "a":"opaque"});
    let second: serde_json::Value = serde_json::from_str(r#"{"a":"opaque","z":[{"a":1,"b":2}]}"#).unwrap();
    assert_eq!(digest(&first).unwrap(), digest(&second).unwrap());
    assert_ne!(digest(&first).unwrap(), digest(&json!({"z":[{"b":3,"a":1}],"a":"opaque"})).unwrap());
    assert_eq!(digest(&first).unwrap().len(), 64);
}

#[test]
fn same_alias_cannot_replace_transport_or_run_a_headers_helper() {
    let config: McpServerConfig = toml::from_str("url = 'http://127.0.0.1:9000/mcp'").unwrap();
    let mut policy = policy();
    policy.server_config_sha256 = digest(&config).unwrap();
    assert!(policy.server_matches("sift-worker", &config));
    assert!(!policy.server_matches("other", &config));
    let other: McpServerConfig = toml::from_str("url = 'http://127.0.0.1:9001/mcp'").unwrap();
    assert!(!policy.server_matches("sift-worker", &other));
    let helper: McpServerConfig = toml::from_str("url = 'http://127.0.0.1:9000/mcp'\nhttp_headers_helper = 'touch /tmp/must-not-run'").unwrap();
    policy.server_config_sha256 = digest(&helper).unwrap();
    assert!(!policy.server_matches("sift-worker", &helper));
    let stdio: McpServerConfig = toml::from_str("command = '/tmp/must-not-run'").unwrap();
    policy.server_config_sha256 = digest(&stdio).unwrap();
    assert!(!policy.server_matches("sift-worker", &stdio));
}

#[test]
fn isolated_process_enforces_the_real_registry_and_rpc_surface() {
    let directory = tempfile::tempdir().unwrap();
    let receipt = directory.path().join("receipt");
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "worker_policy::tests::isolated_dispatch_child", "--ignored"])
        .env("CODEX_WORKER_POLICY_TEST_RECEIPT", &receipt)
        .env("CODEX_RESTRICTED_WORKER", "1")
        .env("CODEX_WORKER_POLICY_V1", policy_json().to_string())
        .env("CODEX_WORKER_POLICY_TEST_CHILD", "1")
        .status().unwrap();
    assert!(status.success());
    assert_eq!(std::fs::read_to_string(receipt).unwrap(), "dispatch-enforced");
}

struct CountingRuntime {
    name: ToolName,
    server: Option<String>,
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl crate::tools::registry::ToolExecutor<crate::tools::context::ToolInvocation> for CountingRuntime {
    fn tool_name(&self) -> ToolName { self.name.clone() }

    fn spec(&self) -> codex_tools::ToolSpec {
        codex_tools::ToolSpec::Function(codex_tools::ResponsesApiTool {
            name: self.name.name.clone(), description: "test".to_string(),
            strict: false, defer_loading: None, parameters: codex_tools::JsonSchema::default(), output_schema: None,
        })
    }

    fn handle<'a>(&'a self, _invocation: crate::tools::context::ToolInvocation) -> codex_tools::ToolExecutorFuture<'a>
    where crate::tools::context::ToolInvocation: 'a,
    {
        Box::pin(async move {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Box::new(crate::tools::context::FunctionToolOutput::from_text("ok".to_string(), Some(true)))
                as Box<dyn crate::tools::context::ToolOutput>)
        })
    }
}

impl crate::tools::registry::CoreToolRuntime for CountingRuntime {
    fn mcp_server_name(&self) -> Option<&str> { self.server.as_deref() }
}

#[tokio::test]
#[ignore = "run in an isolated process by the parent test"]
async fn isolated_dispatch_child() {
    if std::env::var_os("CODEX_WORKER_POLICY_TEST_CHILD").is_none() { return; }
    initialize_worker_policy().unwrap();
    for method in ["command/exec", "thread/shellCommand", "mcpServer/tool/call", "fs/writeFile",
        "fs/remove", "config/value/write", "plugin/install", "environment/create", "future/unknown"] {
        assert!(!worker_rpc_allowed(method), "{method}");
    }
    assert!(worker_rpc_allowed("turn/start"));
    assert!(worker_rpc_allowed("workerPolicy/read"));
    assert!(record_registry("registry-test".to_owned(), "worker-model", vec![]).is_err());
    let allowed_tool = ToolName::namespaced("mcp__sift_worker", "execute");
    assert!(record_registry("registry-test".to_owned(), "worker-model", vec![
        (allowed_tool, Some("sift-worker".to_owned())),
    ]).is_ok());
    let readback = read_worker_policy("registry-test", "fresh-challenge");
    assert_eq!(readback["challenge"], "fresh-challenge");
    assert_eq!(readback["incarnationId"], "controller-process-nonce");
    assert_eq!(readback["coverageComplete"], false);
    assert!(readback["configSha256"].is_null());
    assert_eq!(read_worker_policy("registry-test", "")["ready"], false);
    assert!(executor_request_meta("not-registered", "turn-1", "call-1", &None, None).is_err());
    assert!(executor_request_meta("registry-test", "turn-1", "call-1", &None, None).is_ok());
    for input in [
        json!({"type":"text","text":"task","text_elements":[]}),
        json!({"type":"localImage","path":"/path/must-not-be-read"}),
        json!({"type":"localAudio","path":"/path/must-not-be-read"}),
        json!({"type":"image","url":"https://example.invalid/image.png"}),
        json!({"type":"audio","url":"https://example.invalid/audio"}),
        json!({"type":"skill","name":"untrusted","path":"/path/must-not-be-read"}),
        json!({"type":"mention","name":"untrusted","path":"plugin://untrusted"}),
    ] {
        let request: codex_app_server_protocol::ClientRequest = serde_json::from_value(json!({
            "method":"turn/start","id":1,"params":{"threadId":"test-thread","input":[input.clone()]}
        })).unwrap();
        assert_eq!(worker_request_allowed(&request), input["type"] == "text");
    }
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    // A fresh/default per-thread ToolPolicy cannot widen the process ceiling.
    let mut registry = crate::tools::registry::ToolRegistry::with_tool_policy(Default::default());
    let allowed = ToolName::namespaced("mcp__sift_worker", "execute");
    for (name, server) in [(ToolName::plain("shell"), None), (allowed.clone(), None),
        (ToolName::plain("apply_patch"), None), (ToolName::plain("exec"), None),
        (ToolName::namespaced("collaboration", "spawn_agent"), None),
        (allowed.clone(), Some("sift-worker".to_string()))] {
        registry.add_with_exposure(CountingRuntime { name, server, calls: calls.clone() }, codex_tools::ToolExposure::Hidden);
    }
    assert_eq!(registry.tool_names_for_test(), vec![allowed.clone()]);
    let (session, turn) = crate::session::tests::make_session_and_context().await;
    let session = std::sync::Arc::new(session);
    let turn = std::sync::Arc::new(turn);
    // A default context cannot turn the protected preflight into inference or
    // silently replace the launch-bound model/provider/executor configuration.
    assert!(session.prepare_restricted_worker_registry(&tokio_util::sync::CancellationToken::new())
        .await.is_err());
    assert_eq!(read_worker_policy(&session.thread_id.to_string(), "after-rejection")["ready"], false);
    for name in [ToolName::plain("shell"), allowed] {
        let step_context = crate::session::step_context::StepContext::for_test(turn.clone());
        let invocation = crate::tools::context::ToolInvocation {
            session: session.clone(), step_context, turn: turn.clone(),
            cancellation_token: tokio_util::sync::CancellationToken::new(),
            tracker: std::sync::Arc::new(tokio::sync::Mutex::new(crate::turn_diff_tracker::TurnDiffTracker::new())),
            call_id: name.to_string(), tool_name: name.clone(), source: crate::tools::context::ToolCallSource::Direct,
            payload: crate::tools::context::ToolPayload::Function { arguments: "{}".to_string() },
        };
        let result = registry.dispatch_any_with_state(invocation, /*call_state*/ None).await;
        assert_eq!(result.is_ok(), name.name == "execute");
    }
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    std::fs::write(std::env::var_os("CODEX_WORKER_POLICY_TEST_RECEIPT").unwrap(), "dispatch-enforced").unwrap();
}

#[test]
fn provider_replacement_and_command_auth_refuse_even_with_the_same_model() {
    let mut policy = policy();
    let mut provider = codex_model_provider_info::ModelProviderInfo::default();
    provider.base_url = Some("http://127.0.0.1:9000/responses".to_string());
    policy.model_provider_sha256 = digest(&provider).unwrap();
    assert!(policy.provider_matches("test-provider", &provider));
    assert!(!policy.provider_matches("replacement", &provider));
    provider.base_url = Some("http://127.0.0.1:9001/responses".to_string());
    assert!(!policy.provider_matches("test-provider", &provider));
    let command: codex_model_provider_info::ModelProviderInfo = toml::from_str(
        "name='worker'\nbase_url='http://127.0.0.1:9000/responses'\n[auth]\ncommand='/tmp/must-not-run'\nargs=[]"
    ).unwrap();
    policy.model_provider_sha256 = digest(&command).unwrap();
    assert!(!policy.provider_matches("test-provider", &command));
}

#[test]
fn executor_metadata_binds_exact_arguments_and_native_invocation_without_changing_them() {
    let arguments = Some(json!({"argv":["printf","a b"],"nested":{"b":2,"a":1}}));
    let original = arguments.clone();
    let meta = executor_meta(&policy(), "thread-1", "turn-1", "call-1", &arguments,
        Some(json!({"other":"retained"}))).unwrap();
    assert_eq!(arguments, original);
    assert_eq!(meta, json!({
        "other":"retained",
        "siftWorkerExecutor": {
            "version":1,"protocol":"sift-worker-executor-v1",
            "launchId":"controller-launch-nonce", "incarnationId":"controller-process-nonce",
            "bindingSha256":"c".repeat(64), "threadId":"thread-1", "turnId":"turn-1",
            "callId":"call-1", "argumentsSha256":digest(&arguments).unwrap(),
        }
    }));
    let changed_arguments = Some(json!({"argv":["printf","a","b"],"nested":{"a":1,"b":2}}));
    let changed = executor_meta(&policy(), "thread-1", "turn-1", "call-1", &changed_arguments, None).unwrap();
    assert_ne!(meta["siftWorkerExecutor"]["argumentsSha256"], changed["siftWorkerExecutor"]["argumentsSha256"]);
    let mut restarted = policy();
    restarted.incarnation_id = "new-process".to_owned();
    assert_ne!(meta["siftWorkerExecutor"], executor_meta(&restarted,
        "thread-1", "turn-1", "call-1", &arguments, None).unwrap()["siftWorkerExecutor"]);
}

#[test]
fn executor_identity_rejects_spoofed_or_invalid_metadata() {
    for supplied in [Some(json!(true)), Some(json!({"siftWorkerExecutor":{"callId":"spoof"}}))] {
        assert!(executor_meta(&policy(), "thread-1", "turn-1", "call-1", &None, supplied).is_err());
    }
    for (thread, turn, call) in [("", "turn", "call"), ("thread", "", "call"), ("thread", "turn", "bad\0call")] {
        assert!(executor_meta(&policy(), thread, turn, call, &None, None).is_err());
    }
    let absent = executor_meta(&policy(), "thread", "turn", "call", &None, None).unwrap();
    let empty = executor_meta(&policy(), "thread", "turn", "call", &Some(json!({})), None).unwrap();
    assert_ne!(absent["siftWorkerExecutor"]["argumentsSha256"], empty["siftWorkerExecutor"]["argumentsSha256"]);
}

#[test]
fn executor_digest_refuses_cross_language_number_and_structural_ambiguity() {
    for arguments in [json!({"value":1.0}), json!({"value":9007199254740992_u64}), json!(["x".repeat(262145)])] {
        assert!(executor_meta(&policy(), "thread", "turn", "call", &Some(arguments), None).is_err());
    }
    assert!(executor_meta(&policy(), "thread", "turn", "call",
        &Some(json!({"max":9007199254740991_u64,"min":-9007199254740991_i64})), None).is_ok());
    let mut deep = json!(null);
    for _ in 0..66 { deep = json!([deep]); }
    assert!(executor_meta(&policy(), "thread", "turn", "call", &Some(deep), None).is_err());
}

#[test]
fn model_argument_identity_does_not_replace_transport_identity() {
    let arguments = Some(json!({"siftWorkerExecutor":{
        "launchId":"model-spoof", "incarnationId":"model-spoof", "threadId":"model-spoof"
    }}));
    let meta = executor_meta(&policy(), "actual-thread", "actual-turn", "actual-call", &arguments, None).unwrap();
    assert_eq!(meta["siftWorkerExecutor"]["launchId"], "controller-launch-nonce");
    assert_eq!(meta["siftWorkerExecutor"]["threadId"], "actual-thread");
    assert_eq!(arguments.unwrap()["siftWorkerExecutor"]["threadId"], "model-spoof");
}
