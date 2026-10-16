//! Process ceiling for controller-launched workers. This is independent of thread config.

use codex_config::McpServerConfig;
use codex_config::McpServerTransportConfig;
use codex_mcp::McpServerSource;
use codex_mcp::ResolvedMcpCatalog;
use codex_tools::ToolName;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::OnceLock;

const UPSTREAM_REVISION: &str = "36650394c5b38c2990ccf2a3457165ca3e9d9726";
static LAUNCH: OnceLock<Result<Option<WorkerPolicy>, String>> = OnceLock::new();
static REGISTRIES: Mutex<BTreeMap<String, serde_json::Value>> = Mutex::new(BTreeMap::new());

/// Only the trusted launcher supplies this value, before any thread or config loading.
/// The worker workspace must not contain its launch environment, binary or controller.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WorkerPolicy {
    version: u32,
    launch_id: String,
    incarnation_id: String,
    binding_sha256: String,
    executor_protocol_version: String,
    server: String,
    namespace: String,
    tool: String,
    raw_tool: String,
    endpoint: String,
    server_config_sha256: String,
    config_schema_version: String,
    config_sha256: String,
    model: String,
    model_provider_id: String,
    model_provider_sha256: String,
}

fn parse_launch(marker: Option<&str>, json: Option<&str>) -> Result<Option<WorkerPolicy>, String> {
    match (marker, json) {
        (None, None) => Ok(None),
        (Some("1"), Some(json)) if json.len() <= 8192 => {
            let policy: WorkerPolicy = serde_json::from_str(json)
                .map_err(|_| "invalid restricted worker policy".to_string())?;
            let endpoint = url::Url::parse(&policy.endpoint)
                .map_err(|_| "invalid worker endpoint".to_string())?;
            if policy.version != 1
                || policy.config_schema_version != crate::worker_policy_config::CONFIG_SCHEMA_VERSION
                || policy.executor_protocol_version != "sift-worker-executor-v1"
                || [&policy.launch_id, &policy.incarnation_id, &policy.server, &policy.namespace, &policy.tool, &policy.raw_tool, &policy.model, &policy.model_provider_id]
                    .into_iter().any(|s| s.is_empty() || s.len() > 256 || s.chars().any(char::is_control))
                || policy.namespace == codex_protocol::DEFAULT_FUNCTION_NAMESPACE
                || [&policy.binding_sha256, &policy.server_config_sha256, &policy.model_provider_sha256, &policy.config_sha256].into_iter().any(|value| value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
                || !matches!(endpoint.scheme(), "http" | "https")
                || !endpoint.username().is_empty() || endpoint.password().is_some()
                || endpoint.query().is_some() || endpoint.fragment().is_some()
            {
                return Err("unsupported restricted worker policy".to_string());
            }
            Ok(Some(policy))
        }
        _ => Err("restricted worker launch requires marker 1 and a valid policy".to_string()),
    }
}

fn launch() -> &'static Result<Option<WorkerPolicy>, String> {
    LAUNCH.get_or_init(|| {
        let marker = std::env::var("CODEX_RESTRICTED_WORKER");
        let json = std::env::var("CODEX_WORKER_POLICY_V1");
        if matches!(marker, Err(std::env::VarError::NotUnicode(_)))
            || matches!(json, Err(std::env::VarError::NotUnicode(_)))
        {
            return Err("worker launch environment must be UTF-8".to_string());
        }
        parse_launch(marker.as_deref().ok(), json.as_deref().ok())
    })
}

/// Capture before loading app-server configuration. Malformed restricted launches fail closed.
pub fn initialize_worker_policy() -> std::io::Result<()> {
    launch().as_ref().map(|_| ()).map_err(|error| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, error.clone())
    })
}

/// Bind the private bootstrap to the already-captured immutable process launch.
pub fn validate_worker_bootstrap_identity(request: &serde_json::Value) -> std::io::Result<()> {
    initialize_worker_policy()?;
    let Ok(Some(policy)) = launch() else { return Err(crate::worker_launch_config::worker_materialization_error()); };
    if policy.bootstrap_matches(request) { Ok(()) }
    else { Err(crate::worker_launch_config::worker_materialization_error()) }
}

/// Validate before session startup side effects, and again for every resumed thread.
pub fn validate_worker_config(config: &crate::config::Config) -> std::io::Result<()> {
    initialize_worker_policy()?;
    let Ok(Some(policy)) = launch() else { return Ok(()); };
    policy.validate_config(config)
}

pub(crate) fn validate_worker_model(model: &str) -> std::io::Result<()> {
    initialize_worker_policy()?;
    if let Ok(Some(policy)) = launch()
        && model != policy.model
    {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied,
            "worker effective model violates protected launch policy"));
    }
    Ok(())
}

impl WorkerPolicy {
    fn bootstrap_matches(&self, request: &serde_json::Value) -> bool {
        let input = &request["input"];
        input["launchId"].as_str() == Some(self.launch_id.as_str())
            && input["incarnationId"].as_str() == Some(self.incarnation_id.as_str())
            && input["bindingSha256"].as_str() == Some(self.binding_sha256.as_str())
            && input["endpoint"].as_str() == Some(self.endpoint.as_str())
            && request["configSha256"].as_str() == Some(self.config_sha256.as_str())
            && request["template"]["server"].as_str() == Some(self.server.as_str())
    }

    fn validate_config(&self, config: &crate::config::Config) -> std::io::Result<()> {
        let policy = self;
        let features = [codex_features::Feature::Plugins, codex_features::Feature::Apps,
            codex_features::Feature::CodexHooks, codex_features::Feature::CodeMode,
            codex_features::Feature::CodeModeOnly, codex_features::Feature::CodeModePrewarm, codex_features::Feature::CodeModeHost,
            codex_features::Feature::ShellSnapshot, codex_features::Feature::ShellSnapshotV2];
        if config.notify.is_some() || features.into_iter().any(|feature| config.features.enabled(feature))
            || config.model.as_deref() != Some(policy.model.as_str())
            || !policy.provider_matches(&config.model_provider_id, &config.model_provider)
            || config.mcp_servers.get().len() != 1
            || !config.mcp_servers.get().get(&policy.server).is_some_and(|server| policy.server_matches(&policy.server, server))
            || crate::worker_policy_config::effective_config_sha256(config)
                .map_err(std::io::Error::other)? != policy.config_sha256
        {
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied,
                "worker configuration violates protected launch policy"));
        }
        Ok(())
    }
}

/// Whether a process-wide ceiling forbids ordinary host effects.
pub fn worker_is_restricted() -> bool { restricted() }

pub(crate) fn restricted() -> bool {
    !matches!(launch(), Ok(None))
}

/// Restricted clients get a deliberately narrow control plane, never arbitrary host RPC effects.
pub fn worker_rpc_allowed(method: &str) -> bool {
    !restricted() || matches!(method,
        "initialize" | "workerPolicy/read" | "thread/start" | "thread/resume"
        | "thread/read" | "thread/list" | "thread/loaded/list" | "thread/unsubscribe"
        | "turn/start" | "turn/steer" | "turn/interrupt")
}

pub(crate) fn text_input_only(input: &[codex_protocol::user_input::UserInput]) -> bool {
    input.iter().all(|item| matches!(item, codex_protocol::user_input::UserInput::Text { .. }))
}

/// Validate typed input before attachment reads, environment selection or skill expansion.
pub fn worker_request_allowed(request: &codex_app_server_protocol::ClientRequest) -> bool {
    if !restricted() { return true; }
    if !worker_rpc_allowed(request.method_name()) { return false; }
    let text_only = |input: &[codex_app_server_protocol::UserInput]| input.iter()
        .all(|item| matches!(item, codex_app_server_protocol::UserInput::Text { .. }));
    match request {
        codex_app_server_protocol::ClientRequest::TurnStart { params, .. } =>
            text_only(&params.input) && params.tool_output.is_none() && params.additional_context.is_none()
            && params.environments.is_none() && params.runtime_workspace_roots.is_none()
            && params.cwd.is_none() && params.model.is_none() && params.collaboration_mode.is_none()
            && params.approval_policy.is_none() && params.approvals_reviewer.is_none()
            && params.sandbox_policy.is_none() && params.permissions.is_none()
            && params.service_tier.is_none() && params.service_tier_for_turn.is_none()
            && params.effort.is_none() && params.summary.is_none() && params.personality.is_none()
            && params.disabled_plugin_ids.is_none() && params.output_schema.is_none()
            && params.cyber_access_program.is_none() && params.multi_agent_mode.is_none(),
        codex_app_server_protocol::ClientRequest::TurnSteer { params, .. } =>
            text_only(&params.input) && params.additional_context.is_none(),
        codex_app_server_protocol::ClientRequest::ThreadStart { params, .. } =>
            params.environments.is_none() && params.dynamic_tools.is_none() && params.config.is_none()
            && params.runtime_workspace_roots.is_none(),
        codex_app_server_protocol::ClientRequest::ThreadResume { params, .. } =>
            params.path.is_none() && params.history.is_none() && params.config.is_none()
            && params.runtime_workspace_roots.is_none(),
        _ => true, // Method allowlist above denies all unknown/future operations.
    }
}

/// The restricted worker's launch configuration is immutable for its lifetime.
/// Exhaustive patterns make future settings additions require an explicit choice.
pub(crate) fn settings_update_allowed(updates: &crate::session::SessionSettingsUpdate) -> bool {
    if !restricted() { return true; }
    let crate::session::SessionSettingsUpdate {
        step_settings, environments, runtime_workspace_roots, profile_workspace_roots,
        sandbox_policy, permission_profile, active_permission_profile, windows_sandbox_level,
        service_tier_for_turn, disabled_plugin_ids,
        app_server_client_name: _, app_server_client_version: _,
    } = updates;
    let crate::session::step_settings::StepSettingsUpdate {
        model, effort, collaboration_mode, reasoning_summary, service_tier,
        personality, approval_policy, approvals_reviewer,
    } = step_settings;
    model.is_none() && effort.is_none() && collaboration_mode.is_none()
        && reasoning_summary.is_none() && service_tier.is_none() && personality.is_none()
        && approval_policy.is_none() && approvals_reviewer.is_none()
        && environments.is_none() && runtime_workspace_roots.is_none() && profile_workspace_roots.is_none()
        && sandbox_policy.is_none() && permission_profile.is_none() && active_permission_profile.is_none()
        && windows_sandbox_level.is_none() && service_tier_for_turn.is_none() && disabled_plugin_ids.is_none()
}

pub(crate) fn digest(value: &impl Serialize) -> Result<String, serde_json::Error> {
    fn canonical(value: serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(object) => serde_json::Value::Object(
                object.into_iter().map(|(k, v)| (k, canonical(v)))
                    .collect::<BTreeMap<_, _>>().into_iter().collect()),
            serde_json::Value::Array(items) => serde_json::Value::Array(items.into_iter().map(canonical).collect()),
            value => value,
        }
    }
    let bytes = serde_json::to_vec(&canonical(serde_json::to_value(value)?))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

impl WorkerPolicy {
    fn provider_matches(&self, id: &str, provider: &codex_model_provider_info::ModelProviderInfo) -> bool {
        id == self.model_provider_id && !provider.has_command_auth()
            && provider.aws.is_none() && provider.gateway_oauth.is_none()
            && digest(provider).is_ok_and(|actual| actual == self.model_provider_sha256)
    }

    fn allows(&self, name: &ToolName, server: Option<&str>) -> bool {
        server == Some(self.server.as_str())
            && name.clone().with_default_namespace() == ToolName::namespaced(&self.namespace, &self.tool)
    }

    fn server_matches(&self, name: &str, config: &McpServerConfig) -> bool {
        name == self.server && config.enabled && config.is_local_environment()
            && matches!(&config.transport, McpServerTransportConfig::StreamableHttp {
                url, http_headers_helper: None, ..
            } if url == &self.endpoint)
            && digest(config).is_ok_and(|actual| actual == self.server_config_sha256)
    }
}

pub(crate) fn allows_tool(name: &ToolName, server: Option<&str>) -> bool {
    match launch() {
        Ok(None) => true,
        Ok(Some(policy)) => policy.allows(name, server),
        Err(_) => false,
    }
}

/// Apply after *all* catalog contributions, before any client/helper/stdio startup.
pub(crate) fn restrict_catalog(catalog: &ResolvedMcpCatalog) -> ResolvedMcpCatalog {
    if !restricted() { return catalog.clone(); }
    let mut builder = ResolvedMcpCatalog::builder();
    if let Ok(Some(policy)) = launch()
        && let Some(server) = catalog.server(&policy.server)
        && matches!(server.source(), McpServerSource::Config)
        && policy.server_matches(&policy.server, server.config())
    {
        builder.register(codex_mcp::McpServerRegistration::from_config(policy.server.clone(), server.config().clone()));
    }
    builder.build()
}

pub(crate) fn prepared_call_allowed(call: &codex_mcp::PreparedMcpCall) -> bool {
    match launch() {
        Ok(None) => true,
        Ok(Some(policy)) => call.config().mcp_server_catalog.server(&policy.server)
            .is_some_and(|server| matches!(server.source(), McpServerSource::Config)
                && policy.server_matches(call.server_name(), server.config()))
            && policy.allows(&call.tool_info().canonical_tool_name(), Some(call.server_name()))
            && call.tool_info().tool.name.to_string() == policy.raw_tool,
        Err(_) => false,
    }
}

pub(crate) fn record_registry(thread: String, model: &str, config: &crate::config::Config, inventory: Vec<(ToolName, Option<String>)>) -> Result<(), String> {
    let Ok(Some(policy)) = launch() else { return Ok(()); };
    invalidate_registry(&thread)?;
    policy.validate_config(config).map_err(|_| "worker effective configuration violates launch policy")?;
    validate_worker_model(model).map_err(|_| "worker effective model violates launch policy")?;
    if inventory.len() != 1 || inventory.iter().any(|(name, server)| !policy.allows(name, server.as_deref())) {
        return Err("worker registry or model violates launch policy".to_string());
    }
    let mut inventory = inventory.into_iter().map(|(name, server)| {
        (name.namespace.unwrap_or_else(|| codex_protocol::DEFAULT_FUNCTION_NAMESPACE.to_string()), name.name, server)
    }).collect::<Vec<_>>();
    inventory.sort();
    let attestation = serde_json::json!({
        "version": 1, "coverageComplete": false, "threadId": thread,
        "launchId": policy.launch_id, "processId": std::process::id(),
        "incarnationId": policy.incarnation_id, "bindingSha256": policy.binding_sha256,
        "executorProtocolVersion": policy.executor_protocol_version,
        "upstreamRevision": UPSTREAM_REVISION,
        "buildRevision": option_env!("CODEX_BUILD_SOURCE_REVISION"),
        "policySha256": digest(policy).map_err(|_| "policy digest failed")?,
        "registrySha256": digest(&inventory).map_err(|_| "registry digest failed")?,
        "serverConfigSha256": policy.server_config_sha256,
        "configSchemaVersion": crate::worker_policy_config::CONFIG_SCHEMA_VERSION,
        "configSha256": crate::worker_policy_config::effective_config_sha256(config)?, "model": model,
        "modelProviderSha256": policy.model_provider_sha256, "modelProviderId": policy.model_provider_id,
        "executableRegistry": inventory,
        "remaining": ["trusted-image-build-binding", "external-state-config-binding", "alternate-effect-qualification", "controller-handshake"]
    });
    let mut registries = REGISTRIES.lock().map_err(|_| "worker registry state unavailable")?;
    if !registries.contains_key(&thread) && registries.len() >= 64 {
        return Err("worker attestation capacity exceeded".to_string());
    }
    registries.insert(thread, attestation);
    Ok(())
}

/// Content-bounded evidence from actual router construction, not model-visible schemas.
pub fn read_worker_policy(thread: &str, challenge: &str) -> serde_json::Value {
    if !valid_identity(challenge) || !valid_identity(thread) {
        return serde_json::json!({"version":1,"coverageComplete":false,"ready":false});
    }
    let mut attestation = REGISTRIES.lock().ok().and_then(|registries| registries.get(thread).cloned())
        .unwrap_or_else(|| serde_json::json!({"version":1,"coverageComplete":false,"ready":false}));
    attestation["challenge"] = serde_json::json!(challenge);
    attestation
}

pub(crate) fn invalidate_registry(thread: &str) -> Result<(), String> {
    REGISTRIES.lock().map_err(|_| "worker registry state unavailable")?.remove(thread);
    Ok(())
}

pub(crate) fn preflight_server() -> Result<String, String> {
    match launch() {
        Ok(Some(policy)) => Ok(policy.server.clone()),
        Ok(None) => Err("worker preparation requires a protected launch".to_owned()),
        Err(error) => Err(error.clone()),
    }
}

pub(crate) fn valid_read_request(thread: &str, challenge: &str) -> bool {
    valid_identity(thread) && valid_identity(challenge)
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

/// Native identity is carried outside model-supplied arguments on the sealed MCP transport.
/// The executor must authenticate that transport and durably reserve this exact identity
/// before effects. This metadata alone is not a human decision or an execution grant.
pub(crate) fn executor_request_meta(
    thread: &str,
    turn: &str,
    call: &str,
    arguments: &Option<serde_json::Value>,
    meta: Option<serde_json::Value>,
) -> Result<Option<serde_json::Value>, String> {
    match launch() {
        Ok(None) => Ok(meta),
        Ok(Some(policy)) => {
            if !REGISTRIES.lock().map_err(|_| "worker registry state unavailable")?.contains_key(thread) {
                return Err("worker registry handshake unavailable".to_string());
            }
            executor_meta(policy, thread, turn, call, arguments, meta).map(Some)
        }
        Err(error) => Err(error.clone()),
    }
}

fn executor_meta(
    policy: &WorkerPolicy,
    thread: &str,
    turn: &str,
    call: &str,
    arguments: &Option<serde_json::Value>,
    meta: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    if ![thread, turn, call].into_iter().all(valid_identity) {
        return Err("worker execution identity invalid".to_string());
    }
    validate_executor_arguments(arguments)?;
    let mut meta = match meta {
        None => serde_json::Map::new(),
        Some(serde_json::Value::Object(meta)) => meta,
        Some(_) => return Err("worker request metadata must be an object".to_string()),
    };
    if meta.contains_key("siftWorkerExecutor") {
        return Err("worker execution identity already supplied".to_string());
    }
    meta.insert("siftWorkerExecutor".to_string(), serde_json::json!({
        "version": 1, "protocol": policy.executor_protocol_version,
        "launchId": policy.launch_id, "incarnationId": policy.incarnation_id,
        "bindingSha256": policy.binding_sha256, "threadId": thread, "turnId": turn,
        "callId": call, "argumentsSha256": digest(arguments).map_err(|_| "worker argument digest failed")?,
    }));
    Ok(serde_json::Value::Object(meta))
}

// Match the controller's JSON scalar semantics. Floating point or unsafe integers
// cannot receive a cross-language digest with a possibly different representation.
fn validate_executor_arguments(arguments: &Option<serde_json::Value>) -> Result<(), String> {
    let Some(arguments) = arguments else { return Ok(()); };
    let mut pending = vec![(arguments, 0_usize)];
    let mut visited = 0_usize;
    let mut scalar_bytes = 0_usize;
    while let Some((value, depth)) = pending.pop() {
        visited += 1;
        if depth > 64 || visited > 16_384 || pending.len() > 16_384 || scalar_bytes > 262_144 {
            return Err("worker arguments exceed structural bounds".to_owned());
        }
        match value {
            serde_json::Value::Number(number) => {
                let safe = number.as_i64().is_some_and(|value| value.unsigned_abs() <= 9_007_199_254_740_991)
                    || number.as_u64().is_some_and(|value| value <= 9_007_199_254_740_991);
                if !safe { return Err("worker arguments require exact JSON integers".to_owned()); }
            }
            serde_json::Value::Array(items) => {
                if items.len() > 16_384 { return Err("worker arguments exceed structural bounds".to_owned()); }
                pending.extend(items.iter().map(|item| (item, depth + 1)));
            }
            serde_json::Value::Object(fields) => {
                if fields.len() > 16_384 { return Err("worker arguments exceed structural bounds".to_owned()); }
                scalar_bytes = scalar_bytes.saturating_add(fields.keys().map(String::len).sum::<usize>());
                pending.extend(fields.values().map(|item| (item, depth + 1)));
            }
            serde_json::Value::String(value) => {
                scalar_bytes = scalar_bytes.saturating_add(value.len());
            }
            serde_json::Value::Null | serde_json::Value::Bool(_) => {}
        }
    }
    if scalar_bytes > 262_144
        || serde_json::to_vec(arguments).map_err(|_| "worker argument encoding failed")?.len() > 262_144 {
        return Err("worker arguments exceed byte limit".to_owned());
    }
    Ok(())
}

#[cfg(test)]
#[path = "worker_policy_tests.rs"]
mod tests;
