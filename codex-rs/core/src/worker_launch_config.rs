//! Native materialization shared by the controller helper and protected startup.
//! Secret-bearing requests have no Debug/Serialize implementation and must travel
//! only over the private bootstrap channel, never config files or diagnostics.

use crate::config::Config;
use crate::config::ConfigOverrides;
use crate::worker_policy::digest;
use crate::worker_policy_config::effective_config_projection;
use crate::worker_policy_config::effective_config_sha256;
use codex_config::ConfigLayerEntry;
use codex_config::ConfigLayerSource;
use codex_config::ConfigLayerStack;
use codex_config::McpServerConfig;
use codex_config::McpServerTransportConfig;
use codex_config::config_toml::ConfigToml;
use codex_config::types::AuthCredentialsStoreMode;
use codex_utils_absolute_path::AbsolutePathBuf;
use serde::Deserialize;
use serde_json::Value;
use serde_json::json;
use sha2::Digest;
use sha2::Sha256;
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::path::PathBuf;

pub const WORKER_MATERIALIZATION_MAX_BYTES: usize = 262_144;

#[derive(Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkerRuntimePaths {
    pub cwd: PathBuf,
    pub codex_home: PathBuf,
    pub sqlite_home: PathBuf,
    pub codex_self_exe: PathBuf,
    pub codex_linux_sandbox_exe: Option<PathBuf>,
    pub main_execve_wrapper_exe: Option<PathBuf>,
    pub zsh_path: Option<PathBuf>,
}

/// Loaded immutable typed state. Only `receipt` and `configuration` are safe to
/// serialize. `config` contains the transient MCP authorization header.
pub struct WorkerLaunchMaterialization {
    pub configuration: String,
    pub receipt: Value,
    pub runtime: WorkerRuntimePaths,
    config: Config,
}

pub fn worker_materialization_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "protected worker materialization refused",
    )
}

fn text<'a>(value: &'a Value, max: usize) -> io::Result<&'a str> {
    value
        .as_str()
        .filter(|text| !text.is_empty() && text.len() <= max && !text.contains('\0'))
        .ok_or_else(worker_materialization_error)
}

fn hash(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn exact_keys(value: &Value, keys: &[&str]) -> io::Result<()> {
    let object = value.as_object().ok_or_else(worker_materialization_error)?;
    if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
        return Err(worker_materialization_error());
    }
    Ok(())
}

impl WorkerRuntimePaths {
    fn validate(&self) -> io::Result<()> {
        for path in [
            Some(&self.cwd),
            Some(&self.codex_home),
            Some(&self.sqlite_home),
            Some(&self.codex_self_exe),
            self.codex_linux_sandbox_exe.as_ref(),
            self.main_execve_wrapper_exe.as_ref(),
            self.zsh_path.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            let value = path.to_str().ok_or_else(worker_materialization_error)?;
            if value.len() > 4096
                || !value.starts_with('/')
                || value.chars().any(char::is_control)
                || (value != "/"
                    && value[1..]
                        .split('/')
                        .any(|p| p.is_empty() || p == "." || p == ".."))
            {
                return Err(worker_materialization_error());
            }
        }
        Ok(())
    }

    /// Compare actual process identity paths before loading any configuration.
    pub fn matches_process(
        &self,
        cwd: &Path,
        codex_home: &Path,
        executable: Option<&Path>,
        sandbox: Option<&Path>,
        wrapper: Option<&Path>,
    ) -> bool {
        self.cwd == cwd
            && self.codex_home == codex_home
            && Some(self.codex_self_exe.as_path()) == executable
            && self.codex_linux_sandbox_exe.as_deref() == sandbox
            && self.main_execve_wrapper_exe.as_deref() == wrapper
    }
}

impl WorkerLaunchMaterialization {
    /// Compare behavioral state with the actual retained native configuration,
    /// without discovering ambient local/cloud requirements or credentials.
    pub fn validate_config(&self, current: &Config) -> io::Result<()> {
        let fail = worker_materialization_error;
        if effective_config_sha256(current).map_err(|_| fail())?
            != effective_config_sha256(&self.config).map_err(|_| fail())?
        {
            return Err(fail());
        }
        Ok(())
    }

    /// Thread/resume loads clone the same native loaded state, without reading
    /// ambient layers or re-installing authorization into serializable layers.
    pub fn load_config(
        &self,
        overrides: &ConfigOverrides,
        fallback_cwd: Option<&Path>,
    ) -> io::Result<Config> {
        let mut allowed = ConfigOverrides::default();
        allowed.model = overrides
            .model
            .clone()
            .filter(|value| Some(value) == self.config.model.as_ref());
        allowed.model_provider = overrides
            .model_provider
            .clone()
            .filter(|value| value == &self.config.model_provider_id);
        allowed.approval_policy = overrides
            .approval_policy
            .clone()
            .filter(|value| value == self.config.permissions.approval_policy.get());
        allowed.approvals_reviewer = overrides
            .approvals_reviewer
            .filter(|value| value == &self.config.approvals_reviewer);
        allowed.service_tier = overrides
            .service_tier
            .clone()
            .filter(|value| value == &self.config.service_tier);
        allowed.cwd = overrides.cwd.clone().filter(|cwd| cwd == &self.runtime.cwd);
        allowed.workspace_roots = overrides
            .workspace_roots
            .clone()
            .filter(|roots| roots == &self.config.workspace_roots);
        allowed.persisted_permission_profile_id = overrides
            .persisted_permission_profile_id
            .clone()
            .filter(|id| {
                self.config
                    .permissions
                    .active_permission_profile()
                    .is_some_and(|profile| &profile.id == id)
            });
        allowed.codex_self_exe = overrides
            .codex_self_exe
            .clone()
            .filter(|path| path == &self.runtime.codex_self_exe);
        allowed.codex_linux_sandbox_exe = overrides
            .codex_linux_sandbox_exe
            .clone()
            .filter(|path| Some(path) == self.runtime.codex_linux_sandbox_exe.as_ref());
        allowed.main_execve_wrapper_exe = overrides
            .main_execve_wrapper_exe
            .clone()
            .filter(|path| Some(path) == self.runtime.main_execve_wrapper_exe.as_ref());
        if &allowed != overrides || fallback_cwd.is_some_and(|cwd| cwd != self.runtime.cwd) {
            return Err(worker_materialization_error());
        }
        Ok(self.config.clone())
    }
}

fn reject_indirection(value: &toml::Value) -> io::Result<()> {
    match value {
        toml::Value::Table(table) => {
            for (key, value) in table {
                if [
                    "model_instructions_file",
                    "experimental_compact_prompt_file",
                    "model_catalog_json",
                    "config_file",
                    "http_headers",
                    "env_http_headers",
                    "http_headers_helper",
                    "bearer_token",
                    "bearer_token_env_var",
                    "experimental_bearer_token",
                    "env_key",
                    "auth",
                    "aws",
                    "gateway_oauth",
                    "model_catalog_url",
                    "notify",
                    "api_key",
                    "access_token",
                    "refresh_token",
                    "client_secret",
                    "password",
                ]
                .contains(&key.as_str())
                {
                    return Err(worker_materialization_error());
                }
                reject_indirection(value)?;
            }
        }
        toml::Value::Array(values) => {
            for value in values {
                reject_indirection(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Validate the request's native context before the actual typed constructor.
pub fn worker_request_runtime(request: &Value) -> io::Result<WorkerRuntimePaths> {
    exact_keys(
        &request["runtime"],
        &[
            "cwd",
            "codexHome",
            "sqliteHome",
            "codexSelfExe",
            "codexLinuxSandboxExe",
            "mainExecveWrapperExe",
            "zshPath",
        ],
    )?;
    let runtime: WorkerRuntimePaths = serde_json::from_value(request["runtime"].clone())
        .map_err(|_| worker_materialization_error())?;
    runtime.validate()?;
    Ok(runtime)
}

/// Derive every output hash from the actual loaded Config. Requested hashes are
/// checked only after native materialization; none are copied as observations.
pub async fn materialize_worker_launch(request: &Value) -> io::Result<WorkerLaunchMaterialization> {
    load_worker_launch(request, MaterializationPurpose::Verify).await
}

/// Controller-only projection creates no launch authority. Runtime startup never
/// uses this mode; it must compare the independently supplied launch expectation.
pub async fn project_worker_launch(request: &Value) -> io::Result<WorkerLaunchMaterialization> {
    load_worker_launch(request, MaterializationPurpose::Project).await
}

enum MaterializationPurpose {
    Project,
    Verify,
}

async fn load_worker_launch(
    request: &Value,
    purpose: MaterializationPurpose,
) -> io::Result<WorkerLaunchMaterialization> {
    let fail = worker_materialization_error;
    exact_keys(
        request,
        &[
            "version",
            "template",
            "input",
            "runtime",
            "serverConfig",
            "projection",
            "configSha256",
            "serverConfigSha256",
            "requestSha256",
        ],
    )?;
    let mut body = request.clone();
    body.as_object_mut()
        .ok_or_else(fail)?
        .remove("requestSha256");
    if request["version"] != 1
        || digest(&body).map_err(|_| fail())? != text(&request["requestSha256"], 64)?
    {
        return Err(fail());
    }
    let runtime = worker_request_runtime(request)?;
    let template = &request["template"];
    let input = &request["input"];
    let source = text(&template["template"], 65_536)?;
    let authorization = text(&input["authorization"], 128)?;
    if authorization.len() != 50
        || !authorization.starts_with("Bearer ")
        || !authorization[7..]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        || source.contains(&authorization[7..])
        || hash(source) != text(&template["templateSha256"], 64)?
        || hash(text(&input["baseConfiguration"], 65_536)?)
            != text(&template["baseConfigurationSha256"], 64)?
        || template["runtime"] != request["runtime"]
        || template["bindingSha256"] != input["bindingSha256"]
        || template["model"] != input["model"]
    {
        return Err(fail());
    }
    let server = text(&template["server"], 128)?;
    if !server
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(fail());
    }
    let mut server_config: McpServerConfig =
        serde_json::from_value(request["serverConfig"].clone()).map_err(|_| fail())?;
    let McpServerTransportConfig::StreamableHttp {
        url,
        http_headers: Some(headers),
        bearer_token_env_var: None,
        env_http_headers: None,
        http_headers_helper: None,
    } = &server_config.transport
    else {
        return Err(fail());
    };
    let endpoint = url::Url::parse(url).map_err(|_| fail())?;
    if url != text(&input["endpoint"], 256)?
        || endpoint.scheme() != "http"
        || endpoint.host_str() != Some("127.0.0.1")
        || endpoint.port().is_none()
        || endpoint.path() != "/mcp"
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || headers.len() != 1
        || headers.get("Authorization").map(String::as_str) != Some(authorization)
        || server_config.enabled_tools.as_deref() != Some(&["execute".to_string()][..])
        || !server_config.enabled
        || !server_config.is_local_environment()
        || server_config.oauth.is_some()
    {
        return Err(fail());
    }
    let mut value: toml::Value = toml::from_str(source).map_err(|_| fail())?;
    reject_indirection(&value)?;
    let table = value.as_table_mut().ok_or_else(fail)?;
    if table.contains_key("mcp_servers") || table.contains_key("sqlite_home") {
        return Err(fail());
    }
    // Storage is launch authority, never an ambient environment fallback.
    table.insert(
        "sqlite_home".to_string(),
        toml::Value::String(runtime.sqlite_home.to_str().ok_or_else(fail)?.to_string()),
    );
    if let McpServerTransportConfig::StreamableHttp { http_headers, .. } =
        &mut server_config.transport
    {
        *http_headers = None;
    }
    table.insert(
        "mcp_servers".to_string(),
        toml::Value::try_from(HashMap::from([(server.to_string(), &server_config)]))
            .map_err(|_| fail())?,
    );
    let configuration = toml::to_string(&value).map_err(|_| fail())?;
    if configuration.len() > 65_536 || configuration.contains(&authorization[7..]) {
        return Err(fail());
    }
    let cfg: ConfigToml = value.clone().try_into().map_err(|_| fail())?;
    if cfg.model.as_deref() != Some(text(&template["model"], 256)?)
        || cfg.model_provider.as_deref() != Some(text(&template["modelProviderId"], 128)?)
        || cfg.model_providers.len() != 1
    {
        return Err(fail());
    }
    let layers = ConfigLayerStack::new(
        vec![ConfigLayerEntry::new(
            ConfigLayerSource::SessionFlags,
            value,
        )],
        Default::default(),
        Default::default(),
    )
    .map_err(|_| fail())?
    .with_user_and_project_exec_policy_rules_ignored(true);
    let home = AbsolutePathBuf::from_absolute_path(&runtime.codex_home).map_err(|_| fail())?;
    let overrides = ConfigOverrides {
        cwd: Some(runtime.cwd.clone()),
        codex_self_exe: Some(runtime.codex_self_exe.clone()),
        codex_linux_sandbox_exe: runtime.codex_linux_sandbox_exe.clone(),
        main_execve_wrapper_exe: runtime.main_execve_wrapper_exe.clone(),
        default_zsh_path: runtime
            .zsh_path
            .clone()
            .map(AbsolutePathBuf::from_absolute_path)
            .transpose()
            .map_err(|_| fail())?,
        ..Default::default()
    };
    let mut config = Config::load_sealed_worker_config(cfg, overrides, home, layers)
        .await
        .map_err(|_| fail())?;
    if config.cli_auth_credentials_store_mode != AuthCredentialsStoreMode::Ephemeral
        || config.model_provider.requires_openai_auth
        || config.model_provider.env_key.is_some()
        || config.model_provider.has_command_auth()
        || config.model_provider.aws.is_some()
        || config.model_provider.gateway_oauth.is_some()
        || config.cloud_skill_enabled
        || config.orchestrator_mcp_enabled
        || config.zsh_path != runtime.zsh_path
        || config.sqlite.home() != runtime.sqlite_home
    {
        return Err(fail());
    }
    let mut servers = config.mcp_servers.get().clone();
    let actual = servers.get_mut(server).ok_or_else(fail)?;
    if let McpServerTransportConfig::StreamableHttp { http_headers, .. } = &mut actual.transport {
        *http_headers = Some(HashMap::from([(
            "Authorization".to_string(),
            authorization.to_string(),
        )]));
    } else {
        return Err(fail());
    }
    config.mcp_servers.set(servers).map_err(|_| fail())?;
    let observed_server = digest(&config.mcp_servers.get()[server]).map_err(|_| fail())?;
    let observed_provider = digest(&config.model_provider).map_err(|_| fail())?;
    let projection = effective_config_projection(&config).map_err(|_| fail())?;
    let config_sha256 = effective_config_sha256(&config).map_err(|_| fail())?;
    if matches!(purpose, MaterializationPurpose::Verify)
        && (Some(observed_server.as_str()) != request["serverConfigSha256"].as_str()
            || Some(observed_provider.as_str()) != template["modelProviderSha256"].as_str()
            || projection != request["projection"]
            || Some(config_sha256.as_str()) != request["configSha256"].as_str())
    {
        return Err(fail());
    }
    let receipt = json!({"version":1,"requestSha256":request["requestSha256"],"templateSha256":template["templateSha256"],
        "configuration":configuration,"configurationSha256":hash(&configuration),"model":config.model,
        "modelProviderId":config.model_provider_id,"modelProviderSha256":observed_provider,
        "serverConfigSha256":observed_server,"projection":projection,"configSha256":config_sha256});
    if serde_json::to_string(&receipt)
        .map_err(|_| fail())?
        .contains(&authorization[7..])
    {
        return Err(fail());
    }
    Ok(WorkerLaunchMaterialization {
        configuration,
        receipt,
        runtime,
        config,
    })
}

#[cfg(test)]
#[path = "worker_launch_config_tests.rs"]
mod tests;
