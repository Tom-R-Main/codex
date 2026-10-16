//! Versioned, content-free binding of the loaded worker configuration.
//!
//! This is an explicit projection, not serialization of raw TOML or Debug output.
//! It includes resolved loader defaults and constrained effective permissions.
//! `None` inference preferences mean inheritance and remain distinct from explicit
//! preferences; controllers must pin preferences that change during turn resolution.
//! Launch expectations, policy/registry digests, provenance/warnings and UI-only
//! preferences do not participate, so the expected digest cannot hash itself.
//! External environment values, file contents, model-catalog resolution and runtime
//! effects remain separate qualification gates; this is not complete coverage.

use crate::config::Config;
use crate::worker_policy::digest;
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeMap;

pub(crate) const CONFIG_SCHEMA_VERSION: &str = "sift-worker-effective-config-v1";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EffectiveWorkerConfigV1 {
    domain: &'static str,
    schema_version: &'static str,
    model_sha256: String,
    permissions_sha256: String,
    mcp_sha256: String,
    registry_sha256: String,
    instructions_sha256: String,
    execution_sha256: String,
}

/// Hash only already-loaded typed values; never read credential stores, files or
/// environment variables here. Neither raw sections nor serialization errors are
/// exposed in the attestation, logs or error messages.
pub(crate) fn effective_config_sha256(config: &Config) -> Result<String, String> {
    effective_config_projection(config).and_then(|projection| {
        digest(&projection)
            .map_err(|_| "worker effective configuration cannot be bound".to_string())
    })
}

pub(crate) fn effective_config_projection(config: &Config) -> Result<serde_json::Value, String> {
    if config.rollout_budget.as_ref().is_some_and(|budget| {
        !budget.sampling_token_weight.is_finite() || !budget.prefill_token_weight.is_finite()
    }) {
        return Err("worker effective configuration cannot be bound".to_string());
    }
    let project = || -> Result<EffectiveWorkerConfigV1, serde_json::Error> {
        let shell = &config.permissions.shell_environment_policy;
        let features = codex_features::FEATURES
            .iter()
            .map(|spec| (spec.key, config.features.enabled(spec.id)))
            .collect::<BTreeMap<_, _>>();
        let network = config
            .permissions
            .network
            .as_ref()
            .map(|network| network.worker_policy_sha256())
            .transpose()
            .map_err(serde_json::Error::io)?;
        let residency =
            config
                .enforce_residency
                .get()
                .as_ref()
                .map(|requirement| match requirement {
                    codex_config::ResidencyRequirement::Us => "us",
                });
        Ok(EffectiveWorkerConfigV1 {
            domain: "codex-worker-loaded-config",
            schema_version: CONFIG_SCHEMA_VERSION,
            model_sha256: digest(&json!({
                "model": config.model, "providerId": config.model_provider_id,
                "provider": config.model_provider, "serviceTier": config.service_tier,
                "reviewModel": config.review_model, "contextWindow": config.model_context_window,
                "autoCompactLimit": config.model_auto_compact_token_limit,
                "autoCompactScope": config.model_auto_compact_token_limit_scope,
                "postTurnCompactPercent": config.model_post_turn_compact_threshold_percent,
                "reasoningEffort": config.model_reasoning_effort,
                "planReasoningEffort": config.plan_mode_reasoning_effort,
                "reasoningSummary": config.model_reasoning_summary, "verbosity": config.model_verbosity,
                "catalog": config.model_catalog, "residency": residency,
                "chatgptBaseUrl": config.chatgpt_base_url, "respectSystemProxy": config.respect_system_proxy,
                "responsesMetadata": config.responses_api_metadata,
            }))?,
            permissions_sha256: digest(&json!({
                "approvalPolicy": config.permissions.approval_policy.get(),
                "profile": config.permissions.effective_permission_profile(),
                "explicitProfileMode": config.explicit_permission_profile_mode,
                "workspaceRoots": config.workspace_roots,
                "permissionWorkspaceRoots": config.permissions.workspace_roots(),
                "network": network,
                "allowLoginShell": config.permissions.allow_login_shell,
                "windowsMode": config.permissions.windows_sandbox_mode,
                "windowsType": config.permissions.windows_sandbox_type,
                "approvalsReviewer": config.approvals_reviewer,
                "shell": {
                    "inherit": shell.inherit, "ignoreDefaultExcludes": shell.ignore_default_excludes,
                    "exclude": shell.exclude.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "set": shell.r#set,
                    "includeOnly": shell.include_only.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "useProfile": shell.use_profile,
                },
            }))?,
            mcp_sha256: digest(&json!({
                "servers": config.mcp_servers.get(),
                "enterpriseManagedAuth": config.mcp_enterprise_managed_auth,
                "oauthStoreMode": config.mcp_oauth_credentials_store_mode,
                "oauthCallbackPort": config.mcp_oauth_callback_port,
                "oauthCallbackUrl": config.mcp_oauth_callback_url,
                "nonPrefixedServers": config.non_prefixed_mcp_tool_servers,
                "optionalStartupGraceNanos": config.mcp_optional_startup_grace.as_nanos().to_string(),
            }))?,
            registry_sha256: digest(&json!({
                "features": features, "registry": config.tool_registry, "codeMode": config.code_mode,
                "webSearchMode": config.web_search_mode.get(), "webSearch": config.web_search_config,
                "requestUserInput": config.experimental_request_user_input_enabled,
                "updatePlan": config.update_plan_enabled, "agentsEnabled": config.agents_enabled,
                "agentMaxThreads": config.agent_max_threads, "agentMaxDepth": config.agent_max_depth,
                "agentDefaultModel": config.agent_default_subagent_model,
                "agentDefaultReasoning": config.agent_default_subagent_reasoning_effort,
                "agentRoles": config.agent_roles.iter().map(|(name, role)| {
                    (name, json!({"description": role.description, "configFile": role.config_file,
                        "nicknames": role.nickname_candidates}))
                }).collect::<BTreeMap<_, _>>(),
                "multiAgentV2": config.multi_agent_v2,
                "cloudSkills": config.cloud_skill_enabled, "orchestratorMcp": config.orchestrator_mcp_enabled,
            }))?,
            instructions_sha256: digest(&json!({
                "base": config.base_instructions, "developer": config.developer_instructions,
                "guardianConfig": config.guardian_policy_config, "guardianExtra": config.guardian_extra_policy,
                "guardianTemplate": config.guardian_policy_template, "compact": config.compact_prompt,
                "permissions": config.include_permissions_instructions, "apps": config.include_apps_instructions,
                "collaboration": config.include_collaboration_mode_instructions,
                "skills": config.include_skill_instructions, "environment": config.include_environment_context,
                "skillMaxTokens": config.skill_max_context_tokens, "projectDocMaxBytes": config.project_doc_max_bytes,
                "projectDocFallbacks": config.project_doc_fallback_filenames,
            }))?,
            execution_sha256: digest(&json!({
                "cwd": config.cwd, "workspaceRootsExplicit": config.workspace_roots_explicit,
                "codexHome": config.codex_home, "sqliteHome": config.sqlite.home(), "logDir": config.log_dir,
                "selfExe": config.codex_self_exe, "linuxSandboxExe": config.codex_linux_sandbox_exe,
                "execveWrapper": config.main_execve_wrapper_exe, "zsh": config.zsh_path,
                "notify": config.notify, "bypassHookTrust": config.bypass_hook_trust,
                "history": config.history, "ephemeral": config.ephemeral,
                "toolOutputLimit": config.tool_output_token_limit,
                "terminalMaxTimeout": config.background_terminal_max_timeout,
                "threadUnloadDelayNanos": config.thread_unload_delay.as_nanos().to_string(),
                "maxGoalTokenBudget": config.max_goal_token_budget,
                "memories": config.memories, "tokenBudget": config.token_budget,
                "rolloutBudget": config.rollout_budget,
            }))?,
        })
    };
    project()
        .and_then(serde_json::to_value)
        .map_err(|_| "worker effective configuration cannot be bound".to_string())
}

#[cfg(test)]
#[path = "worker_policy_config_tests.rs"]
mod tests;
