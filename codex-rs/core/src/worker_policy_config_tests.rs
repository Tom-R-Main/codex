use super::*;
use codex_config::Constrained;
use codex_protocol::config_types::EnvironmentVariablePattern;
use pretty_assertions::assert_eq;

async fn load(home: &std::path::Path, overrides: Vec<(String, toml::Value)>) -> Config {
    crate::config::ConfigBuilder::without_managed_config_for_tests()
        .codex_home(home.to_path_buf())
        .harness_overrides(crate::config::ConfigOverrides {
            model: Some("worker-model".to_string()),
            cwd: Some(home.to_path_buf()),
            ..Default::default()
        })
        .cli_overrides(overrides)
        .build()
        .await
        .unwrap()
}

#[tokio::test]
async fn omitted_and_explicit_loader_defaults_have_the_same_binding() {
    let home = tempfile::tempdir().unwrap();
    let omitted = load(home.path(), vec![]).await;
    let explicit = load(
        home.path(),
        vec![
            ("shell_environment_policy.inherit".to_string(), "all".into()),
            (
                "shell_environment_policy.ignore_default_excludes".to_string(),
                true.into(),
            ),
            (
                "shell_environment_policy.experimental_use_profile".to_string(),
                false.into(),
            ),
            (
                "shell_environment_policy.set".to_string(),
                toml::Value::Table(Default::default()),
            ),
        ],
    )
    .await;
    assert_eq!(
        effective_config_sha256(&omitted).unwrap(),
        effective_config_sha256(&explicit).unwrap()
    );
}

#[tokio::test]
async fn actual_behavior_changes_bind_even_with_the_same_model_and_executor_names() {
    let home = tempfile::tempdir().unwrap();
    let config = load(home.path(), vec![]).await;
    let original = effective_config_sha256(&config).unwrap();
    let mut variants = Vec::new();
    let mut changed = config.clone();
    changed.enforce_residency =
        Constrained::allow_any(Some(codex_config::ResidencyRequirement::Us));
    variants.push(changed);
    let mut changed = config.clone();
    changed.model_provider.base_url = Some("http://127.0.0.1:9191/responses".to_string());
    variants.push(changed);
    let mut changed = config.clone();
    changed.permissions.allow_login_shell = !changed.permissions.allow_login_shell;
    variants.push(changed);
    let mut changed = config.clone();
    changed
        .permissions
        .shell_environment_policy
        .r#set
        .insert("EXAMPLE_INPUT".to_string(), "opaque-test-value".to_string());
    variants.push(changed);
    let mut changed = config.clone();
    changed.permissions.shell_environment_policy.exclude.push(
        EnvironmentVariablePattern::new_case_insensitive("EXAMPLE_*"),
    );
    variants.push(changed);
    let mut changed = config.clone();
    changed.tool_registry.error_on_tool_collisions =
        !changed.tool_registry.error_on_tool_collisions;
    variants.push(changed);
    let mut changed = config.clone();
    changed.update_plan_enabled = !changed.update_plan_enabled;
    variants.push(changed);
    let mut changed = config.clone();
    changed.mcp_servers = Constrained::allow_any(std::collections::HashMap::from([(
        "sift-worker".to_string(),
        toml::from_str("url='http://127.0.0.1:9001/mcp'").unwrap(),
    )]));
    variants.push(changed);
    let mut changed = config.clone();
    changed.developer_instructions = Some("fixture instruction".to_string());
    variants.push(changed);
    let mut changed = config.clone();
    changed.cwd =
        codex_utils_absolute_path::AbsolutePathBuf::from_absolute_path(home.path().join("changed"))
            .unwrap();
    variants.push(changed);
    for changed in variants {
        assert_ne!(original, effective_config_sha256(&changed).unwrap());
    }
}

#[tokio::test]
async fn unordered_maps_canonicalize_but_value_changes_do_not() {
    let home = tempfile::tempdir().unwrap();
    let mut config = load(home.path(), vec![]).await;
    config.permissions.shell_environment_policy.r#set = std::collections::HashMap::from([
        ("ONE".to_string(), "opaque-one".to_string()),
        ("TWO".to_string(), "opaque-two".to_string()),
    ]);
    let mut reordered = config.clone();
    reordered.permissions.shell_environment_policy.r#set = std::collections::HashMap::from([
        ("TWO".to_string(), "opaque-two".to_string()),
        ("ONE".to_string(), "opaque-one".to_string()),
    ]);
    let original = effective_config_sha256(&config).unwrap();
    assert_eq!(original, effective_config_sha256(&reordered).unwrap());
    reordered
        .permissions
        .shell_environment_policy
        .r#set
        .insert("ONE".to_string(), "changed".to_string());
    assert_ne!(original, effective_config_sha256(&reordered).unwrap());
    // Public evidence is the content-free digest, never a serialized Config.
    assert_eq!(original.len(), 64);
    assert!(
        original
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    );
}

#[tokio::test]
async fn display_bookkeeping_is_excluded_but_normalized_feature_values_are_bound() {
    let home = tempfile::tempdir().unwrap();
    let config = load(home.path(), vec![]).await;
    let original = effective_config_sha256(&config).unwrap();
    let mut changed = config.clone();
    changed
        .startup_warnings
        .push("display-only warning".to_string());
    changed.animations = !changed.animations;
    assert_eq!(original, effective_config_sha256(&changed).unwrap());
    let feature = codex_features::Feature::ShellSnapshot;
    changed
        .features
        .set_enabled(feature, !config.features.enabled(feature))
        .unwrap();
    assert_ne!(original, effective_config_sha256(&changed).unwrap());
}
