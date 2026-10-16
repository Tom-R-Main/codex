//! Exercise the persisted metadata merge and finalization used by the actual
//! cold thread/resume path, including its post-load reasoning reset.
use super::*;
use codex_protocol::openai_models::ReasoningEffort;
use codex_state::ThreadMetadataBuilder;

#[tokio::test]
async fn cold_resume_merged_reasoning_metadata_must_match_sealed_native_state() {
    let root = tempfile::tempdir().unwrap();
    let (manager, native) = crate::worker_launch::tests::sealed_manager_fixture(root.path()).await;
    let mut builder = ThreadMetadataBuilder::new(ThreadId::new(), root.path().join("rollout.jsonl"),
        chrono::Utc::now(), codex_protocol::protocol::SessionSource::default());
    builder.model_provider = Some(native.model_provider_id.clone());
    let mut metadata = builder.build(&native.model_provider_id);
    metadata.model = native.model.clone();
    metadata.reasoning_effort = Some(ReasoningEffort::Low);
    let mut overrides = None;
    let mut typed = ConfigOverrides::default();
    merge_persisted_resume_metadata(&mut overrides, &mut typed, &metadata);
    assert_eq!(overrides.as_ref().unwrap()["model_reasoning_effort"], serde_json::json!("low"));
    let loaded = manager.load_for_cwd(overrides, typed, Some(root.path().to_path_buf())).await.unwrap();
    let resumed = manager.finalize_resume_config(loaded, false).unwrap();
    assert_eq!(resumed, native);

    metadata.reasoning_effort = Some(ReasoningEffort::High);
    let mut overrides = None;
    let mut typed = ConfigOverrides::default();
    merge_persisted_resume_metadata(&mut overrides, &mut typed, &metadata);
    assert!(manager.load_for_cwd(overrides, typed, Some(root.path().to_path_buf())).await.is_err());

    // A stored None normally clears the effort AFTER the config load. The
    // actual resume entry now validates this final config before restoration.
    metadata.reasoning_effort = None;
    let mut overrides = None;
    let mut typed = ConfigOverrides::default();
    merge_persisted_resume_metadata(&mut overrides, &mut typed, &metadata);
    let loaded = manager.load_for_cwd(overrides, typed, Some(root.path().to_path_buf())).await.unwrap();
    assert!(manager.finalize_resume_config(loaded, true).is_err());
}
