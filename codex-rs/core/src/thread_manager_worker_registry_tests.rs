//! Actual runtime removal/shutdown paths must release only their own registry.
use super::*;
use crate::config::test_config;
use crate::worker_registry;
use codex_utils_absolute_path::AbsolutePathBuf;
use serde_json::json;

async fn fixture() -> (tempfile::TempDir, Config, ThreadManager) {
    let home = tempfile::tempdir().unwrap();
    let mut config = test_config().await;
    config.codex_home = AbsolutePathBuf::from_absolute_path(home.path()).unwrap();
    config.cwd = config.codex_home.clone();
    let manager = ThreadManager::with_models_provider_and_home_for_tests(
        CodexAuth::from_api_key("dummy"), config.model_provider.clone(), home.path().to_path_buf(),
        Arc::new(EnvironmentManager::default_for_tests()));
    (home, config, manager)
}

async fn start(manager: &ThreadManager, config: Config) -> NewThread {
    manager.start_thread(StartThreadOptions { environments: Some(Vec::new()),
        ..StartThreadOptions::new(config) }).await.unwrap()
}

#[tokio::test]
async fn actual_removals_reclaim_capacity_across_more_than_64_distinct_runtimes() {
    let (_home, config, manager) = fixture().await;
    for index in 0..65 {
        let started = start(&manager, config.clone()).await;
        let key = started.thread_id.to_string();
        worker_registry::publish(key.clone(), &started.thread.session.worker_registry, json!({"ready":true})).unwrap();
        assert!(worker_registry::read(&key).is_some());
        let removed = match index % 3 {
            0 => manager.remove_thread(&started.thread_id).await,
            1 => manager.remove_thread_for_client(&started.thread_id).await.unwrap(),
            _ => manager.remove_thread_if_matches(&started.thread_id, &started.thread).await,
        };
        assert!(removed.is_some());
        assert_eq!(worker_registry::read(&key), None);
        assert!(worker_registry::publish(key, &started.thread.session.worker_registry, json!({"ready":true})).is_err());
        started.thread.shutdown_and_wait().await.unwrap();
    }
}

#[tokio::test]
async fn stale_old_runtime_cleanup_preserves_a_resumed_replacement_registry() {
    let (_home, config, manager) = fixture().await;
    let old = start(&manager, config.clone()).await;
    let key = old.thread_id.to_string();
    worker_registry::publish(key.clone(), &old.thread.session.worker_registry, json!({"runtime":"old"})).unwrap();
    manager.remove_thread_if_matches(&old.thread_id, &old.thread).await.unwrap();
    old.thread.shutdown_and_wait().await.unwrap();
    let replacement = manager.start_thread(StartThreadOptions {
        initial_history: InitialHistory::Resumed(codex_history::ResumedHistory {
            conversation_id: old.thread_id, history: Arc::new(Vec::new()), rollout_path: None }),
        environments: Some(Vec::new()), ..StartThreadOptions::new(config)
    }).await.unwrap();
    assert_eq!(replacement.thread_id, old.thread_id);
    worker_registry::publish(key.clone(), &replacement.thread.session.worker_registry, json!({"runtime":"new"})).unwrap();
    assert!(manager.remove_thread_if_matches(&old.thread_id, &old.thread).await.is_none());
    old.thread.session.worker_registry.retire();
    worker_registry::invalidate(&key, &old.thread.session.worker_registry).unwrap();
    assert!(worker_registry::publish(key.clone(), &old.thread.session.worker_registry, json!({"runtime":"stale"})).is_err());
    assert_eq!(worker_registry::read(&key), Some(json!({"runtime":"new"})));
    assert!(!worker_registry::contains(&key, &old.thread.session.worker_registry).unwrap());
    assert!(worker_registry::contains(&key, &replacement.thread.session.worker_registry).unwrap());
    manager.remove_thread(&replacement.thread_id).await.unwrap();
    replacement.thread.shutdown_and_wait().await.unwrap();
}

#[tokio::test]
async fn actual_runtime_shutdown_revokes_before_manager_removal() {
    let (_home, config, manager) = fixture().await;
    let started = start(&manager, config).await;
    let key = started.thread_id.to_string();
    worker_registry::publish(key.clone(), &started.thread.session.worker_registry, json!({"ready":true})).unwrap();
    started.thread.shutdown_and_wait().await.unwrap();
    assert_eq!(worker_registry::read(&key), None);
    assert!(worker_registry::publish(key, &started.thread.session.worker_registry, json!({"ready":true})).is_err());
    manager.remove_thread(&started.thread_id).await.unwrap();
}

#[test]
fn dropped_runtime_owner_releases_without_a_process_lifetime_tombstone() {
    let key = "dropped-runtime-fixture".to_string();
    {
        let owner = worker_registry::WorkerRegistryOwner::default();
        worker_registry::publish(key.clone(), &owner, json!({"ready":true})).unwrap();
    }
    assert_eq!(worker_registry::read(&key), None);
}
