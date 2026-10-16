use super::*;

#[test]
fn isolated_manager_has_no_initial_or_reload_credential_discovery() {
    let home = tempfile::tempdir().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "auth::manager::isolated_ephemeral_tests::isolated_manager_child",
            "--ignored",
        ])
        .env(
            "CODEX_ACCESS_TOKEN",
            "at-isolated-fixture-no-live-credential",
        )
        .env("CODEX_API_KEY", "isolated-api-key-fixture")
        .env(
            "CODEX_AUTHAPI_BASE_URL",
            format!("http://{}", listener.local_addr().unwrap()),
        )
        .env(
            "CODEX_AGENT_IDENTITY_AUTHAPI_BASE_URL",
            "http://must-not-discover.invalid",
        )
        .env("CODEX_ISOLATED_AUTH_TEST_HOME", home.path())
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(
        std::fs::read_to_string(home.path().join("child-receipt")).unwrap(),
        "isolated"
    );
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 1);
}

#[tokio::test]
#[ignore = "run only by isolated environment parent fixture"]
async fn isolated_manager_child() {
    let Some(home) = std::env::var_os("CODEX_ISOLATED_AUTH_TEST_HOME") else {
        return;
    };
    let home = PathBuf::from(home);
    let manager = AuthManager::new_isolated_ephemeral(
        home.clone(),
        crate::test_support::transport_default_auth_route_config(),
    );
    assert!(manager.isolated_ephemeral);
    assert!(manager.agent_identity_authapi_base_url.is_none());
    assert!(manager.auth_cached().is_none());
    assert!(manager.auth().await.is_none());
    assert!(!manager.reload().await);
    assert!(manager.auth().await.is_none());
    std::fs::write(home.join("child-receipt"), "isolated").unwrap();
}
