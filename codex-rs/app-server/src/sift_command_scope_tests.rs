use super::*;
use codex_protocol::approvals::SiftNativeCommandScope;
use pretty_assertions::assert_eq;
use serde_json::json;

fn event(argv: &[&str]) -> ExecApprovalRequestEvent {
    let cwd = std::env::temp_dir();
    let mut event: ExecApprovalRequestEvent = serde_json::from_value(json!({
        "call_id": "call-1", "turn_id": "turn-1", "started_at_ms": 1,
        "command": ["friendly display"], "cwd": cwd, "parsed_cmd": []
    })).unwrap();
    event.sift_command_scope = Some(SiftNativeCommandScope {
        program: serde_json::from_value(json!(cwd.join("program"))).unwrap(),
        argv: argv.iter().map(|arg| (*arg).to_owned()).collect(),
        cwd: serde_json::from_value(json!(cwd)).unwrap(),
    });
    event
}

#[test]
fn native_execve_preserves_argv_zero_spaces_quotes_and_empty_arguments() {
    let request = event(&["custom-argv-zero", "-c", "printf '%s' '$HOME'", "", "a b"]);
    let native = request.sift_command_scope.as_ref().unwrap();
    assert_eq!(from_approval(&request), Some(SiftCommandScope {
        version: 1,
        program: native.program.as_path().to_str().unwrap().to_owned(),
        argv: native.argv.clone(),
        cwd: native.cwd.as_path().to_str().unwrap().to_owned(),
    }));
    // Native identity cannot be reconstructed from a persisted/deserialized event.
    let persisted = serde_json::to_value(&request).unwrap();
    assert!(persisted.get("sift_command_scope").is_none());
    let restored: ExecApprovalRequestEvent = serde_json::from_value(persisted).unwrap();
    assert_eq!(from_approval(&restored), None);
}

#[test]
fn near_miss_programs_vectors_and_working_directories_remain_distinct() {
    let first = event(&["printf", "a b"]);
    assert_ne!(from_approval(&first), from_approval(&event(&["printf", "a", "b"])));
    let mut other = event(&["printf", "a b"]);
    other.sift_command_scope.as_mut().unwrap().program =
        serde_json::from_value(json!(std::env::temp_dir().join("another-program"))).unwrap();
    assert_ne!(from_approval(&first), from_approval(&other));
    other = event(&["printf", "a b"]);
    other.sift_command_scope.as_mut().unwrap().cwd =
        serde_json::from_value(json!(std::env::temp_dir().join("another-directory"))).unwrap();
    assert_ne!(from_approval(&first), from_approval(&other));
}

#[test]
fn pre_rewrite_stdin_network_and_invalid_vectors_never_acquire_scope() {
    let mut ordinary = event(&["echo", "hello"]);
    ordinary.sift_command_scope = None;
    assert_eq!(from_approval(&ordinary), None);
    let mut stdin = event(&["write_stdin", "--session-id", "1", "echo hi"]);
    stdin.kind = ExecApprovalKind::WriteStdin;
    assert_eq!(from_approval(&stdin), None);
    let mut network = event(&["curl", "https://example.invalid"]);
    network.network_approval_context = Some(serde_json::from_value(json!({
        "host": "example.invalid", "protocol": "https"
    })).unwrap());
    assert_eq!(from_approval(&network), None);
    for argv in [vec![], vec![""], vec!["echo", "bad\0arg"]] {
        assert_eq!(from_approval(&event(&argv)), None);
    }
    let mut too_many = event(&["echo"]);
    too_many.sift_command_scope.as_mut().unwrap().argv = vec!["x".to_owned(); 257];
    assert_eq!(from_approval(&too_many), None);
    let mut oversized = event(&["echo"]);
    oversized.sift_command_scope.as_mut().unwrap().argv = vec!["x".repeat(16_385)];
    assert_eq!(from_approval(&oversized), None);
}
