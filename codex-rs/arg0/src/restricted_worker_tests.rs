use super::*;

#[test]
fn actual_restricted_dispatch_refuses_before_dotenv_aliases_or_entrypoint() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join(".env"), "RESTRICTED_ARG0_UNTRUSTED_DOTENV=loaded\n").unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "restricted_worker::tests::restricted_dispatch_child", "--ignored"])
        .env("CODEX_RESTRICTED_WORKER", "1")
        .env("CODEX_HOME", root.path())
        .env_remove("RESTRICTED_ARG0_UNTRUSTED_DOTENV")
        .status().unwrap();
    assert!(status.success());
    assert_eq!(std::fs::read_to_string(root.path().join("entry-receipt")).unwrap(), "refused");
    assert!(!root.path().join("tmp").exists());
}

#[test]
#[ignore = "run only by isolated environment parent fixture"]
fn restricted_dispatch_child() {
    let Some(home) = std::env::var_os("CODEX_HOME") else { return; };
    assert!(crate::arg0_dispatch().is_none());
    assert!(std::env::var_os("RESTRICTED_ARG0_UNTRUSTED_DOTENV").is_none());
    let result = crate::arg0_dispatch_or_else(|_| async { panic!("restricted entrypoint must not run on unbound test executable") });
    assert!(result.is_err());
    std::fs::write(PathBuf::from(home).join("entry-receipt"), "refused").unwrap();
}

#[cfg(unix)]
#[test]
fn image_metadata_requires_immutable_files_and_exact_direct_alias_targets() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    let root = tempfile::tempdir().unwrap();
    let provider = root.path().join("codex");
    std::fs::write(&provider, b"fixture executable").unwrap();
    std::fs::set_permissions(&provider, std::fs::Permissions::from_mode(0o755)).unwrap();
    let owner = std::fs::metadata(&provider).unwrap().uid();
    check_entry(root.path(), owner, true).unwrap();
    check_entry(&provider, owner, false).unwrap();
    let alias = root.path().join("codex-linux-sandbox");
    symlink(&provider, &alias).unwrap();
    check_alias(&alias, &provider, owner).unwrap();
    assert!(check_entry(&alias, owner, false).is_err());
    assert!(check_alias(&alias, &root.path().join("different"), owner).is_err());
    assert!(check_entry(&provider, owner.wrapping_add(1), false).is_err());
    std::fs::set_permissions(&provider, std::fs::Permissions::from_mode(0o775)).unwrap();
    assert!(check_entry(&provider, owner, false).is_err());
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(check_entry(root.path(), owner, true).is_err());
}
