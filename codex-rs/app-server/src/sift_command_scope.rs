use codex_app_server_protocol::SiftCommandScope;
use codex_protocol::approvals::ExecApprovalKind;
use codex_protocol::approvals::ExecApprovalRequestEvent;

/// Copy the native request, never its shell-joined or redacted presentation.
pub(crate) fn from_approval(event: &ExecApprovalRequestEvent) -> Option<SiftCommandScope> {
    let native = event.sift_command_scope.as_ref()?;
    if event.kind != ExecApprovalKind::Command
        || event.network_approval_context.is_some()
        || native.argv.is_empty()
        || native.argv.len() > 256
        || native.argv[0].is_empty()
        || native
            .argv
            .iter()
            .any(|arg| arg.contains('\0') || arg.len() > 16_384)
        || native.argv.iter().map(String::len).sum::<usize>() > 65_536
    {
        return None;
    }
    let cwd = native.cwd.as_path().to_str()?;
    let program = native.program.as_path().to_str()?;
    if cwd.is_empty()
        || cwd.len() > 4096
        || cwd.contains('\0')
        || program.is_empty()
        || program.len() > 4096
        || program.contains('\0')
    {
        return None;
    }
    Some(SiftCommandScope {
        version: 1,
        program: program.to_owned(),
        argv: native.argv.clone(),
        cwd: cwd.to_owned(),
    })
}

#[cfg(test)]
#[path = "sift_command_scope_tests.rs"]
mod tests;
