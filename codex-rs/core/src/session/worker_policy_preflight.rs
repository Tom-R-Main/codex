use super::session::Session;
use codex_async_utils::OrCancelExt;
use codex_protocol::error::CodexErr;
use codex_protocol::error::Result as CodexResult;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use tokio_util::sync::CancellationToken;

static PREPARING: AtomicBool = AtomicBool::new(false);

struct PreparationGuard;

impl PreparationGuard {
    fn acquire() -> CodexResult<Self> {
        PREPARING
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| {
                CodexErr::InvalidRequest("worker preparation already running".to_owned())
            })?;
        Ok(Self)
    }
}

impl Drop for PreparationGuard {
    fn drop(&mut self) {
        PREPARING.store(false, Ordering::Release);
    }
}

impl Session {
    /// Build the same executable router used by a turn without submitting input,
    /// creating a model request, executing a tool, or retaining an active step.
    pub(crate) async fn prepare_restricted_worker_registry(
        self: &Arc<Self>,
        cancellation_token: &CancellationToken,
    ) -> CodexResult<()> {
        let server = crate::worker_policy::preflight_server().map_err(CodexErr::InvalidRequest)?;
        let _guard = PreparationGuard::acquire()?;
        // Serialize the entire speculative capture with every task reservation
        // and registration. active_turn itself cannot be held across capture:
        // capture reads it, and cleanup must remain free to retire live tasks.
        let _admission = self
            .turn_admission
            .lock()
            .or_cancel(cancellation_token)
            .await?;
        if self
            .active_turn
            .lock()
            .or_cancel(cancellation_token)
            .await?
            .is_some()
        {
            return Err(CodexErr::InvalidRequest(
                "worker preparation requires an idle thread".to_owned(),
            ));
        }
        crate::worker_policy::invalidate_registry(
            &self.thread_id.to_string(),
            &self.worker_registry,
        )
        .map_err(CodexErr::InvalidRequest)?;
        // Validate before context discovery as well as after its effective snapshot.
        let config = self.get_config().or_cancel(cancellation_token).await?;
        crate::worker_policy::validate_worker_config(&config).map_err(CodexErr::Io)?;
        let context = self
            .new_default_turn()
            .or_cancel(cancellation_token)
            .await?;
        crate::worker_policy::validate_worker_config(&context.config).map_err(CodexErr::Io)?;
        // Required MCP startup is the sealed launch transport, not a model-selected server.
        // Do not retain this speculative step or invoke run_turn/sampling.
        self.capture_step_context_inner(context, cancellation_token, &[server], &HashSet::new())
            .await?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "worker_policy_preflight_tests.rs"]
pub(super) mod tests;
