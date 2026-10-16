use super::*;

#[tokio::test]
async fn canceled_preparation_releases_singleflight_without_admitting_a_parallel_preparation() {
    let (started, observed) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let _guard = PreparationGuard::acquire().unwrap();
        started.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    observed.await.unwrap();
    assert!(PreparationGuard::acquire().is_err());
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let recovered = PreparationGuard::acquire().unwrap();
    assert!(PreparationGuard::acquire().is_err());
    drop(recovered);
    assert!(PreparationGuard::acquire().is_ok());
}

struct AdmissionProbeTask {
    entered: Arc<tokio::sync::Notify>,
}

impl crate::tasks::SessionTask for AdmissionProbeTask {
    fn kind(&self) -> crate::state::TaskKind {
        crate::state::TaskKind::Regular
    }

    fn span_name(&self) -> &'static str {
        "session_task.worker_admission_test"
    }

    async fn run(
        self: Arc<Self>,
        _session: Arc<Session>,
        _ctx: Arc<crate::session::turn_context::TurnContext>,
        _input: Vec<crate::session::TurnInput>,
        cancellation_token: CancellationToken,
    ) -> crate::tasks::SessionTaskResult {
        self.entered.notify_one();
        cancellation_token.cancelled().await;
        Ok(None)
    }
}

#[derive(Clone, Copy)]
enum PreparationExit {
    ValidationFailure,
    Timeout,
    Dropped,
    Canceled,
}

// Invoked by the existing isolated restricted-worker process, after installing
// the real launch policy. The ordinary fixture deliberately differs from that
// policy: releasing the state barrier must fail config validation, not dispatch
// a model request or start an MCP connection.
pub(crate) async fn assert_restricted_preflight_serializes_turn_admission(
    valid_config: &crate::config::Config,
) {
    use codex_protocol::turn_input::TurnInputMode;
    use codex_protocol::turn_input::TurnInputRequest;
    use codex_protocol::user_input::UserInput;
    use std::time::Duration;

    for exit in [PreparationExit::ValidationFailure, PreparationExit::Timeout,
        PreparationExit::Dropped, PreparationExit::Canceled] {
        let (session, context) = crate::session::tests::make_session_and_context().await;
        let session = Arc::new(session);
        let state = session.state.lock().await;
        let cancellation = CancellationToken::new();
        let mut prepare = Box::pin(session.prepare_restricted_worker_registry(&cancellation));
        // Deterministically stop the real preparation after idle-check and
        // invalidation, at get_config. No scheduler timing or sleeps are needed.
        assert!(futures::poll!(prepare.as_mut()).is_pending());
        assert!(session.turn_admission.try_lock().is_err());
        let mut start = Box::pin(crate::session::turn_input::handle(
            &session,
            TurnInputRequest::user_input(vec![UserInput::Text {
                text: "must queue behind preflight".to_string(),
                text_elements: Vec::new(),
            }]),
            TurnInputMode::StartIfIdle,
            "queued-after-preflight".to_string(),
        ));
        assert!(futures::poll!(start.as_mut()).is_pending());
        // Prior code reserved a turn here, then waited on the held state lock.
        assert!(session.active_turn.lock().await.is_none());
        drop(start); // Never allow this regular/model task to start in the fixture.
        match exit {
            PreparationExit::ValidationFailure => {
                drop(state);
                assert!(prepare.await.is_err());
            }
            PreparationExit::Timeout => {
                assert!(tokio::time::timeout(Duration::from_millis(1), prepare).await.is_err());
                drop(state);
            }
            PreparationExit::Dropped => {
                drop(prepare);
                drop(state);
            }
            PreparationExit::Canceled => {
                cancellation.cancel();
                assert!(prepare.await.is_err());
                drop(state);
            }
        }
        assert!(session.turn_admission.try_lock().is_ok());
        let singleflight = PreparationGuard::acquire().unwrap();
        drop(singleflight);

        // A queued native task can register after every failure/cancel mode.
        // This task has no inference or effects; it only signals and awaits abort.
        let entered = Arc::new(tokio::sync::Notify::new());
        tokio::time::timeout(Duration::from_secs(5), session.start_task(
            Arc::new(context), Vec::new(), AdmissionProbeTask { entered: entered.clone() },
        )).await.expect("preflight must release native task admission");
        tokio::time::timeout(Duration::from_secs(5), entered.notified()).await.unwrap();
        let thread_id = session.thread_id.to_string();
        crate::worker_policy::record_registry(thread_id.clone(), &session.worker_registry,
            "worker-model", valid_config, vec![(
                codex_tools::ToolName::namespaced("mcp__sift_worker", "execute"),
                Some("sift-worker".to_string()),
            )]).unwrap();
        // Turn-first: refusal must occur before invalidating the live registry.
        assert!(session.prepare_restricted_worker_registry(&CancellationToken::new()).await.is_err());
        assert!(crate::worker_policy::executor_request_meta(&thread_id,
            &session.worker_registry, "live-turn", "live-call", &None, None).is_ok());
        session.abort_all_tasks(codex_protocol::protocol::TurnAbortReason::Interrupted).await;
        assert!(session.turn_admission.try_lock().is_ok());
    }
}

#[tokio::test]
async fn ordinary_native_task_queues_behind_admission_and_registers_after_release() {
    let (session, context) = crate::session::tests::make_session_and_context().await;
    let session = Arc::new(session);
    let entered = Arc::new(tokio::sync::Notify::new());
    let admission = session.turn_admission.lock().await;
    let mut start = Box::pin(session.start_task(Arc::new(context), Vec::new(),
        AdmissionProbeTask { entered: entered.clone() }));
    assert!(futures::poll!(start.as_mut()).is_pending());
    assert!(session.active_turn.lock().await.is_none());
    drop(admission);
    tokio::time::timeout(std::time::Duration::from_secs(5), start).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified()).await.unwrap();
    assert!(session.active_turn.lock().await.as_ref().unwrap().task.is_some());
    session.abort_all_tasks(codex_protocol::protocol::TurnAbortReason::Interrupted).await;
    assert!(session.turn_admission.try_lock().is_ok());
}
