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
