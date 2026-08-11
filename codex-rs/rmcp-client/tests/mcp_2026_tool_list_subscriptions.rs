use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use codex_config::types::AuthKeyringBackendKind;
use codex_config::types::OAuthCredentialsStoreMode;
use codex_exec_server::Environment;
use codex_rmcp_client::ElicitationAction;
use codex_rmcp_client::ElicitationResponse;
use codex_rmcp_client::McpProtocolMode;
use codex_rmcp_client::RmcpClient;
use futures::FutureExt;
use rmcp::ServerHandler;
use rmcp::model::ClientCapabilities;
use rmcp::model::Implementation;
use rmcp::model::InitializeRequestParams;
use rmcp::model::ProtocolVersion;
use rmcp::model::ServerCapabilities;
use rmcp::model::ServerInfo;
use rmcp::model::SubscriptionFilter;
use rmcp::service::SubscriptionContext;
use rmcp::transport::streamable_http_server::StreamableHttpServerConfig;
use rmcp::transport::streamable_http_server::StreamableHttpService;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use serde_json::json;
use tokio::sync::Notify;
use tokio::time::timeout;

#[derive(Clone)]
struct ToolListSubscriptionServer {
    subscription_started: Arc<Notify>,
    subscription_cancelled: Arc<Notify>,
}

impl ServerHandler for ToolListSubscriptionServer {
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(&[ProtocolVersion::V_2026_07_28, ProtocolVersion::V_2025_06_18])
    }

    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_tool_list_changed()
                .build(),
        )
    }

    fn accepted_subscription_filter(
        &self,
        requested: &SubscriptionFilter,
    ) -> Option<SubscriptionFilter> {
        Some(requested.supported_by(&self.get_info().capabilities))
    }

    async fn listen(&self, context: SubscriptionContext) -> Result<(), rmcp::ErrorData> {
        self.subscription_started.notify_one();
        context
            .sink()
            .notify_tool_list_changed()
            .await
            .map_err(|error| rmcp::ErrorData::internal_error(error.to_string(), None))?;
        context.cancelled().await;
        self.subscription_cancelled.notify_one();
        Ok(())
    }
}

async fn spawn_server() -> anyhow::Result<(
    String,
    Arc<Notify>,
    Arc<Notify>,
    tokio::task::JoinHandle<()>,
)> {
    let subscription_started = Arc::new(Notify::new());
    let subscription_cancelled = Arc::new(Notify::new());
    let handler = ToolListSubscriptionServer {
        subscription_started: Arc::clone(&subscription_started),
        subscription_cancelled: Arc::clone(&subscription_cancelled),
    };
    let service: StreamableHttpService<ToolListSubscriptionServer, LocalSessionManager> =
        StreamableHttpService::new(
            move || Ok(handler.clone()),
            Default::default(),
            StreamableHttpServerConfig::default()
                .with_legacy_session_mode(true)
                .with_json_response(true),
        );
    let router = axum::Router::new().nest_service("/mcp", service);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Ok((
        format!("http://{address}/mcp"),
        subscription_started,
        subscription_cancelled,
        server,
    ))
}

async fn create_client(url: &str, mode: McpProtocolMode) -> anyhow::Result<RmcpClient> {
    let client = RmcpClient::new_streamable_http_client_with_protocol_mode(
        "tool-list-subscription-test",
        url,
        /*bearer_token*/ None,
        /*http_headers*/ None,
        /*env_http_headers*/ None,
        OAuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::default(),
        Environment::default_for_tests().get_http_client(),
        /*auth_provider*/ None,
        mode,
    )
    .await?;
    let params = InitializeRequestParams::new(
        ClientCapabilities::default(),
        Implementation::new("codex-tool-list-subscription-test", "0.0.0"),
    )
    .with_protocol_version(ProtocolVersion::V_2025_06_18);
    client
        .initialize(
            params,
            Some(Duration::from_secs(5)),
            Box::new(|_, _| {
                async {
                    Ok(ElicitationResponse {
                        action: ElicitationAction::Accept,
                        content: Some(json!({})),
                        meta: None,
                    })
                }
                .boxed()
            }),
        )
        .await?;
    Ok(client)
}

#[tokio::test]
async fn modern_client_receives_advertised_tool_list_changes() -> anyhow::Result<()> {
    let (url, subscription_started, subscription_cancelled, server) = spawn_server().await?;
    let client = create_client(&url, McpProtocolMode::V20260728).await?;

    let mut subscription = client
        .subscribe_tool_list_changes(Some(Duration::from_secs(5)))
        .await?
        .expect("advertised tool-list subscription");
    timeout(Duration::from_secs(5), subscription_started.notified()).await?;
    assert_eq!(
        timeout(Duration::from_secs(5), subscription.recv()).await??,
        Some(())
    );

    subscription.cancel().await?;
    timeout(Duration::from_secs(5), subscription_cancelled.notified()).await?;
    client.shutdown().await;
    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn legacy_client_does_not_open_modern_tool_list_subscription() -> anyhow::Result<()> {
    let (url, subscription_started, _, server) = spawn_server().await?;
    let client = create_client(&url, McpProtocolMode::Legacy).await?;

    assert!(
        client
            .subscribe_tool_list_changes(Some(Duration::from_secs(5)))
            .await?
            .is_none()
    );
    assert!(
        timeout(Duration::from_millis(100), subscription_started.notified())
            .await
            .is_err()
    );

    client.shutdown().await;
    server.abort();
    let _ = server.await;
    Ok(())
}
