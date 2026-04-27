use crate::state::AppState;
use anyhow::Result;
use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

pub async fn run_active_checks(state: Arc<AppState>) {
    let config = state.config.load();
    let active = &config.health.active;
    if !active.enabled {
        return;
    }

    let client: Client<HttpConnector, String> = Client::builder(TokioExecutor::new()).build_http();

    let targets: Vec<(String, String)> = config
        .routes
        .iter()
        .flat_map(|r| r.pools.iter())
        .flat_map(|p| p.origins.iter())
        .map(|o| {
            let base = o.url.as_str().trim_end_matches('/');
            let path = o
                .health_check_path
                .clone()
                .unwrap_or_else(|| "/".to_string());
            (base.to_string(), path)
        })
        .collect();

    let healthy_threshold = active.healthy_threshold;
    let unhealthy_threshold = active.unhealthy_threshold;

    info!(
        "Active health checker starting: {} targets, interval={:?}",
        targets.len(),
        active.interval
    );

    let mut interval = tokio::time::interval(active.interval);

    loop {
        interval.tick().await;

        for (base, path) in &targets {
            let url = format!("{}{}", base, path);
            let req = Request::builder()
                .method("GET")
                .uri(&url)
                .body(String::new())
                .expect("health check request builder");

            let result = tokio::time::timeout(active.timeout, client.request(req)).await;

            if let Some(state) = state.origin_states.get(base) {
                match result {
                    Ok(Ok(resp)) if resp.status().is_success() => {
                        state.record_success_with_threshold(healthy_threshold);
                        debug!("Health check passed for {}", base);
                    }
                    Ok(Ok(resp)) => {
                        state.record_failure_with_threshold(unhealthy_threshold);
                        warn!("Health check failed for {}: status {}", base, resp.status());
                    }
                    Ok(Err(e)) => {
                        state.record_failure_with_threshold(unhealthy_threshold);
                        warn!("Health check failed for {}: {}", base, e);
                    }
                    Err(_) => {
                        state.record_failure_with_threshold(unhealthy_threshold);
                        warn!("Health check timed out for {}", base);
                    }
                }
            }
        }
    }
}

pub async fn run_health_server(state: Arc<AppState>) -> Result<()> {
    let addr = state.config.load().metrics_addr;
    let listener = TcpListener::bind(addr).await?;
    info!("Health server listening on {}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();

        tokio::spawn(async move {
            let service = hyper::service::service_fn(move |req| {
                let state = state.clone();
                async move { handle_health_request(req, &state).await }
            });

            let io = TokioIo::new(stream);
            let _ = http1::Builder::new().serve_connection(io, service).await;
        });
    }
}

async fn handle_health_request(
    req: Request<hyper::body::Incoming>,
    state: &AppState,
) -> Result<Response<Full<Bytes>>> {
    match req.uri().path() {
        "/metrics" => {
            let body = state.metrics_handle.render();
            Ok(Response::builder()
                .header("Content-Type", "text/plain; version=0.0.4")
                .body(Full::new(Bytes::from(body)))?)
        }
        "/healthz" => Ok(Response::new(Full::new(Bytes::from(r#"{"status":"ok"}"#)))),
        "/healthz/upstreams" => {
            let mut origins = serde_json::Map::new();
            for entry in state.origin_states.iter() {
                let key = entry.key().clone();
                let state = entry.value();
                let mut obj = serde_json::Map::new();
                obj.insert(
                    "healthy".to_string(),
                    serde_json::Value::Bool(
                        state.healthy.load(std::sync::atomic::Ordering::Relaxed),
                    ),
                );
                obj.insert(
                    "consecutive_successes".to_string(),
                    serde_json::Value::Number(
                        state
                            .consecutive_successes
                            .load(std::sync::atomic::Ordering::Relaxed)
                            .into(),
                    ),
                );
                obj.insert(
                    "consecutive_failures".to_string(),
                    serde_json::Value::Number(
                        state
                            .consecutive_failures
                            .load(std::sync::atomic::Ordering::Relaxed)
                            .into(),
                    ),
                );
                obj.insert(
                    "total_requests".to_string(),
                    serde_json::Value::Number(
                        state
                            .total_requests
                            .load(std::sync::atomic::Ordering::Relaxed)
                            .into(),
                    ),
                );
                obj.insert(
                    "total_failures".to_string(),
                    serde_json::Value::Number(
                        state
                            .total_failures
                            .load(std::sync::atomic::Ordering::Relaxed)
                            .into(),
                    ),
                );
                obj.insert(
                    "ewma_latency_ns".to_string(),
                    serde_json::Value::Number(
                        state
                            .ewma_latency_ns
                            .load(std::sync::atomic::Ordering::Relaxed)
                            .into(),
                    ),
                );
                origins.insert(key, serde_json::Value::Object(obj));
            }

            let body = serde_json::to_string(&serde_json::json!({ "origins": origins }))?;
            Ok(Response::new(Full::new(Bytes::from(body))))
        }
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("Not Found")))?),
    }
}
