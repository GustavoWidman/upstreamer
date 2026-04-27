use crate::errors::ErrorResponse;
use crate::state::AppState;
use anyhow::Result;
use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper::body::Incoming;
use hyper::header::HOST;
use hyper::server::conn::http1;
use hyper::{Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

pub async fn run_proxy(state: Arc<AppState>) -> Result<()> {
    let config = state.config.load();
    let addr = config.listen;

    let listener = TcpListener::bind(addr).await?;
    info!("Proxy server listening on {}", addr);

    loop {
        let (stream, remote_addr) = listener.accept().await?;
        let state = state.clone();

        tokio::spawn(async move {
            let start = Instant::now();
            let result = handle_connection(stream, remote_addr, state).await;
            let duration = start.elapsed();

            match result {
                Ok(_) => {
                    debug!(
                        "Connection from {} closed after {:?}",
                        remote_addr, duration
                    );
                }
                Err(e) => {
                    error!("Connection from {} failed: {}", remote_addr, e);
                }
            }
        });
    }
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    remote_addr: SocketAddr,
    state: Arc<AppState>,
) -> Result<()> {
    let http = http1::Builder::new();

    let service = hyper::service::service_fn(move |req| {
        let state = state.clone();
        let remote_addr = remote_addr;
        async move { handle_request(req, state, remote_addr).await }
    });

    let io = TokioIo::new(stream);
    http.serve_connection(io, service).await?;

    Ok(())
}

async fn handle_request(
    mut req: Request<Incoming>,
    state: Arc<AppState>,
    remote_addr: SocketAddr,
) -> Result<ErrorResponse> {
    let host = req
        .headers()
        .get(HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let path = req.uri().path();

    debug!(
        "Incoming request: host={} path={} method={}",
        host,
        path,
        req.method()
    );

    let router = state.router.load();

    let route = match router.match_route(host, path) {
        Some(r) => r,
        None => {
            debug!("No route matched for host={} path={}", host, path);
            return Ok(not_found(&state));
        }
    };

    debug!("Matched route with {} candidates", route.candidates().len());

    // Rate limiting check
    let ip = remote_addr.ip();
    let route_key = route.key();

    // Check per-route rate limit first, then global rate limit
    let allowed = if let Some(route_limiter) = state.route_ratelimiters.get(route_key) {
        route_limiter.check(ip)
    } else if let Some(ref global_limiter) = state.ratelimiter {
        global_limiter.check(ip)
    } else {
        true
    };

    if !allowed {
        debug!("Rate limited: ip={} route={}", ip, route_key);
        return Ok(rate_limited(&state));
    }

    let origin = match route
        .load_balancer()
        .select_origin(route.candidates(), &state.origin_states)
        .await
    {
        Some(o) => o,
        None => {
            warn!(
                "No healthy origin available for host={} path={}",
                host, path
            );
            return Ok(bad_gateway(&state, "No healthy origins available"));
        }
    };

    debug!("Selected origin: {}", origin.url);

    let start = Instant::now();

    let result = proxy_request(&mut req, &origin, &state.client).await;

    let latency = start.elapsed();
    let origin_url = &origin.url_key;

    metrics::histogram!("upstreamer_proxy_request_duration_nanoseconds", "origin" => origin_url.clone())
        .record(latency.as_nanos() as f64);

    if let Some(origin_state) = state.origin_states.get(origin_url) {
        origin_state.increment_requests();
        origin_state.record_latency(latency);

        let config = state.config.load();
        let passive = &config.health.passive;

        if passive.enabled {
            match &result {
                Ok(resp) if resp.status().is_server_error() => {
                    warn!(
                        "Origin {} returned {} for {} {}",
                        origin.url,
                        resp.status(),
                        req.method(),
                        req.uri().path()
                    );
                    origin_state.record_failure_with_threshold(passive.failure_threshold);
                }
                Ok(_) => {
                    origin_state.record_success_with_threshold(passive.success_threshold);
                }
                Err(e) => {
                    error!("Failed to proxy to {}: {}", origin.url, e);
                    origin_state.record_failure_with_threshold(passive.failure_threshold);
                }
            }
        } else {
            match &result {
                Ok(resp) if resp.status().is_server_error() => {
                    warn!(
                        "Origin {} returned {} for {} {}",
                        origin.url,
                        resp.status(),
                        req.method(),
                        req.uri().path()
                    );
                    origin_state.record_failure();
                }
                Ok(_) => {
                    origin_state.record_success();
                }
                Err(e) => {
                    error!("Failed to proxy to {}: {}", origin.url, e);
                    origin_state.record_failure();
                }
            }
        }
    }

    if let Ok(ref resp) = result {
        info!(
            "{} {} → {} [{}] {:.1?}",
            req.method(),
            req.uri().path(),
            origin.url,
            resp.status().as_u16(),
            latency
        );
    }

    result
}

async fn proxy_request(
    req: &mut Request<Incoming>,
    origin: &crate::balance::OriginEndpoint,
    client: &hyper_util::client::legacy::Client<
        hyper_util::client::legacy::connect::HttpConnector,
        Full<Bytes>,
    >,
) -> Result<ErrorResponse> {
    let origin_uri = format!(
        "{}{}",
        origin.url.as_str().trim_end_matches('/'),
        req.uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("")
    );

    let mut builder = Request::builder().method(req.method()).uri(&origin_uri);

    for (name, value) in req.headers().iter() {
        if name != HOST {
            builder = builder.header(name, value);
        }
    }

    let authority = origin.url.authority();
    builder = builder.header(HOST, authority);

    let body = collect_body(req).await?;

    let outgoing_req = builder.body(Full::new(body))?;

    let response = client.request(outgoing_req).await?;

    let status = response.status();
    let headers = response.headers().clone();
    let body = response.collect().await?.to_bytes();

    let mut resp = Response::new(Full::new(body));
    *resp.status_mut() = status;
    *resp.headers_mut() = headers;

    Ok(resp)
}

async fn collect_body(req: &mut Request<Incoming>) -> Result<Bytes> {
    let body = req.body_mut();
    let mut buf = BytesMut::new();

    while let Some(frame_result) = body.frame().await {
        let frame = frame_result?;
        if let Ok(chunk) = frame.into_data() {
            buf.extend_from_slice(&chunk);
        }
    }

    Ok(buf.freeze())
}

fn not_found(state: &AppState) -> ErrorResponse {
    crate::errors::get_error_response(state, StatusCode::NOT_FOUND, "Not Found")
}

fn bad_gateway(state: &AppState, message: &str) -> ErrorResponse {
    crate::errors::get_error_response(state, StatusCode::BAD_GATEWAY, message)
}

fn rate_limited(state: &AppState) -> ErrorResponse {
    crate::errors::get_error_response(state, StatusCode::TOO_MANY_REQUESTS, "Too Many Requests")
}
