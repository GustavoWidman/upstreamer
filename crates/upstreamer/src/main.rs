use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::fmt;
use tracing_subscriber::EnvFilter;

mod balance;
mod config;
mod discovery;
mod errors;
mod health;
mod metrics;
mod ratelimit;
mod reload;
mod route;
mod server;
mod state;

#[derive(Parser, Debug)]
#[command(name = "upstreamer")]
#[command(version = "0.1.0")]
#[command(about = "A high-performance reverse proxy", long_about = None)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "upstreamer.toml")]
    config: PathBuf,

    /// Validate configuration and exit
    #[arg(long)]
    validate: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    fmt().with_env_filter(filter).init();

    let config = config::ProxyConfig::load(&args.config)?;

    config.validate()?;

    if args.validate {
        println!("Configuration is valid");
        println!("  Listen address: {}", config.listen);
        println!("  Metrics address: {}", config.metrics_addr);
        println!("  Routes: {}", config.routes.len());
        for (i, route) in config.routes.iter().enumerate() {
            let host_match = route.match_host.as_deref().unwrap_or("*");
            let path_match = route.match_path.as_deref().unwrap_or("/");
            println!("    [{}]: host={} path={} pools={}", i, host_match, path_match, route.pools.len());
        }
        return Ok(());
    }

    let rt = tokio::runtime::Runtime::new()?;

    rt.block_on(async {
        let metrics_handle = metrics::init();

        let state = Arc::new(state::AppState::new(config, metrics_handle));

        info!("upstreamer v0.1.0 starting...");
        info!("  Listen: {}", state.config.load().listen);
        info!("  Metrics: {}", state.config.load().metrics_addr);
        info!("  Routes: {}", state.config.load().routes.len());

        for (i, route) in state.config.load().routes.iter().enumerate() {
            let host_match = route.match_host.as_deref().unwrap_or("*");
            let path_match = route.match_path.as_deref().unwrap_or("/");
            let algo = format!("{:?}", route.lb_algorithm);
            info!(
                "    [{}]: host={} path={} algo={} pools={}",
                i,
                host_match,
                path_match,
                algo,
                route.pools.len()
            );
        }

        // Spawn background task to clean up stale rate limit buckets
        let state_clone = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                if let Some(ref limiter) = state_clone.ratelimiter {
                    limiter.cleanup_stale(std::time::Duration::from_secs(300));
                }
                for limiter in state_clone.route_ratelimiters.iter() {
                    limiter.cleanup_stale(std::time::Duration::from_secs(300));
                }
            }
        });

        // Spawn active health checker
        if state.config.load().health.active.enabled {
            let state_clone = state.clone();
            tokio::spawn(async move {
                health::run_active_checks(state_clone).await;
            });
        }

        // Spawn self-metrics collection
        {
            let state_clone = state.clone();
            tokio::spawn(async move {
                metrics::collect_self_metrics(state_clone).await;
            });
        }

        // Spawn k8s service discovery
        if state.config.load().kubernetes.is_some() {
            let state_clone = state.clone();
            tokio::spawn(async move {
                if let Err(e) = discovery::run_k8s_discovery(state_clone).await {
                    tracing::error!("k8s discovery error: {}", e);
                }
            });
        }

        // Spawn config file watcher for hot-reload
        {
            let state_clone = state.clone();
            let config_path = args.config.clone();
            tokio::spawn(async move {
                if let Err(e) = reload::watch_config(state_clone, config_path).await {
                    tracing::error!("config watcher error: {}", e);
                }
            });
        }

        // Run proxy and health server concurrently
        let proxy_state = state.clone();
        let health_state = state.clone();
        tokio::select! {
            r = server::run_proxy(proxy_state) => {
                if let Err(e) = r {
                    tracing::error!("Proxy server error: {}", e);
                }
            }
            r = health::run_health_server(health_state) => {
                if let Err(e) = r {
                    tracing::error!("Health server error: {}", e);
                }
            }
        }
    });

    Ok(())
}
