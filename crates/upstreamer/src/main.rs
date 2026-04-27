use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;

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
#[command(version, about = "A high-performance reverse proxy")]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "upstreamer.toml")]
    config: PathBuf,

    /// Validate configuration and exit
    #[arg(long)]
    validate: bool,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level));

    fmt().with_env_filter(filter).init();

    let config = config::ProxyConfig::load(&args.config)?;

    config.validate()?;

    if args.validate {
        print_config_summary(&config);
        return Ok(());
    }

    let rt = tokio::runtime::Runtime::new()?;

    rt.block_on(async {
        let metrics_handle = metrics::init();

        let state = Arc::new(state::AppState::new(config, metrics_handle));

        info!("upstreamer v{} starting...", env!("CARGO_PKG_VERSION"));
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

fn print_config_summary(config: &config::ProxyConfig) {
    println!("Configuration is valid");
    println!();
    println!("  listen:        {}", config.listen);
    println!("  metrics_addr:  {}", config.metrics_addr);

    // Routes
    println!();
    println!("  routes ({}):", config.routes.len());
    for (i, route) in config.routes.iter().enumerate() {
        let host = route.match_host.as_deref().unwrap_or("*");
        let path = route.match_path.as_deref().unwrap_or("/");
        let algo = format!("{:?}", route.lb_algorithm).to_lowercase();
        println!("    [{}] host={} path={} algo={}", i, host, path, algo);

        for pool in &route.pools {
            println!("      pool: {}", pool.name);
            for origin in &pool.origins {
                let weight = origin
                    .weight
                    .map(|w| format!(" weight={}", w))
                    .unwrap_or_default();
                println!("        - {}{}", origin.url, weight);
            }
        }

        if let Some(ref rl) = route.ratelimit {
            println!("      ratelimit: rate={}/s burst={}", rl.rate, rl.burst);
        }
    }

    // Global rate limit
    if let Some(ref rl) = config.ratelimit {
        println!();
        println!("  ratelimit: rate={}/s burst={}", rl.rate, rl.burst);
    }

    // Health
    let a = &config.health.active;
    let p = &config.health.passive;
    println!();
    println!("  health:");
    println!(
        "    active:  enabled={} interval={:?} timeout={:?} thresholds={}/{}",
        a.enabled, a.interval, a.timeout, a.healthy_threshold, a.unhealthy_threshold
    );
    println!(
        "    passive: enabled={} failure_threshold={} success_threshold={}",
        p.enabled, p.failure_threshold, p.success_threshold
    );

    // K8s
    if let Some(ref k8s) = config.kubernetes {
        println!();
        let ns = k8s.namespace.as_deref().unwrap_or("default");
        let sel = k8s.label_selector.as_deref().unwrap_or("(none)");
        println!("  kubernetes: namespace={} selector={}", ns, sel);
    }

    // Error pages
    if let Some(ref ep) = config.error_pages {
        println!();
        println!("  error_pages: directory={}", ep.directory.display());
        for page in &ep.pages {
            println!("    {} -> {}", page.code, page.file);
        }
    }
}
