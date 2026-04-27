use crate::state::AppState;
use anyhow::Result;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{info, warn};

pub async fn watch_config(state: Arc<AppState>, config_path: PathBuf) -> Result<()> {
    let (tx, mut rx) = mpsc::channel::<()>(16);

    let mut watcher = RecommendedWatcher::new(
        move |res: Result<notify::Event, notify::Error>| {
            if let Ok(event) = res
                && (event.kind.is_modify() || event.kind.is_create())
            {
                let _ = tx.blocking_send(());
            }
        },
        notify::Config::default().with_poll_interval(Duration::from_secs(1)),
    )?;

    watcher.watch(&config_path, RecursiveMode::NonRecursive)?;
    info!("Watching config file: {}", config_path.display());

    // Debounce: wait for 500ms of silence after first event
    while rx.recv().await.is_some() {
        // Drain any queued events for debouncing
        tokio::time::sleep(Duration::from_millis(500)).await;
        while rx.try_recv().is_ok() {}

        info!("Config file changed, reloading...");

        match crate::config::ProxyConfig::load(&config_path) {
            Ok(new_config) => match new_config.validate() {
                Ok(()) => {
                    info!(
                        "Config reloaded: {} routes, listen={}",
                        new_config.routes.len(),
                        new_config.listen
                    );

                    // Rebuild router
                    let router = crate::route::Router::from_config(&new_config);
                    state.router.swap(Arc::new(router));

                    // Update per-route ratelimiters
                    state.route_ratelimiters.clear();
                    for route in &new_config.routes {
                        if let Some(ref rl) = route.ratelimit {
                            let key = format!(
                                "{}:{}",
                                route.match_host.as_deref().unwrap_or("*"),
                                route.match_path.as_deref().unwrap_or("*")
                            );
                            state
                                .route_ratelimiters
                                .insert(key, crate::ratelimit::RateLimiter::new(rl.rate, rl.burst));
                        }
                    }

                    // Add origin states for any new origins
                    for route in &new_config.routes {
                        for pool in &route.pools {
                            for origin in &pool.origins {
                                state
                                    .origin_states
                                    .entry(origin.url.to_string())
                                    .or_insert_with(crate::balance::OriginState::new);
                            }
                        }
                    }

                    // Global ratelimiter changes take effect on next restart (v1 limitation)

                    // Swap the config last (everything else is ready)
                    state.config.swap(Arc::new(new_config));
                }
                Err(e) => {
                    warn!("Config validation failed, keeping current config: {}", e);
                }
            },
            Err(e) => {
                warn!("Failed to parse new config, keeping current: {}", e);
            }
        }
    }

    Ok(())
}
