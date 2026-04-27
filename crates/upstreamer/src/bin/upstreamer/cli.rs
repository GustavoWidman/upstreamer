use clap::Parser;
use std::path::PathBuf;

use upstreamer::config::ProxyConfig;

#[derive(Parser, Debug)]
#[command(name = "upstreamer")]
#[command(version, about = "A high-performance reverse proxy")]
pub struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "upstreamer.toml")]
    pub config: PathBuf,

    /// Validate configuration and exit
    #[arg(long)]
    pub validate: bool,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    pub log_level: String,
}

pub fn print_config_summary(config: &ProxyConfig) {
    println!("Configuration is valid");
    println!();
    println!("  listen:        {}", config.listen);
    println!("  metrics_addr:  {}", config.metrics_addr);

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

    if let Some(ref rl) = config.ratelimit {
        println!();
        println!("  ratelimit: rate={}/s burst={}", rl.rate, rl.burst);
    }

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

    if let Some(ref k8s) = config.kubernetes {
        println!();
        let ns = k8s.namespace.as_deref().unwrap_or("default");
        let sel = k8s.label_selector.as_deref().unwrap_or("(none)");
        println!("  kubernetes: namespace={} selector={}", ns, sel);
    }

    if let Some(ref ep) = config.error_pages {
        println!();
        println!("  error_pages: directory={}", ep.directory.display());
        for page in &ep.pages {
            println!("    {} -> {}", page.code, page.file);
        }
    }
}
