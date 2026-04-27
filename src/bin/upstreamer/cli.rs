use clap::Parser;
use std::path::PathBuf;

use upstreamer::config::parser::ProxyConfig;

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

fn green(s: &str) -> String {
    format!("\x1b[32m{}\x1b[0m", s)
}

fn dim(s: &str) -> String {
    format!("\x1b[2m{}\x1b[0m", s)
}

pub fn print_config_summary(config: &ProxyConfig) {
    let version = env!("CARGO_PKG_VERSION");
    println!(
        "  {} upstreamer v{} — {}",
        green("✓"),
        version,
        green("configuration valid")
    );
    println!();
    println!("  {} {}", dim("listen:"), config.listen);
    println!("  {} {}", dim("metrics:"), config.metrics_addr);

    println!();
    println!("  {} {}", dim("routes:"), config.routes.len());
    for (i, route) in config.routes.iter().enumerate() {
        let host = route.match_host.as_deref().unwrap_or("*");
        let path = route.match_path.as_deref().unwrap_or("/");
        let algo = format!("{:?}", route.lb_algorithm).to_lowercase();

        println!();
        println!("  {} [{}]", dim("route"), i);
        println!("    {:10} {} {}", dim("match:"), host, path);
        println!("    {:10} {}", dim("algo:"), algo);

        for pool in &route.pools {
            println!("    {:10} {}", dim("pool:"), pool.name);
            for origin in &pool.origins {
                let weight = origin
                    .weight
                    .map(|w| format!(" {}", dim(&format!("weight={}", w))))
                    .unwrap_or_default();
                println!("      {} {}{}", dim("→"), origin.url, weight);
            }
        }

        if let Some(ref rl) = route.ratelimit {
            println!(
                "    {:10} {}/s burst={}",
                dim("ratelimit:"),
                rl.rate,
                rl.burst
            );
        }
    }

    if let Some(ref rl) = config.ratelimit {
        println!();
        println!("  {} {}/s burst={}", dim("ratelimit:"), rl.rate, rl.burst);
    }

    let a = &config.health.active;
    let p = &config.health.passive;
    println!();
    println!("  {}", dim("health:"));
    if a.enabled {
        println!(
            "    {:10} {} interval={:?} timeout={:?} thresholds={}/{}",
            dim("active:"),
            green("on"),
            a.interval,
            a.timeout,
            a.healthy_threshold,
            a.unhealthy_threshold
        );
    } else {
        println!("    {:10} \x1b[31moff\x1b[0m", dim("active:"));
    }
    println!(
        "    {:10} failures={} successes={}",
        dim("passive:"),
        p.failure_threshold,
        p.success_threshold
    );

    if let Some(ref k8s) = config.kubernetes {
        println!();
        let ns = k8s.namespace.as_deref().unwrap_or("default");
        let sel = k8s.label_selector.as_deref().unwrap_or("(none)");
        println!("  {} ns={} selector={}", dim("kubernetes:"), ns, sel);
    }

    if let Some(ref ep) = config.error_pages {
        println!();
        println!("  {} {}", dim("error_pages:"), ep.directory.display());
        for page in &ep.pages {
            println!("    {} → {}", page.code, page.file);
        }
    }
}
