use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

pub fn init() -> PrometheusHandle {
    PrometheusBuilder::new()
        .set_buckets(&[
            50_000.0,
            100_000.0,
            250_000.0,
            500_000.0,
            1_000_000.0,
            2_500_000.0,
            5_000_000.0,
            10_000_000.0,
            50_000_000.0,
            100_000_000.0,
        ])
        .expect("invalid buckets")
        .install_recorder()
        .expect("failed to install Prometheus recorder")
}

pub async fn collect_self_metrics(state: std::sync::Arc<crate::state::AppState>) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
    loop {
        interval.tick().await;

        // RSS from /proc/self/statm (page index 2, in pages)
        if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
            let parts: Vec<&str> = statm.split_whitespace().collect();
            if parts.len() >= 2
                && let Ok(rss_pages) = parts[1].parse::<u64>()
            {
                let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 };
                let rss_bytes = rss_pages * page_size;
                metrics::gauge!("upstreamer_process_resident_memory_bytes").set(rss_bytes as f64);
            }
        }

        // Open FDs from /proc/self/fd
        if let Ok(fd_dir) = std::fs::read_dir("/proc/self/fd") {
            let count = fd_dir.count();
            metrics::gauge!("upstreamer_process_open_fds").set(count as f64);
        }

        // CPU time from /proc/self/stat (field 14=utime, 15=stime, in clock ticks)
        if let Ok(stat) = std::fs::read_to_string("/proc/self/stat") {
            let fields: Vec<&str> = stat.split_whitespace().collect();
            if fields.len() >= 15 {
                let utime: u64 = fields[13].parse().unwrap_or(0);
                let stime: u64 = fields[14].parse().unwrap_or(0);
                let ticks = utime + stime;
                let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) as u64 };
                if clk_tck > 0 {
                    let cpu_secs = ticks as f64 / clk_tck as f64;
                    metrics::gauge!("upstreamer_process_cpu_seconds_total").set(cpu_secs);
                }
            }
        }

        // Aggregate origin counts
        let total = state.origin_states.len();
        let healthy = state
            .origin_states
            .iter()
            .filter(|e| e.value().healthy.load(std::sync::atomic::Ordering::Relaxed))
            .count();
        metrics::gauge!("upstreamer_total_origins").set(total as f64);
        metrics::gauge!("upstreamer_healthy_origins").set(healthy as f64);
    }
}
