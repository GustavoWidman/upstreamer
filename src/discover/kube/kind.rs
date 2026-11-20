//! The client against a real API server. Ignored unless `tests/kubernetes/run.sh` provides a
//! kind cluster and the two kubeconfigs named below; it runs these with `--ignored`.
//!
//! The cluster holds Deployment `web` (label `app=web`, port `http` 8080) and Service `web`
//! (label `upstreamer.example/pool=web`) in namespace `shop`. The source under test
//! authenticates as the ServiceAccount that only `docs/kubernetes-rbac.yaml` allows; the
//! test mutates the cluster with admin credentials through `kubectl`.

use super::*;
use serde_json::Value;
use std::collections::BTreeSet;
use std::process::Command;

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is set by tests/kubernetes/run.sh"))
}

fn kubectl(args: &[&str]) -> String {
    let out = Command::new("kubectl")
        .env("KUBECONFIG", env("UPSTREAMER_KIND_ADMIN"))
        .args(args)
        .output()
        .expect("kubectl is on PATH");
    assert!(
        out.status.success(),
        "kubectl {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// The pods that should be members: running, Ready, not being deleted.
fn ready_pods() -> BTreeSet<SocketAddr> {
    let pods: Value = serde_json::from_str(&kubectl(&[
        "-n", "shop", "get", "pods", "-l", "app=web", "-o", "json",
    ]))
    .unwrap();
    pods["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|pod| pod["metadata"]["deletionTimestamp"].is_null())
        .filter(|pod| {
            pod["status"]["conditions"].as_array().is_some_and(|c| {
                c.iter()
                    .any(|c| c["type"] == "Ready" && c["status"] == "True")
            })
        })
        .filter_map(|pod| pod["status"]["podIP"].as_str())
        .map(|ip| SocketAddr::new(ip.parse().unwrap(), 8080))
        .collect()
}

fn loader() -> Loader {
    let path = std::path::PathBuf::from(env("UPSTREAMER_KIND_RESTRICTED"));
    Arc::new(move || config::from_kubeconfig(&path))
}

fn service(name: &str) -> Arc<KubeWatch> {
    Arc::new(KubeWatch {
        namespace: "shop".into(),
        select: KubeSelect::Service(name.into()),
        port: KubePort::Name("http".into()),
    })
}

struct Cluster {
    thread: Thread,
    /// The last report of each source.
    last: HashMap<SourceKey, Found>,
}

impl Cluster {
    fn start(sources: &[Arc<KubeWatch>]) -> Cluster {
        let thread = Thread::spawn_with(loader(), Timing::default()).unwrap();
        thread.set_sources(sources.to_vec());
        Cluster {
            thread,
            last: HashMap::new(),
        }
    }

    /// Takes the reports that are already waiting.
    async fn drain(&mut self) {
        while let Ok(Some(found)) =
            tokio::time::timeout(Duration::from_millis(50), self.thread.recv()).await
        {
            self.last.insert(found.source.clone(), found);
        }
    }

    /// Reads reports until `done` accepts the latest of `source`, or `within` passes.
    async fn until(
        &mut self,
        source: &Arc<KubeWatch>,
        within: Duration,
        what: &str,
        mut done: impl FnMut(&Found) -> bool,
    ) -> Found {
        let key = SourceKey::Kubernetes(source.clone());
        let deadline = Instant::now() + within;
        loop {
            self.drain().await;
            if let Some(found) = self.last.get(&key)
                && done(found)
            {
                return Found {
                    source: found.source.clone(),
                    endpoints: found.endpoints.clone(),
                    state: found.state.clone(),
                };
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {what}; last report: {:?}",
                self.last.get(&key)
            );
            if let Ok(Some(found)) =
                tokio::time::timeout(Duration::from_secs(1), self.thread.recv()).await
            {
                self.last.insert(found.source.clone(), found);
            }
        }
    }

    /// Waits until the cluster has `pods` ready pods and the source's synced set is exactly them.
    async fn converge(
        &mut self,
        source: &Arc<KubeWatch>,
        what: &str,
        pods: usize,
    ) -> BTreeSet<SocketAddr> {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let truth = ready_pods();
            let found = self
                .until(source, Duration::from_secs(3), what, |_| true)
                .await;
            let reported: BTreeSet<SocketAddr> = found.endpoints.iter().copied().collect();
            if matches!(found.state, SourceState::Synced)
                && reported == truth
                && truth.len() == pods
            {
                return truth;
            }
            assert!(
                Instant::now() < deadline,
                "{what}: reported {reported:?} while the ready pods are {truth:?}"
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}

fn scale(replicas: u32) {
    kubectl(&[
        "-n",
        "shop",
        "scale",
        "deploy/web",
        &format!("--replicas={replicas}"),
    ]);
}

#[tokio::test]
#[ignore = "needs the kind cluster of tests/kubernetes/run.sh"]
async fn kind_1_service_and_selector_follow_scaling() {
    let by_service = service("web");
    let by_labels = Arc::new(KubeWatch {
        namespace: "shop".into(),
        select: KubeSelect::Labels("upstreamer.example/pool=web".into()),
        port: KubePort::Name("http".into()),
    });
    scale(3);
    kubectl(&[
        "-n",
        "shop",
        "rollout",
        "status",
        "deploy/web",
        "--timeout=180s",
    ]);
    let mut cluster = Cluster::start(&[by_service.clone(), by_labels.clone()]);
    let three = cluster
        .converge(&by_service, "three pods by service", 3)
        .await;
    assert_eq!(three.len(), 3);
    let copied = cluster
        .converge(&by_labels, "three pods by selector", 3)
        .await;
    assert_eq!(
        copied, three,
        "the selector reads the Service labels the slices carry"
    );

    scale(5);
    let five = cluster.converge(&by_service, "scaled to five", 5).await;
    assert_eq!(five.len(), 5);
    assert_eq!(
        cluster.converge(&by_labels, "five by selector", 5).await,
        five
    );

    scale(1);
    let one = cluster.converge(&by_service, "scaled to one", 1).await;
    assert_eq!(one.len(), 1);
}

#[tokio::test]
#[ignore = "needs the kind cluster of tests/kubernetes/run.sh"]
async fn kind_2_a_rollout_restart_never_leaves_the_set_empty() {
    let source = service("web");
    scale(3);
    kubectl(&[
        "-n",
        "shop",
        "rollout",
        "status",
        "deploy/web",
        "--timeout=180s",
    ]);
    let mut cluster = Cluster::start(std::slice::from_ref(&source));
    let before = cluster.converge(&source, "three pods", 3).await;

    kubectl(&["-n", "shop", "rollout", "restart", "deploy/web"]);
    let rollout = std::thread::spawn(|| {
        kubectl(&[
            "-n",
            "shop",
            "rollout",
            "status",
            "deploy/web",
            "--timeout=300s",
        ]);
    });
    let mut reports = 0;
    while !rollout.is_finished() {
        if let Ok(Some(found)) =
            tokio::time::timeout(Duration::from_millis(200), cluster.thread.recv()).await
        {
            if matches!(found.state, SourceState::Synced) {
                reports += 1;
                assert!(
                    !found.endpoints.is_empty(),
                    "a rollout with maxUnavailable 0 never leaves no ready endpoint"
                );
            }
            cluster.last.insert(found.source.clone(), found);
        }
    }
    rollout.join().unwrap();
    let after = cluster.converge(&source, "the new pods", 3).await;
    assert!(
        reports >= 2,
        "a rollout is several reports, not one: {reports}"
    );
    assert!(
        before.is_disjoint(&after),
        "every pod was replaced: {before:?} then {after:?}"
    );
}

#[tokio::test]
#[ignore = "needs the kind cluster of tests/kubernetes/run.sh"]
async fn kind_3_the_role_covers_its_namespace_and_nothing_else() {
    let path = std::path::PathBuf::from(env("UPSTREAMER_KIND_RESTRICTED"));
    let mut cluster = config::from_kubeconfig(&path).unwrap();
    let ok = api::get(
        &mut cluster,
        "/apis/discovery.k8s.io/v1/namespaces/shop/endpointslices",
        Duration::from_secs(10),
    )
    .await;
    assert!(
        ok.is_ok(),
        "the documented Role lists slices in its namespace: {:?}",
        ok.err()
    );
    for forbidden in [
        "/apis/discovery.k8s.io/v1/namespaces/kube-system/endpointslices",
        "/api/v1/namespaces/shop/secrets",
        "/api/v1/namespaces/shop/services",
        "/api/v1/namespaces/shop/pods",
    ] {
        let failure = api::get(&mut cluster, forbidden, Duration::from_secs(10))
            .await
            .err()
            .unwrap_or_else(|| panic!("{forbidden} must be forbidden"));
        assert!(
            failure.to_string().contains("HTTP 403"),
            "{forbidden}: {failure}"
        );
    }

    let outside = Arc::new(KubeWatch {
        namespace: "kube-system".into(),
        select: KubeSelect::Service("kube-dns".into()),
        port: KubePort::Number(53),
    });
    let mut run = Cluster::start(std::slice::from_ref(&outside));
    let found = run
        .until(&outside, Duration::from_secs(20), "the 403", |found| {
            matches!(&found.state, SourceState::Unreachable { error, .. } if error.contains("forbidden"))
        })
        .await;
    assert!(found.endpoints.is_empty());
}

#[tokio::test]
#[ignore = "needs the kind cluster of tests/kubernetes/run.sh"]
async fn kind_4_an_api_server_outage_keeps_the_endpoints_and_resyncs() {
    let source = service("web");
    scale(3);
    kubectl(&[
        "-n",
        "shop",
        "rollout",
        "status",
        "deploy/web",
        "--timeout=180s",
    ]);
    let mut cluster = Cluster::start(std::slice::from_ref(&source));
    let before = cluster.converge(&source, "three pods", 3).await;

    let node = env("UPSTREAMER_KIND_NODE");
    let manifest = "/etc/kubernetes/manifests/kube-apiserver.yaml";
    let parked = "/etc/kubernetes/kube-apiserver.yaml.parked";
    let docker = |script: String| {
        let status = Command::new("docker")
            .args(["exec", &node, "sh", "-c", &script])
            .status()
            .unwrap();
        assert!(status.success(), "docker exec {script}");
    };
    docker(format!("mv {manifest} {parked}"));
    let down = cluster
        .until(&source, Duration::from_secs(180), "the outage", |found| {
            matches!(found.state, SourceState::Unreachable { .. })
        })
        .await;
    let held: BTreeSet<SocketAddr> = down.endpoints.iter().copied().collect();
    assert_eq!(
        held, before,
        "the last endpoints stay in use while the API server is gone"
    );

    docker(format!("mv {parked} {manifest}"));
    cluster
        .until(
            &source,
            Duration::from_secs(240),
            "the API server back",
            |found| matches!(found.state, SourceState::Synced),
        )
        .await;
    let after = cluster
        .converge(&source, "the set after the outage", 3)
        .await;
    assert_eq!(after, before, "nothing changed while it was away");
}
