//! Docker containers shared by the integration tests.
//!
//! Each image runs in one named container that every test process reuses, across runs too
//! (testcontainers' `ReuseDirective::Always`). nextest runs each test in its own process, so a
//! container per process would pile up; `just test-clean` removes the shared ones.
//!
//! `DATABASE_URL` and `VALKEY_URL` point the tests at existing servers instead (CI services).

#![allow(dead_code, reason = "each test crate uses some of these")]

use std::time::Duration;

use testcontainers::{
    ContainerAsync, ContainerRequest, GenericImage, ImageExt, ReuseDirective,
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};
use tokio::sync::OnceCell;

/// Label on every test container, for `just test-clean`.
pub const LABEL: &str = "session-guard.test";

/// Starts (or joins) the shared container `name`. Processes racing to create it retry until
/// the winner's container is visible.
async fn shared(image: impl Fn() -> ContainerRequest<GenericImage>, port: u16, name: &str) -> (String, u16) {
    let container = shared_container(image, name).await;
    let host = container.get_host().await.expect("container host").to_string();
    let port = container.get_host_port_ipv4(port.tcp()).await.expect("container port");
    (host, port)
}

/// Starts (or joins) the shared container `name` without resolving any port.
async fn shared_container(
    image: impl Fn() -> ContainerRequest<GenericImage>,
    name: &str,
) -> ContainerAsync<GenericImage> {
    let mut attempt = 0;
    let container: ContainerAsync<GenericImage> = loop {
        let request = image()
            .with_container_name(name)
            .with_label(LABEL, "1")
            .with_reuse(ReuseDirective::Always);
        match request.start().await {
            Ok(container) => break container,
            Err(e) if attempt < 40 => {
                attempt += 1;
                eprintln!("joining test container {name} (attempt {attempt}): {e}");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => panic!("start test container {name}: {e}"),
        }
    };
    container
}

/// URL of the shared Valkey, or `VALKEY_URL`.
pub async fn valkey_url() -> &'static str {
    static URL: OnceCell<String> = OnceCell::const_new();
    URL.get_or_init(|| async {
        if let Ok(url) = std::env::var("VALKEY_URL") {
            return url;
        }
        let image = || {
            GenericImage::new("valkey/valkey", "8-alpine")
                .with_exposed_port(6379.tcp())
                .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
                .into()
        };
        let (host, port) = shared(image, 6379, "session-guard-test-valkey").await;
        format!("redis://{host}:{port}")
    })
    .await
}

/// Port of the shared single-node Valkey Cluster. The node announces `127.0.0.1:PORT`, so the
/// container uses host networking and a fixed port instead of a mapped one.
const CLUSTER_PORT: u16 = 7391;

/// Seed URL of a Valkey Cluster, or `VALKEY_CLUSTER_URL`.
///
/// The default is one cluster-enabled node owning all 16384 slots. That is enough to catch
/// every `CROSSSLOT` error, which the server raises per slot, not per node.
pub async fn valkey_cluster_url() -> &'static str {
    static URL: OnceCell<String> = OnceCell::const_new();
    URL.get_or_init(|| async {
        if let Ok(url) = std::env::var("VALKEY_CLUSTER_URL") {
            return url;
        }
        let script = format!(
            "valkey-server --port {CLUSTER_PORT} --cluster-enabled yes --cluster-announce-ip 127.0.0.1 \
             --cluster-config-file /tmp/nodes.conf --save '' & \
             until valkey-cli -p {CLUSTER_PORT} cluster addslotsrange 0 16383 >/dev/null 2>&1; do sleep 0.2; done; \
             echo cluster-slots-assigned; wait"
        );
        let image = || {
            GenericImage::new("valkey/valkey", "8-alpine")
                .with_entrypoint("sh")
                .with_wait_for(WaitFor::message_on_stdout("cluster-slots-assigned"))
                .with_network("host")
                .with_cmd(["-c", script.as_str()])
        };
        let _container = shared_container(image, "session-guard-test-cluster").await;
        format!("redis://127.0.0.1:{CLUSTER_PORT}")
    })
    .await
}

/// URL of the shared Postgres, or `DATABASE_URL`.
pub async fn postgres_url() -> &'static str {
    static URL: OnceCell<String> = OnceCell::const_new();
    URL.get_or_init(|| async {
        if let Ok(url) = std::env::var("DATABASE_URL") {
            return url;
        }
        let image = || {
            GenericImage::new("postgres", "18-alpine")
                .with_exposed_port(5432.tcp())
                .with_wait_for(WaitFor::message_on_stderr(
                    "database system is ready to accept connections",
                ))
                .with_env_var("POSTGRES_PASSWORD", "postgres")
        };
        let (host, port) = shared(image, 5432, "session-guard-test-postgres").await;
        format!("postgres://postgres:postgres@{host}:{port}/postgres")
    })
    .await
}
