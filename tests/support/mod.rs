//! Docker containers shared by the integration tests.
//!
//! Each image runs in one named container that every test process reuses, across runs too
//! (testcontainers' `ReuseDirective::Always`). nextest runs each test in its own process, so a
//! container per process would pile up; `just test-clean` removes the shared ones.

#![allow(dead_code, reason = "each test crate uses some of these")]

use std::time::Duration;

use testcontainers::{
    ContainerAsync, GenericImage, ImageExt, ReuseDirective,
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};
use tokio::sync::OnceCell;

/// Label on every test container, for `just test-clean`.
pub const LABEL: &str = "session-guard.test";

/// Starts (or joins) the shared container `name`. Processes racing to create it retry until
/// the winner's container is visible.
async fn shared(image: GenericImage, port: u16, name: &str) -> (String, u16) {
    let mut attempt = 0;
    let container: ContainerAsync<GenericImage> = loop {
        let request = image
            .clone()
            .with_container_name(name)
            .with_label(LABEL, "1")
            .with_reuse(ReuseDirective::Always);
        match request.start().await {
            Ok(container) => break container,
            Err(e) if attempt < 10 => {
                attempt += 1;
                eprintln!("joining test container {name} (attempt {attempt}): {e}");
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            Err(e) => panic!("start test container {name}: {e}"),
        }
    };
    let host = container.get_host().await.expect("container host").to_string();
    let port = container.get_host_port_ipv4(port.tcp()).await.expect("container port");
    (host, port)
}

/// URL of the shared Valkey.
pub async fn valkey_url() -> &'static str {
    static URL: OnceCell<String> = OnceCell::const_new();
    URL.get_or_init(|| async {
        let image = GenericImage::new("valkey/valkey", "8-alpine")
            .with_exposed_port(6379.tcp())
            .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"));
        let (host, port) = shared(image, 6379, "session-guard-test-valkey").await;
        format!("redis://{host}:{port}")
    })
    .await
}
