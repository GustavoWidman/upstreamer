use crate::state::AppState;
use bytes::Bytes;
use dashmap::DashMap;
use tracing::{info, warn};

pub struct ErrorPageStore {
    pages: DashMap<u16, Bytes>,
}

impl ErrorPageStore {
    pub fn from_config(config: &crate::config::ErrorPagesConfig) -> Self {
        let pages = DashMap::new();
        for page in &config.pages {
            let path = config.directory.join(&page.file);
            match std::fs::read(&path) {
                Ok(content) => {
                    info!("Loaded custom error page for status {}: {}", page.code, page.file);
                    pages.insert(page.code, Bytes::from(content));
                }
                Err(e) => {
                    warn!(
                        "Failed to load error page {} for status {}: {}",
                        page.file, page.code, e
                    );
                }
            }
        }
        Self { pages }
    }

    pub fn get(&self, status: u16) -> Option<Bytes> {
        self.pages.get(&status).map(|p| p.value().clone())
    }
}

pub fn get_error_response(
    state: &AppState,
    status: hyper::StatusCode,
    default_body: &str,
) -> crate::server::ErrorResponse {
    let code = status.as_u16();

    if let Some(ref store) = state.error_pages
        && let Some(body) = store.get(code)
    {
        return hyper::Response::builder()
            .status(status)
            .header("Content-Type", "text/html")
            .body(http_body_util::Full::new(body))
            .expect("error page response builder");
    }

    hyper::Response::builder()
        .status(status)
        .body(http_body_util::Full::new(Bytes::from(default_body.to_string())))
        .expect("default error response builder")
}
