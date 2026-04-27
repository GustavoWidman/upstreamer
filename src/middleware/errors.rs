use crate::state::AppState;
use bytes::Bytes;
use dashmap::DashMap;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use tracing::{info, warn};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub type ProxyBody = BoxBody<Bytes, BoxError>;

pub struct ErrorPageStore {
    pages: DashMap<u16, Bytes>,
}

impl ErrorPageStore {
    pub fn from_config(config: &crate::config::parser::ErrorPagesConfig) -> Self {
        let pages = DashMap::new();
        for page in &config.pages {
            let path = config.directory.join(&page.file);
            match std::fs::read(&path) {
                Ok(content) => {
                    info!(
                        "Loaded custom error page for status {}: {}",
                        page.code, page.file
                    );
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

fn full_body(bytes: Bytes) -> ProxyBody {
    Full::new(bytes)
        .map_err(|e| -> BoxError { match e {} })
        .boxed()
}

pub fn get_error_response(
    state: &AppState,
    status: hyper::StatusCode,
    default_body: &str,
) -> hyper::Response<ProxyBody> {
    let code = status.as_u16();

    if let Some(ref store) = state.error_pages
        && let Some(body) = store.get(code)
    {
        return hyper::Response::builder()
            .status(status)
            .header("Content-Type", "text/html")
            .body(full_body(body))
            .expect("error page response builder");
    }

    hyper::Response::builder()
        .status(status)
        .body(full_body(Bytes::from(default_body.to_string())))
        .expect("default error response builder")
}
