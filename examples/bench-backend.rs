use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

static SERVED: AtomicU64 = AtomicU64::new(0);

async fn handle(_: Request<hyper::body::Incoming>) -> Result<Response<String>, Infallible> {
    SERVED.fetch_add(1, Ordering::Relaxed);
    Ok(Response::builder()
        .header("Content-Type", "text/plain")
        .header("Content-Length", "2")
        .body("ok".into())
        .unwrap())
}

#[tokio::main]
async fn main() {
    let addr: SocketAddr = "127.0.0.1:18080".parse().unwrap();
    let listener = TcpListener::bind(addr).await.unwrap();
    println!("bench-backend listening on {addr}");

    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let io = TokioIo::new(stream);
        tokio::spawn(async move {
            let _ = hyper::server::conn::http1::Builder::new()
                .keep_alive(true)
                .serve_connection(io, service_fn(handle))
                .await;
        });
    }
}
