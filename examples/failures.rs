use hudsucker::{
    async_trait::async_trait,
    certificate_authority::RcgenAuthority,
    hyper::{Body, Request, Response},
    tokio_tungstenite::tungstenite::Message,
    *,
};
use rand::Rng;
use rustls_pemfile as pemfile;
use std::net::SocketAddr;
use tracing::*;
use http::StatusCode;

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}

#[derive(Clone)]
struct FailHandler;

#[async_trait]
impl HttpHandler for FailHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        println!("{:?}", req);
        req.into()
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        let mut rng = rand::thread_rng();
        let n: f64 = rng.gen();
        if n >= 0.05 {
            println!("{:?}", res);
            res
        } else {
            println!("Fail!@!");
            let builder = Response::builder().status(StatusCode::SERVICE_UNAVAILABLE);
            builder.body(Body::empty()).unwrap()
        }
    }
}

#[async_trait]
impl WebSocketHandler for FailHandler {
    async fn handle_message(&mut self, _ctx: &WebSocketContext, msg: Message) -> Option<Message> {
        println!("{:?}", msg);
        Some(msg)
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let mut private_key_bytes: &[u8] = include_bytes!("ca/hudsucker.key");
    let mut ca_cert_bytes: &[u8] = include_bytes!("ca/hudsucker.cer");
    let private_key = rustls::PrivateKey(
        pemfile::pkcs8_private_keys(&mut private_key_bytes)
            .expect("Failed to parse private key")
            .remove(0),
    );
    let ca_cert = rustls::Certificate(
        pemfile::certs(&mut ca_cert_bytes)
            .expect("Failed to parse CA certificate")
            .remove(0),
    );

    let ca = RcgenAuthority::new(private_key, ca_cert, 1_000)
        .expect("Failed to create Certificate Authority");

    let proxy = Proxy::builder()
        .with_addr(SocketAddr::from(([127, 0, 0, 1], 3000)))
        .with_rustls_client()
        .with_ca(ca)
        .with_http_handler(FailHandler)
        .with_websocket_handler(FailHandler)
        .build();
    println!("Listening on 127.0.0.1:3000");

    if let Err(e) = proxy.start(shutdown_signal()).await {
        error!("{}", e);
    }
}
