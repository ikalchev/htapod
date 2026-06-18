use crate::{netstack::netstack::Stream, TCPFilter};
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

struct ProxyService {
    sender: Arc<Mutex<SendRequest<Incoming>>>,
}

impl ProxyService {
    async fn new(stream: Box<dyn Stream>) -> Self {
        let io = TokioIo::new(stream);
        let (sender, connection) = hyper::client::conn::http1::handshake(io).await.unwrap();

        tokio::task::spawn(async move {
            if let Err(err) = connection.await {
                // TODO
                println!("Connection failed: {:?}", err);
            }
        });

        Self {
            sender: Arc::new(Mutex::new(sender)),
        }
    }
}

impl hyper::service::Service<Request<Incoming>> for ProxyService {
    type Response = Response<Incoming>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, request: Request<Incoming>) -> Self::Future {
        let response = {
            let mut sender = self.sender.lock().unwrap();
            sender.send_request(request)
        };
        Box::pin(response)
    }
}

struct UpstreamState {
    upstreams: HashMap<u32, Box<dyn Stream>>,
}

impl UpstreamState {
    fn new() -> Self {
        Self {
            upstreams: HashMap::new(),
        }
    }
}

pub struct HTTPFilter {
    uds_path: String,
    upstream_state: Arc<Mutex<UpstreamState>>,
    next_upstream_token: AtomicU32,
    server_handle: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for HTTPFilter {
    fn drop(&mut self) {
        // Clean up the Unix domain socket file when the filter is dropped
        if Path::new(&self.uds_path).exists() {
            let _ = std::fs::remove_file(&self.uds_path);
        }

        // The server_handle will be automatically dropped here, which will
        // cancel the tokio task and stop the server
    }
}

impl Default for HTTPFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl HTTPFilter {
    pub fn new() -> HTTPFilter {
        HTTPFilter {
            uds_path: "htapod.sock".to_owned(),
            server_handle: None,
            upstream_state: Arc::new(Mutex::new(UpstreamState::new())),
            next_upstream_token: AtomicU32::new(0),
        }
    }
}

impl TCPFilter for HTTPFilter {
    fn prepare(&mut self) -> std::io::Result<()> {
        if Path::new(&self.uds_path).exists() {
            std::fs::remove_file(&self.uds_path)?;
        }

        let uds_path = self.uds_path.clone();

        let upstream_state = self.upstream_state.clone();
        let handle = tokio::spawn(async move {
            let listener = UnixListener::bind(&uds_path).expect("Failed to bind Unix socket");

            loop {
                match listener.accept().await {
                    Ok((mut socket, _addr)) => {
                        // Get the upstream corresponding to this socket connection. This will be hinted by the other
                        // end in the first `u32` on the wire.
                        let upstream_token = socket.read_u32().await.unwrap();
                        let upstream = {
                            let mut upstream_state = upstream_state.lock().unwrap();
                            upstream_state.upstreams.remove(&upstream_token).unwrap()
                        };
                        let proxy_service = ProxyService::new(upstream).await;

                        let io = TokioIo::new(socket);
                        tokio::task::spawn(async move {
                            // TODO: Handle http2
                            if let Err(err) = hyper::server::conn::http1::Builder::new()
                                .serve_connection(io, proxy_service)
                                .await
                            {
                                println!("Failed to serve connection: {:?}", err);
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("Accept error: {}", e);
                        break;
                    }
                }
            }
        });

        self.server_handle = Some(handle);
        Ok(())
    }

    fn handle_new_connection(
        &mut self,
        _userspace_address: std::net::SocketAddr,
        mut userspace_stream: Box<dyn Stream>,
        _www_address: std::net::SocketAddr,
        upstream_stream: Box<dyn Stream>,
    ) {
        let upstream_token = self.next_upstream_token.fetch_add(1, Ordering::Relaxed);
        self.upstream_state.lock().map(|mut state| {
            state.upstreams.insert(upstream_token, upstream_stream);
            ()
        });

        let uds_path = self.uds_path.clone();
        tokio::spawn(async move {
            let mut proxy_stream = UnixStream::connect(uds_path).await.unwrap();
            proxy_stream.write_u32(upstream_token).await.unwrap();

            let result =
                tokio::io::copy_bidirectional(&mut userspace_stream, &mut proxy_stream).await;

            match result {
                Ok((from, to)) => log::debug!("Copied {} bytes from, {} bytes to.", from, to),
                Err(error) => log::error!("Failed to copy between streams: {:?}", error),
            }
        });
    }
}
