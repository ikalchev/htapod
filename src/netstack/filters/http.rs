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

struct ProxyService<FReq, FRes>
where
    FReq: Fn(&Request<Incoming>),
    FRes: Fn(&Response<Incoming>) + Clone + Send + 'static,
{
    // Technically, the sender is accessed exclusively through hyper, but the
    // `call` method takes a shared ref, hence the ref cell.
    // TODO: move within the handshake to within the clal method.
    sender: std::cell::RefCell<SendRequest<Incoming>>,
    request_inspect_fn: FReq,
    response_inspect_fn: FRes,
}

impl<
        FReq: Fn(&Request<Incoming>),
        FRes: Fn(&Response<Incoming>) + Clone + Send + 'static,
    > ProxyService<FReq, FRes>
{
    async fn new(
        stream: Box<dyn Stream>,
        request_inspect_fn: FReq,
        response_inspect_fn: FRes,
    ) -> Result<Self, hyper::Error> {
        let io = TokioIo::new(stream);
        let (sender, connection) = hyper::client::conn::http1::handshake(io).await.unwrap();

        tokio::task::spawn(async move {
            if let Err(err) = connection.await {
                // TODO
                println!("Connection failed: {:?}", err);
            }
        });

        Ok(Self {
            sender: std::cell::RefCell::new(sender),
            request_inspect_fn,
            response_inspect_fn,
        })
    }
}

impl<FReq, FRes> hyper::service::Service<Request<Incoming>> for ProxyService<FReq, FRes>
where
    FReq: Fn(&Request<Incoming>),
    FRes: Fn(&Response<Incoming>) + Clone + Send + 'static,
{
    type Response = Response<Incoming>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, request: Request<Incoming>) -> Self::Future {
        (self.request_inspect_fn)(&request);
        let response = self.sender.borrow_mut().send_request(request);

        // Wrap the response in a future which inspects whatever is inside.
        let response_inspect_fn = self.response_inspect_fn.clone();
        Box::pin(async move {
            let response = response.await?;
            (response_inspect_fn)(&response);
            Ok(response)
        })
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

fn noop_request(_: &Request<Incoming>) {}
fn noop_response(_: &Response<Incoming>) {}

pub struct HTTPFilter<FReq, FRes> {
    uds_path: String,
    upstream_state: Arc<Mutex<UpstreamState>>,
    next_upstream_token: AtomicU32,
    server_handle: Option<tokio::task::JoinHandle<()>>,
    request_inspect_fn: FReq,
    response_inspect_fn: FRes,
}

impl<FReq, FRes> Drop for HTTPFilter<FReq, FRes> {
    fn drop(&mut self) {
        // Clean up the Unix domain socket file when the filter is dropped
        if Path::new(&self.uds_path).exists() {
            let _ = std::fs::remove_file(&self.uds_path);
        }

        // The server_handle will be automatically dropped here, which will
        // cancel the tokio task and stop the server
    }
}

impl Default for HTTPFilter<fn(&Request<Incoming>) -> (), fn(&Response<Incoming>) -> ()> {
    fn default() -> Self {
        Self::new()
    }
}

impl HTTPFilter<fn(&Request<Incoming>) -> (), fn(&Response<Incoming>) -> ()> {
    pub fn new() -> Self {
        HTTPFilter {
            uds_path: "htapod.sock".to_owned(),
            server_handle: None,
            upstream_state: Arc::new(Mutex::new(UpstreamState::new())),
            next_upstream_token: AtomicU32::new(0),
            request_inspect_fn: noop_request,
            response_inspect_fn: noop_response,
        }
    }
}

// Generic impl for custom inspect functions
impl<FReq, FRes> HTTPFilter<FReq, FRes>
where
    FReq: Fn(&Request<Incoming>) + Clone + Send + 'static,
    FRes: Fn(&Response<Incoming>) + Clone + Send + 'static,
{
    pub fn new_with_inspect(request_inspect_fn: FReq, response_inspect_fn: FRes) -> Self {
        HTTPFilter {
            uds_path: "htapod.sock".to_owned(),
            server_handle: None,
            upstream_state: Arc::new(Mutex::new(UpstreamState::new())),
            next_upstream_token: AtomicU32::new(0),
            request_inspect_fn,
            response_inspect_fn,
        }
    }
}

impl<FReq, FRes> TCPFilter for HTTPFilter<FReq, FRes>
where
    FReq: Fn(&Request<Incoming>) + Clone + Send + 'static,
    FRes: Fn(&Response<Incoming>) + Clone + Send + 'static,
{
    fn prepare(&mut self) -> std::io::Result<()> {
        if Path::new(&self.uds_path).exists() {
            std::fs::remove_file(&self.uds_path)?;
        }

        let uds_path = self.uds_path.clone();

        let upstream_state = self.upstream_state.clone();
        let request_inspect_fn = self.request_inspect_fn.clone();
        let response_inspect_fn = self.response_inspect_fn.clone();

        // Spawn a task to listen on the UDS and handle connections by forwarding them
        // through the ProxyService.
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
                        let proxy_service = ProxyService::new(
                            upstream,
                            request_inspect_fn.clone(),
                            response_inspect_fn.clone(),
                        )
                        .await
                        .unwrap();

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
