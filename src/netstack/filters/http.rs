use crate::{netstack::netstack::Stream, TCPFilter};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
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
    FReq: Fn(&http::request::Parts, &Bytes),
    FRes: Fn(&http::response::Parts, &Bytes) + Clone + Send + 'static,
{
    sender: Arc<Mutex<SendRequest<Full<Bytes>>>>,
    request_inspect_fn: FReq,
    response_inspect_fn: FRes,
}

impl<
        FReq: Fn(&http::request::Parts, &Bytes),
        FRes: Fn(&http::response::Parts, &Bytes) + Clone + Send + 'static,
    > ProxyService<FReq, FRes>
{
    async fn new(
        stream: Box<dyn Stream>,
        request_inspect_fn: FReq,
        response_inspect_fn: FRes,
    ) -> Result<Self, hyper::Error> {
        let io = TokioIo::new(stream);
        let (sender, connection) = hyper::client::conn::http1::Builder::new()
            .handshake(io)
            .await?;

        tokio::task::spawn(async move {
            if let Err(err) = connection.await {
                // TODO
                println!("Connection failed: {:?}", err);
            }
        });

        Ok(Self {
            sender: Arc::new(Mutex::new(sender)),
            request_inspect_fn,
            response_inspect_fn,
        })
    }
}

impl<FReq, FRes> hyper::service::Service<Request<Incoming>> for ProxyService<FReq, FRes>
where
    FReq: Fn(&http::request::Parts, &Bytes) + Clone + Send + 'static,
    FRes: Fn(&http::response::Parts, &Bytes) + Clone + Send + 'static,
{
    type Response = Response<Full<Bytes>>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, request: Request<Incoming>) -> Self::Future {
        let sender = self.sender.clone();
        let req_fn = self.request_inspect_fn.clone();
        let res_fn = self.response_inspect_fn.clone();

        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let bytes = body.collect().await?.to_bytes();
            (req_fn)(&parts, &bytes);

            let req = Request::from_parts(parts, Full::from(bytes));
            let response_fut = {
                let mut sender_guard = sender.lock().unwrap();
                sender_guard.send_request(req)
            };

            let response = response_fut.await?;
            let (parts, body) = response.into_parts();
            let bytes = body.collect().await?.to_bytes();
            (res_fn)(&parts, &bytes);

            let res = Response::from_parts(parts, Full::from(bytes));
            Ok(res)
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

// Generic impl for custom inspect functions
impl<FReq, FRes> HTTPFilter<FReq, FRes>
where
    FReq: Fn(&http::request::Parts, &Bytes) + Clone + Send + 'static,
    FRes: Fn(&http::response::Parts, &Bytes) + Clone + Send + 'static,
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

// TODO: handle the traffic not being http.
/// A TCPFilter that allows the inspection of HTTP request and responses.
///
/// For every connection that arrives from the network namespace, there is a
/// corresponding connection from the root network namespace to the peer. To
/// leverage hyper HTTP handling, the traffic between these connections is
/// proxied through a hyper Service.
///
/// This proxying happens over a UDS, i.e. all traffic coming from the userspace
/// is sent over the UDS, handled by the hyper Service and then forwarded to the
/// peer (and vice versa). However, we need to forward the stream from
/// the connection handling in the TCPFilter to the proxy task so we can setup
/// the `Service` to the right peer.
///
/// The above is done as follows:
/// - We maintain a mapping from a u32 token to a `Stream`.
/// - Whenever a new connection is established, we put the corresponding
///     upstream in the map and key it with a new u32 token. We then establish a
///     connection to the UDS and send the token. Finally, we set up traffic forwarding
///     between the userspace connection and the UDS connection.
/// - On the other end, whenever we get a new connection on the UDS, we read a u32
///     token from it, get the userspace `Stream` from the map and then spawn
///     a task to handle the hyper Service.
///
/// Conceptually, the flow looks like this:
///
/// ```
/// userspace --> UDS --> hyper::Service --> inspect request --> upstream --┐
///                                                                    Some Server
/// userspace <-- UDS <-- inspect response <-- hyper::Service <-- upstream -┘
/// ```
impl<FReq, FRes> TCPFilter for HTTPFilter<FReq, FRes>
where
    FReq: Fn(&http::request::Parts, &Bytes) + Clone + Send + 'static,
    FRes: Fn(&http::response::Parts, &Bytes) + Clone + Send + 'static,
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

// Tests

#[cfg(test)]
mod tests {
    use super::ProxyService;
    use crate::netstack::netstack::Stream;
    use futures::task::{Context, Poll};
    use hyper::service::Service;
    use std::pin::Pin;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::test;

    // A mock upstream stream that can fail on demand
    struct FailingStream;

    impl AsyncRead for FailingStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "Connection reset by peer",
            )))
        }
    }

    impl AsyncWrite for FailingStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "Connection reset by peer",
            )))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Stream for FailingStream {}

    // A mock stream that immediately closes
    struct ClosedStream;

    impl AsyncRead for ClosedStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(())) // EOF
        }
    }

    impl AsyncWrite for ClosedStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Stream for ClosedStream {}
}
