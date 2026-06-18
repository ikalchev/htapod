use crate::netstack::netstack::Stream;
use crate::TCPFilter;

/// A "noop" TCP stack that does nothing.
///
/// Use this when you don't want special handling of TCP packets but still want
/// to allow TCP traffic to pass from the tunnel interface to the outside world and
/// vice versa.
pub struct PassthroughTCP {}

impl PassthroughTCP {
    /// Creates a new `PassthroughTCP` filter.
    pub fn new() -> Self {
        Self {}
    }

    async fn handle(
        userspace_address: std::net::SocketAddr,
        mut userspace_stream: Box<dyn Stream>,
        www_address: std::net::SocketAddr,
        mut www_stream: Box<dyn Stream>,
    ) {
        let result = tokio::io::copy_bidirectional(&mut userspace_stream, &mut www_stream).await;

        match result {
            Ok((from, to)) => log::debug!("Copied {} bytes from, {} bytes to.", from, to),
            Err(error) => log::error!("Failed to copy between streams: {:?}", error),
        }
    }
}

impl Default for PassthroughTCP {
    fn default() -> Self {
        Self::new()
    }
}

impl TCPFilter for PassthroughTCP {
    fn handle_new_connection(
        &mut self,
        userspace_address: std::net::SocketAddr,
        userspace_stream: Box<dyn Stream>,
        www_address: std::net::SocketAddr,
        www_stream: Box<dyn Stream>,
    ) {
        tokio::spawn(PassthroughTCP::handle(
            userspace_address,
            userspace_stream,
            www_address,
            www_stream,
        ));
    }
}
