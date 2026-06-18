use crate::UDPFilter;
use std::net::SocketAddr;
use tokio::sync::mpsc::UnboundedSender;

use crate::netstack::netstack::UDPPacket;

/// A "noop" UDP stack that just forwards UDP packets without inspecting them.
///
/// Use this when you don't want special handling of UDP packets but still want
/// to allow UDP traffic to pass from the tunnel interface to the outside world and
/// vice versa.
///
/// DNS for processes inside the network namespace will work.
pub struct PassthroughUDP {}

impl PassthroughUDP {
    /// Create a new `PassthroughUDP` stack.
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for PassthroughUDP {
    fn default() -> Self {
        Self::new()
    }
}

impl UDPFilter for PassthroughUDP {
    /// Forwards all packets from the tunnel interface to the outside world.
    fn handle_tun_udp(
        &mut self,
        data: Vec<u8>,
        local_address: SocketAddr,
        remote_address: SocketAddr,
        remote_sender: UnboundedSender<UDPPacket>,
    ) -> std::io::Result<()> {
        remote_sender
            .send(UDPPacket {
                data,
                local_address,
                remote_address,
            })
            .map_err(|_send_error| std::io::Error::other("handle_tun_udp: Remote end is closed!"))
    }

    /// Forwards all packets from the outside world to the tunnel interface.
    fn handle_remote_udp(
        &mut self,
        data: Vec<u8>,
        local_address: SocketAddr,
        remote_address: SocketAddr,
        tun_sender: tokio::sync::mpsc::UnboundedSender<UDPPacket>,
    ) -> std::io::Result<()> {
        tun_sender
            .send(UDPPacket {
                data,
                local_address,
                remote_address,
            })
            .map_err(|_send_error| {
                std::io::Error::other("handle_remote_udp: Remote end is closed!")
            })
    }
}
