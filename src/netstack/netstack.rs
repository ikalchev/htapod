use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use crate::router::TCPRouter;
use futures::{SinkExt, StreamExt};
use rcgen::SanType;
use rustls::pki_types::ServerName;
use rustls_platform_verifier::ConfigVerifierExt;
use tokio::{select, sync::mpsc::UnboundedSender};
use tun::AsyncDevice;

/// Helper function to set up bidirectional stream copying with inspection.
///
/// This function handles the common pattern of splitting streams, applying filters,
/// and copying data bidirectionally between two streams.
async fn setup_stream_copy<TH, S1, S2>(
    source_stream: S1,
    destination_stream: S2,
    tcp_filter: Arc<Mutex<TH>>,
) where
    TH: TCPFilter,
    S1: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    S2: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (source_reader, source_writer) = tokio::io::split(source_stream);
    let (destination_reader, destination_writer) = tokio::io::split(destination_stream);

    let tcp_filter_source = tcp_filter.clone();
    let source_reader = tokio_util::io::InspectReader::new(source_reader, move |data: &[u8]| {
        let mut filter = tcp_filter_source.lock().unwrap();
        filter.on_source_read(data);
    });

    let destination_reader =
        tokio_util::io::InspectReader::new(destination_reader, move |data: &[u8]| {
            let mut filter = tcp_filter.lock().unwrap();
            filter.on_destination_read(data);
        });

    let mut in_stream = tokio::io::join(source_reader, source_writer);
    let mut remote_stream = tokio::io::join(destination_reader, destination_writer);

    let result = tokio::io::copy_bidirectional(&mut in_stream, &mut remote_stream).await;
    match result {
        Ok((from, to)) => log::debug!("Copied {} bytes from, {} bytes to.", from, to),
        Err(error) => log::error!("Failed to copy between streams: {:?}", error),
    }
}

/// A TCP filter allows you to observe the TCP traffic going into and out of the
/// virtual tunnel interface.
///
/// Both `on_source_read` and `on_destination_read` are called before data is
/// sent between peers asynchronously. This means that these methods should
/// not take a lot of time to complete as they will block the event loop.
///
/// Here is a simple example that prints the amount of data going in and out
/// of the tunnel interface:
///
/// ```rust
/// use htapod::TCPFilter;
///
/// struct ByteCountTCPFilter {}
///
/// impl TCPFilter for ByteCountTCPFilter {
///
///     fn on_source_read(&mut self, data: &[u8]) {
///         log::info!("Read {} bytes from net namespace.", data.len());
///     }
///
///     fn on_destination_read(&mut self, _data: &[u8]) {
///         log::info!("Received {} bytes from the outside world.", data.len());
///     }
/// }
/// ```
pub trait TCPFilter: Send // TODO move the send bound in the netstack
{
    /// Called when data is sent into the tunnel interface from within the network namespace.
    ///
    /// This typically is data that the wrapped binary is sending to the outside world.
    fn on_source_read(&mut self, data: &[u8]);

    /// Called when data is sent to the tunnel interface from the outside world.
    ///
    /// This typically is data that the outside world is sending into the wrapped binary
    /// running inside the network namespace.
    fn on_destination_read(&mut self, data: &[u8]);
}

/// A representation of a UDP packet.
pub struct UDPPacket {
    /// The payload of the packet.
    pub data: Vec<u8>,

    /// The address from which the data is sent.
    pub local_address: SocketAddr,

    /// The address to which the data is sent.
    pub remote_address: SocketAddr,
}

/// A UDP filter allows you to act on the UDP traffic going into and out of the
/// virtual tunnel interface.
///
///
/// Both `handle_tun_udp` and `handle_remote_udp` are called before data is
/// sent to the peer asynchronously. This means that these methods should
/// not take a lot of time to complete as they will block the event loop.
pub trait UDPFilter: Send {
    fn handle_tun_udp(
        &mut self,
        data: Vec<u8>,
        local_address: SocketAddr,
        remote_address: SocketAddr,
        remote_sender: UnboundedSender<UDPPacket>,
    ) -> std::io::Result<()>;

    fn handle_remote_udp(
        &mut self,
        data: Vec<u8>,
        local_address: SocketAddr,
        remote_address: SocketAddr,
        tun_sender: UnboundedSender<UDPPacket>,
    ) -> std::io::Result<()>;
}

/// A handle on the userspace network stack that allows gracefully tearing it down.
#[doc(hidden)]
pub(crate) struct StopNetstack {
    token: tokio_util::sync::CancellationToken,
    joined_futures: futures_util::future::JoinAll<tokio::task::JoinHandle<()>>,
}

impl StopNetstack {
    pub async fn stop(self) {
        self.token.cancel();
        self.joined_futures.await.iter().for_each(|res| {
            if let Err(e) = res {
                log::error!("error: {:?}", e);
            }
        });
    }
}

/// A `TCPStack` defines how TCP traffic is handled through the userspace network
/// stack.
#[doc(hidden)]
pub(crate) struct TCPStack<TH: TCPFilter + 'static, TR: TCPRouter + 'static> {
    handler: Arc<Mutex<TH>>,
    router: TR,
    /// Whether to verify the TLS certificates of remote peers.
    verify_remote_tls_cert: bool,
}

impl<TH: TCPFilter, TR: TCPRouter> TCPStack<TH, TR> {
    /// Create a new TCP network stack.
    #[doc(hidden)]
    pub fn new(handler: TH, router: TR, verify_remote_tls_cert: bool) -> TCPStack<TH, TR> {
        TCPStack {
            handler: Arc::new(Mutex::new(handler)),
            router,
            verify_remote_tls_cert,
        }
    }

    /// Creates a new plain (unsecured) TCP connection.
    ///
    /// This method connects to the given remote address and then forwards data
    /// between the userspace TCP stream and the remote peer. This essentially provides
    /// the bridge between the outside world and the virtual tunnel interface inside
    /// the network namespace.
    ///
    /// - `tcp_stream` - A TCP stream between a peer on the tunnel interface and htapod.
    /// - `local_address` - The TCP address _inside the network namespace_ that initiated
    ///     the connection to the tunnel interface.
    /// - `remote_address` - The TCP address of the peer in the outside world to which a
    ///     connection needs to be established.
    /// - `tcp_filter` - The TCP filter that should be applied when proxying data between
    ///     the `tcp_stream` and the remote peer.
    #[doc(hidden)]
    async fn new_unsecured_tcp_connection(
        tcp_stream: netstack_smoltcp::TcpStream,
        local_address: SocketAddr,
        remote_address: SocketAddr,
        tcp_filter: std::sync::Arc<std::sync::Mutex<TH>>,
    ) {
        match tokio::net::TcpStream::connect(remote_address).await {
            Ok(remote_stream) => {
                setup_stream_copy(tcp_stream, remote_stream, tcp_filter).await;
            }
            Err(e) => {
                log::error!(
                    "Failed to connect {:?}=>{:?}, err: {:?}",
                    local_address,
                    remote_address,
                    e
                );
            }
        };
    }

    /// Creates a new TLS connection.
    ///
    /// This method connects to the given remote address and then forwards data
    /// between the userspace TCP stream and the remote peer. This essentially provides
    /// the bridge between the outside world and the virtual tunnel interface inside
    /// the network namespace.
    ///
    /// - `tcp_stream` - A TCP stream between a peer on the tunnel interface and htapod.
    /// - `local_address` - The TCP address _inside the network namespace_ that initiated
    ///     the connection to the tunnel interface.
    /// - `remote_address` - The TCP address of the peer in the outside world to which a
    ///     connection needs to be established.
    /// - `tcp_filter` - The TCP filter that should be applied when proxying data between
    ///     the `tcp_stream` and the remote peer.
    /// - `root_ca` - The root certificate with which to create and sign an on-demand
    ///     certificate for the remote peer. The `root_ca` should be the certificate
    ///     installed by htapod in the binary environment as part of the trusted
    ///     CAs.
    /// - `verify_remote_tls_cert` - Whether to verify the certificate of the remote
    ///   peer.
    #[doc(hidden)]
    async fn new_tls_connection(
        tcp_stream: netstack_smoltcp::TcpStream,
        _local_address: SocketAddr,
        remote_address: SocketAddr,
        tcp_filter: std::sync::Arc<std::sync::Mutex<TH>>,
        root_ca: Arc<rcgen::CertifiedKey>,
        verify_remote_tls_cert: bool,
    ) {
        // In case the TUN connection is to an IP address, we need the original address when
        // creating a TLS certificate on the fly, not the "resolved" address that the
        // library user might have given us (i.e. `remote_address`).
        let unmapped_remote_address = tcp_stream.remote_addr().ip();
        let acceptor =
            tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), tcp_stream);
        tokio::pin!(acceptor);
        match acceptor.as_mut().await {
            Ok(start) => {
                let client_hello = start.client_hello();
                let server_name = client_hello.server_name().map_or_else(
                    || rcgen::SanType::IpAddress(unmapped_remote_address),
                    |server_name| rcgen::SanType::DnsName(server_name.try_into().unwrap()),
                );
                let rcgen::CertifiedKey { cert, key_pair } =
                    crate::tls::generate_mock_leaf(&root_ca, server_name.clone());
                let config = std::sync::Arc::new(
                    rustls::ServerConfig::builder()
                        .with_no_client_auth()
                        .with_single_cert(
                            vec![cert.der().clone().into_owned()],
                            key_pair.serialize_der().try_into().unwrap(), //TODO:
                        )
                        .unwrap(),
                );
                // Accept the connection from the tunnel end.
                let tls_stream = start.into_stream(config).await.unwrap(); // TODO

                // Now, initiate a connection to the target address.
                // TODO: need to support certificate validation options here.
                let config = {
                    if verify_remote_tls_cert {
                        rustls::ClientConfig::with_platform_verifier()
                    } else {
                        rustls::ClientConfig::builder()
                            .dangerous()
                            .with_custom_certificate_verifier(Arc::new(
                                crate::tls::NoCertificateVerification,
                            ))
                            .with_no_client_auth()
                    }
                };
                let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));

                let stream = tokio::net::TcpStream::connect(&remote_address)
                    .await
                    .unwrap(); //TODO

                let remote_address = match server_name {
                    SanType::DnsName(name) => name.as_str().to_owned(),
                    SanType::IpAddress(address) => address.to_string(),
                    _ => panic!("Unsupported TLS peer SAN type."), // TODO
                };
                let remote_address = ServerName::try_from(remote_address).unwrap();
                let remote_stream = connector.connect(remote_address, stream).await.unwrap(); // TODO

                setup_stream_copy(tls_stream, remote_stream, tcp_filter).await;
            }
            Err(_) => {
                todo!("handle");
            }
        }
    }

    /// Listens and accepts for new TCP connections.
    ///
    /// This method continuously waits for incoming TCP connections from the virtual
    /// tunnel interface. When a new connection arrives and is accepted, the remote
    /// address, i.e. the address of the peer in the outside world, is resolved using
    /// the `self.router`. Based on that result, the connection is forwarded to the
    /// outside world either as a plain TCP connection or as a TLS connection.
    ///
    /// This method stops listening for incoming connections when the `cancel_token` is
    /// set.
    ///
    /// - `tcp_listener` - A TCP listener which accepts connections from the virtual
    ///     tunnel interface.
    /// - `cancel_token` - A token which when set will cause this method to stop
    ///     listening for new connections and exit.
    /// - `root_ca` - The root TLS certificate used to generate on-demand certificates
    ///     for TLS connections.
    #[doc(hidden)]
    async fn handle_tcp_connections(
        self,
        mut tcp_listener: netstack_smoltcp::TcpListener,
        cancel_token: tokio_util::sync::CancellationToken,
        root_ca: rcgen::CertifiedKey,
    ) {
        let root_ca = Arc::new(root_ca);
        loop {
            select! {
                // TODO: Should spawn a task for every new connection.
                Some((tcp_stream, local_address, remote_address)) = tcp_listener.next() => {
                    log::debug!("Got new TCP connection to {:?}", remote_address);
                    match self.router.resolve(&remote_address) {
                        Some(crate::router::TCPTargetAddress::Plain(address)) => {
                            let handler = self.handler.clone();
                            tokio::spawn(async move {
                                Self::new_unsecured_tcp_connection(
                                    tcp_stream, local_address, address, handler
                                ).await;
                            });
                        },
                        Some(crate::router::TCPTargetAddress::TLS(address)) => {
                            let handler = self.handler.clone();
                            let root_ca = root_ca.clone();
                            tokio::spawn(async move {
                            Self::new_tls_connection(
                                tcp_stream, local_address, address, handler, root_ca, self.verify_remote_tls_cert
                            ).await;
                            });
                        },
                        None => {
                            log::info!("No resolve rule for {:?}.", remote_address)
                        }
                    };
                },
                _ = cancel_token.cancelled() => {
                    log::debug!("Shutting down TCP handler.");
                    break;
                },
                else => break,
            }
        }
    }
}

/// A `UDPStack` defines how UDP packets is handled through the userspace network
/// stack.
pub(crate) struct UDPStack<UH: UDPFilter> {
    handler: UH,
}

impl<UH: UDPFilter> UDPStack<UH> {
    pub fn new(handler: UH) -> UDPStack<UH> {
        UDPStack { handler }
    }

    /// Start handling UDP packets between the outside world and the tunnel interface.
    ///
    /// This method spawns two tasks - one that listens for packets from the virtual
    /// tunnel interface and one from the outside world. We have the following flow of packets:
    /// - From the tunnel interface to the world: `world <-- userspace netstack <-- tun`
    /// - From the outside world to (an address behind) the tunnel interface: `world --> userspace netstack --> tun`
    ///
    /// Specifically, let's take a DNS packet going from the tunnel interface to the outside
    /// world (forget DNS uses port 53 for the moment):
    /// 1. The packet is initially sent by the process having a source address of
    ///     `<privIP:privPort>` and a destination address of `<pubIP:pubPort>`.
    /// 2. The packet goes into the tunnel interface and is delivered to `htapod` through
    ///     the userspace network stack. Now `htapod` needs to forward the packet to the
    ///     destination. However, it will now use an IP address and port from the root
    ///     network namespace, so the source address is going to change to `<htapodIP:htapodPort>`.
    /// 3. The remote peer receives the DNS query and must now respond. It uses the original source
    ///     address and sends a UDP packet with a destination address `<htapodIP:htapodPort>` and
    ///     a source address `<pubIP:other_pubPort>`.
    /// 4. `htapod` receives this UDP packet and now needs to forward it inside the tunnel
    ///     interface to the process running inside the network namespace. To do this correctly,
    ///     `htapod` must have remembered that it mapped the source address from step 1 to its
    ///     source address in step 2 above, i.e. it must implement an SNAT and know that a
    ///     packet destined to `<htapodIP:htapodPort>` must be forwarded to `<privIP:privPort>`.
    /// 5. After doing the SNAT, the packet is sent to the process over the networkstack
    ///     through the virtual tunnel interface.
    #[doc(hidden)]
    async fn handle_udp(
        mut self,
        udp_socket: netstack_smoltcp::UdpSocket,
        cancel_token: tokio_util::sync::CancellationToken,
    ) {
        // TODO: SNAT must be improved as it currently handles one udp request.
        let snat = std::sync::Arc::new(std::sync::Mutex::new(
            HashMap::<SocketAddr, SocketAddr>::new(),
        ));
        // Spawn a task that reads from the channel and sends into the TUN UDP socket.
        let (tun_udp_handler_sender, mut tun_udp_handler_receiver) =
            tokio::sync::mpsc::unbounded_channel::<UDPPacket>();
        let (mut read_half, mut write_half) = udp_socket.split();
        let remote_to_tun_snat = snat.clone();
        tokio::spawn(async move {
            while let Some(udp_packet) = tun_udp_handler_receiver.recv().await {
                let snat_result = {
                    let remote_to_tun_snat = remote_to_tun_snat.lock().unwrap(); //  TODO
                    remote_to_tun_snat.get(&udp_packet.local_address).cloned()
                };
                match snat_result {
                    Some(within_tun_address) => {
                        log::debug!(
                            "Incoming UDP from {:?} to {:?} via {:?}",
                            udp_packet.remote_address,
                            within_tun_address,
                            udp_packet.local_address
                        );
                        let _ = write_half
                            .send((
                                udp_packet.data,
                                udp_packet.remote_address,
                                within_tun_address,
                            ))
                            .await;
                    }
                    None => {
                        log::info!("No SNAT for {:?}", udp_packet.local_address);
                    }
                };
            }
        });

        // Spawn a task that reads from channel and sends into the remote UDP socket.
        let (remote_udp_handler_sender, mut remote_udp_handler_receiver) =
            tokio::sync::mpsc::unbounded_channel::<UDPPacket>();
        let socket = std::sync::Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap()); // TODO:
        let writer = socket.clone();
        let socket_local_addr = socket.local_addr().unwrap(); // TODO
        let tun_to_remote_snat = snat.clone();
        tokio::spawn(async move {
            while let Some(udp_packet) = remote_udp_handler_receiver.recv().await {
                {
                    let mut tun_to_remote_snat = tun_to_remote_snat.lock().unwrap(); // TODO
                    tun_to_remote_snat.insert(socket_local_addr, udp_packet.local_address);
                }
                log::debug!(
                    "Outgoing UDP from {:?} to {:?} via {:?}",
                    udp_packet.local_address,
                    udp_packet.remote_address,
                    socket_local_addr
                );
                let _ = writer
                    .send_to(udp_packet.data.as_slice(), udp_packet.remote_address)
                    .await;
            }
        });

        let local_address = socket.local_addr().unwrap(); // TODO:
        loop {
            let mut remote_recv_buf = vec![0; 1024];
            select! {
                Some((data, local_address, remote_address)) = read_half.next() => {
                    match self.handler.handle_tun_udp(
                        data, local_address, remote_address, remote_udp_handler_sender.clone()
                    ) {
                        Ok(_) => (),
                        Err(error) => log::error!("Failed to handle UDP from tunnel: {:?}", error),
                    }
                },
                recv_result = socket.recv_from(&mut remote_recv_buf) => {
                    match recv_result {
                        Ok((_total_bytes, remote_address)) => {
                            match self.handler.handle_remote_udp(
                                remote_recv_buf,
                                local_address,
                                remote_address,
                                tun_udp_handler_sender.clone()
                            ) {
                                Ok(_) => (),
                                Err(error) => log::error!("Faled to handle UDP from remote: {:?}", error)
                            }
                        },
                        Err(_) => log::error!("recv_from failed") // TODO
                    }
                },
                _ = cancel_token.cancelled() => {
                    log::debug!("Shutting down UDP handler.");
                    break;
                },
                else => {
                    log::error!("Unknown exit condition.");
                    break;
                },
            }
        }
    }
}

/// Runs a userspace network stack with the given configuration.
///
/// Returns a handle for gracefully shutting down the network stack and stopping all
/// packet listeners.
///
/// - `tcp_stack` - An optional TCP stack. If `None`, the userspace network stack will not
///     handle TCP packets.
/// - `udp_stack` - An optional UDP stack. If `None`, the userspace network stack will not
///     handle UDP packets.
/// - `tun_device` - The tunnel interface from which the userspace network will read
///     packets.
/// - `root_ca` - The root TLS certificate to use when generating TLS certificates on the
///     fly.
#[doc(hidden)]
pub(crate) fn run<TH, TR, UH>(
    tcp_stack: Option<TCPStack<TH, TR>>,
    udp_stack: Option<UDPStack<UH>>,
    tun_device: AsyncDevice,
    root_ca: rcgen::CertifiedKey, // TODO: this is needed only in case of TCP.
) -> StopNetstack
where
    TH: TCPFilter + Send + 'static,
    TR: TCPRouter + Send + 'static,
    UH: UDPFilter + Send + 'static,
{
    log::debug!("Building network stack.");
    let (stack, runner, udp_socket, tcp_listener) = netstack_smoltcp::StackBuilder::default()
        .enable_tcp(tcp_stack.is_some())
        .enable_udp(udp_stack.is_some())
        .build()
        .unwrap();

    if let Some(runner) = runner {
        tokio::spawn(runner);
    }

    // Create a stream from the TUN fd.
    let tun_framed = tun_device.into_framed();

    // Now split the netstack and the TUN stream into readers and writers so we
    // can spawn tasks for each direction.
    let (mut tun_sink, mut tun_stream) = tun_framed.split();
    let (mut stack_sink, mut stack_stream) = stack.split();

    // Holds all Futures we will select on.
    let mut futs = vec![];

    // Start routing traffic back and forth.
    log::debug!("Start routing.");
    let token = tokio_util::sync::CancellationToken::new();

    // Reads packet from stack and sends to TUN.
    let stack_to_tun_token = token.child_token();
    futs.push(tokio::spawn(async move {
            loop {
                select! {
                    Some(pkt) = stack_stream.next() => {
                        if let Ok(pkt) = pkt {
                            match tun_sink.send(pkt).await {
                                Ok(_) => {}
                                Err(e) => log::info!("Failed to send packet to TUN, err: {e:?}"),
                            }
                        }
                    },
                    _ = stack_to_tun_token.cancelled() => {
                        log::debug!("Shutting down userspace packet forwarding (userspace stack -> TUN).");
                        break;
                    },
                    else => {
                        log::error!("Unknown exit in userspace -> TUN processing.");
                        break;
                    }
                }
            }
        }));

    // Reads packet from TUN and sends to stack.
    let tun_to_stack_token = token.child_token();
    futs.push(tokio::spawn(async move {
            loop {
                select! {
                    Some(pkt) = tun_stream.next() => {
                        match pkt {
                            Ok(pkt) => {
                                match stack_sink.send(pkt).await {
                                    Ok(_) => {}
                                    Err(e) => log::info!("Failed to send packet to stack, err: {e:?}"),
                                };
                            }
                            Err(err) => {
                                log::error!("Unknown error while processing packets from TUN: {err:?}");
                            }
                        }
                    },
                    _ = tun_to_stack_token.cancelled() => {
                        log::debug!("Shutting down userspace packet forwarding (TUN -> userspace stack).");
                        break;
                    },
                    else => {
                        log::error!("Unknown exit in TUN -> userspace processing.");
                        break;
                    }
                }
            }
        }));

    // Extracts TCP connections from stack and sends them to the dispatcher.
    if let Some(tcp_stack) = tcp_stack {
        let tcp_listener = tcp_listener.unwrap();
        let handle_tun_tcp_connections_token = token.child_token();
        futs.push(tokio::spawn({
            async move {
                tcp_stack
                    .handle_tcp_connections(tcp_listener, handle_tun_tcp_connections_token, root_ca)
                    .await
            }
        }));
    }

    // Extracts UDP packets.
    if let Some(udp_stack) = udp_stack {
        let udp_socket = udp_socket.unwrap();
        let handle_tun_udp_token = token.child_token();
        futs.push(tokio::spawn(async move {
            udp_stack.handle_udp(udp_socket, handle_tun_udp_token).await
        }))
    }

    StopNetstack {
        token,
        joined_futures: futures::future::join_all(futs),
    }
}
