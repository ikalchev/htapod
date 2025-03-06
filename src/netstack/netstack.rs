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

pub trait TCPFilter: Send // TODO move the send bound in the netstack
{
    fn on_source_read(&mut self, data: &[u8]);
    fn on_destination_read(&mut self, data: &[u8]);
}

pub struct UDPPacket {
    pub data: Vec<u8>,
    pub local_address: SocketAddr,
    pub remote_address: SocketAddr,
}

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

pub struct StopNetstack {
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

pub(crate) struct TCPStack<TH: TCPFilter + 'static, TR: TCPRouter + 'static> {
    handler: Arc<Mutex<TH>>,
    router: TR,
    verify_remote_tls_cert: bool,
}

impl<TH: TCPFilter, TR: TCPRouter> TCPStack<TH, TR> {
    pub fn new(handler: TH, router: TR, verify_remote_tls_cert: bool) -> TCPStack<TH, TR> {
        TCPStack {
            handler: Arc::new(Mutex::new(handler)),
            router,
            verify_remote_tls_cert,
        }
    }

    async fn new_unsecured_tcp_connection(
        tcp_stream: netstack_smoltcp::TcpStream,
        local_address: SocketAddr,
        remote_address: SocketAddr,
        tcp_filter: std::sync::Arc<std::sync::Mutex<TH>>,
    ) {
        match tokio::net::TcpStream::connect(remote_address).await {
            Ok(remote_stream) => {
                let (source_reader, source_writer) = tokio::io::split(tcp_stream);
                let (destination_reader, destination_writer) = tokio::io::split(remote_stream);

                let inspect_source = tcp_filter.clone();
                let source_reader =
                    tokio_util::io::InspectReader::new(source_reader, move |data| {
                        let mut inspect_source = inspect_source.lock().unwrap();
                        inspect_source.on_source_read(data);
                    });

                let inspect_destination = tcp_filter;
                let destination_reader =
                    tokio_util::io::InspectReader::new(destination_reader, move |data| {
                        let mut inspect_destination = inspect_destination.lock().unwrap();
                        inspect_destination.on_destination_read(data)
                    });

                let mut in_stream = tokio::io::join(source_reader, source_writer);
                let mut remote_stream = tokio::io::join(destination_reader, destination_writer);
                let result =
                    tokio::io::copy_bidirectional(&mut in_stream, &mut remote_stream).await;
                match result {
                    Ok((from, to)) => log::debug!("Copied {} bytes from, {} bytes to.", from, to),
                    Err(error) => log::error!("Failed to copy between streams: {:?}", error),
                }
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

                // Now, initiate a connection to the targer address.
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
                    _ => panic!("fira"), // TODO
                };
                let remote_address = ServerName::try_from(remote_address).unwrap();
                let remote_stream = connector.connect(remote_address, stream).await.unwrap(); // TODO

                let (source_reader, source_writer) = tokio::io::split(tls_stream);
                let (destination_reader, destination_writer) = tokio::io::split(remote_stream);

                let inspect_source = tcp_filter.clone();
                let source_reader =
                    tokio_util::io::InspectReader::new(source_reader, move |data| {
                        let mut inspect_source = inspect_source.lock().unwrap();
                        inspect_source.on_source_read(data);
                    });

                let inspect_destination = tcp_filter;
                let destination_reader =
                    tokio_util::io::InspectReader::new(destination_reader, move |data| {
                        let mut inspect_destination = inspect_destination.lock().unwrap();
                        inspect_destination.on_destination_read(data)
                    });

                let mut in_stream = tokio::io::join(source_reader, source_writer);
                let mut remote_stream = tokio::io::join(destination_reader, destination_writer);
                let result =
                    tokio::io::copy_bidirectional(&mut in_stream, &mut remote_stream).await;
                match result {
                    Ok((from, to)) => log::debug!("Copied {} bytes from, {} bytes to.", from, to),
                    Err(error) => log::error!("Failed to copy between streams: {:?}", error),
                }
            }
            Err(_) => {
                todo!("handle");
            }
        }
    }

    async fn handle_tcp_connections(
        self,
        mut tcp_listener: netstack_smoltcp::TcpListener,
        cancel_token: tokio_util::sync::CancellationToken,
        root_ca: rcgen::CertifiedKey,
    ) {
        let root_ca = Arc::new(root_ca);
        loop {
            select! {
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

pub(crate) struct UDPStack<UH: UDPFilter> {
    handler: UH,
}

impl<UH: UDPFilter> UDPStack<UH> {
    pub fn new(handler: UH) -> UDPStack<UH> {
        UDPStack { handler }
    }

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

pub(crate) fn run<TH, TR, UH>(
    tcp_stack: Option<TCPStack<TH, TR>>,
    udp_stack: Option<UDPStack<UH>>,
    tun_device: AsyncDevice,
    root_ca: rcgen::CertifiedKey,
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
    match tcp_stack {
        Some(tcp_stack) => {
            let tcp_listener = tcp_listener.unwrap();
            let handle_tun_tcp_connections_token = token.child_token();
            futs.push(tokio::spawn({
                async move {
                    tcp_stack
                        .handle_tcp_connections(
                            tcp_listener,
                            handle_tun_tcp_connections_token,
                            root_ca,
                        )
                        .await
                }
            }));
        }
        None => (),
    }

    // Extracts UDP packets.
    match udp_stack {
        Some(udp_stack) => {
            let udp_socket = udp_socket.unwrap();
            let handle_tun_udp_token = token.child_token();
            futs.push(tokio::spawn(async move {
                udp_stack.handle_udp(udp_socket, handle_tun_udp_token).await
            }))
        }
        None => (),
    }

    StopNetstack {
        token,
        joined_futures: futures::future::join_all(futs),
    }
}
