use async_send_fd::{AsyncRecvFd, AsyncSendFd};
use rcgen::CertifiedKey;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    netstack::netstack::{TCPStack, UDPStack},
    ByPortTCPRouter, PassthroughTCP, PassthroughUDP,
};

/// Start a process with the given binary and args.
///
/// The method returns an error if the process cannot be spawned or tracked
/// after creation.
async fn start_process<I, S>(bin: S, args: I) -> std::io::Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    tokio::process::Command::new(bin)
        .args(args)
        .spawn()?
        .wait()
        .await
        .map_err(|e| {
            log::error!("Failed to track child process exit status: {:?}", e);
            std::io::Error::other(e)
        })
        .map(|exit_status| {
            log::debug!("Child process exited with status: {}", exit_status);
        })
}

pub struct Builder<TCPFilter, TCPRouter, UDPFilter>
where
    TCPFilter: crate::TCPFilter + Send + 'static,
    TCPRouter: crate::TCPRouter + Send + 'static,
    UDPFilter: crate::UDPFilter + Send + 'static,
{
    namespace: Option<crate::Namespace>,
    tun_interface_config: Option<crate::os::TunInterfaceConfig>,
    tcp_stack: Option<TCPStack<TCPFilter, TCPRouter>>,
    udp_stack: Option<UDPStack<UDPFilter>>,
}

impl<TCPFilter, TCPRouter, UDPFilter> Builder<TCPFilter, TCPRouter, UDPFilter>
where
    TCPFilter: crate::TCPFilter + Send + 'static,
    TCPRouter: crate::TCPRouter + Send + 'static,
    UDPFilter: crate::UDPFilter + Send + 'static,
{
    pub fn new() -> Self {
        Self {
            namespace: None,
            tun_interface_config: None,
            tcp_stack: None,
            udp_stack: None,
        }
    }

    pub fn namespace(mut self, namespace: crate::Namespace) -> Self {
        self.namespace = Some(namespace);
        self
    }

    pub fn tun_interface_config(mut self, config: crate::os::TunInterfaceConfig) -> Self {
        self.tun_interface_config = Some(config);
        self
    }

    pub fn with_tcp_stack<H, R>(
        self,
        tcp_handler: H,
        tcp_router: R,
        verify_remote_tls_cert: bool,
    ) -> Builder<H, R, UDPFilter>
    where
        H: crate::TCPFilter + Send + 'static,
        R: crate::TCPRouter + Send + 'static,
    {
        Builder {
            tcp_stack: Some(TCPStack::new(
                tcp_handler,
                tcp_router,
                verify_remote_tls_cert,
            )),
            namespace: self.namespace,
            tun_interface_config: self.tun_interface_config,
            udp_stack: self.udp_stack,
        }
    }

    pub fn with_udp_stack<Handler>(
        self,
        udp_stack: Handler,
    ) -> Builder<TCPFilter, TCPRouter, Handler>
    where
        Handler: crate::UDPFilter + Send + 'static,
    {
        Builder {
            namespace: self.namespace,
            tun_interface_config: self.tun_interface_config,
            tcp_stack: self.tcp_stack,
            udp_stack: Some(UDPStack::new(udp_stack)),
        }
    }

    pub fn build(self) -> Runner<TCPFilter, TCPRouter, UDPFilter> {
        Runner {
            namespace: self.namespace.unwrap_or_default(),
            tun_interface_config: self.tun_interface_config.unwrap_or_default(),
            tcp_stack: self.tcp_stack,
            udp_stack: self.udp_stack,
            root_ca: crate::tls::generate_ca(),
        }
    }
}

pub fn builder() -> Builder<PassthroughTCP, ByPortTCPRouter, PassthroughUDP> {
    Builder::new()
}

pub struct Runner<
    TCPFilter: crate::TCPFilter + Send + 'static,
    TCPRouter: crate::TCPRouter + Send + 'static,
    UDPFilter: crate::UDPFilter + Send + 'static,
> {
    namespace: crate::Namespace,
    tun_interface_config: crate::os::TunInterfaceConfig,
    tcp_stack: Option<TCPStack<TCPFilter, TCPRouter>>,
    udp_stack: Option<UDPStack<UDPFilter>>,

    // A self-signed certificate that will be used as _the_ CA.
    // All TLS connections proxied through htapod will return a leaf
    // certificate from that CA, and the CA will be put in
    // "/etc/ssl/certs/ca-certificates.crt" and in various other CA-defining
    // environment variables.
    root_ca: CertifiedKey,
}

impl<TCPFilter, TCPRouter, UDPFilter> Runner<TCPFilter, TCPRouter, UDPFilter>
where
    TCPFilter: crate::TCPFilter + Send + 'static,
    TCPRouter: crate::TCPRouter + Send + 'static,
    UDPFilter: crate::UDPFilter + Send + 'static,
{
    fn child(
        self,
        child_socket: UnixStream,
        bin: std::ffi::OsString,
        args: Vec<std::ffi::OsString>,
    ) -> Result<(), ()> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            self.async_child(child_socket, bin, args).await?;
            Ok(())
        })
    }

    async fn do_overlay(
        _tun_device_gateway_address: &IpAddr,
        root_ca_certificate: &rcgen::Certificate,
    ) -> std::io::Result<crate::overlayfs::Scope> {
        let resolv_conf_content = [
            b"nameserver " as &[_],
            b"1.1.1.1", // TODO: use our address and resolve ourselves
            //tun_device_gateway_address.to_string().as_bytes(),
            b"\n",
        ]
        .concat();
        let ro = std::fs::Permissions::from_mode(0o444);

        let fs_scope = crate::OverlayFS::new("/etc")?
            .add(resolv_conf_content, "resolv.conf", ro.clone())?
            .add(
                root_ca_certificate.pem(),
                "ssl/certs/ca-certificates.crt",
                ro,
            )?
            .mount()?;

        Ok(fs_scope)
    }

    async fn async_child(
        self,
        child_socket: UnixStream,
        bin: std::ffi::OsString,
        args: Vec<std::ffi::OsString>,
    ) -> Result<(), ()> {
        self.namespace.spawn().await;
        let tun_device = self.tun_interface_config.create().await;
        let _overlayfs_scope =
            Self::do_overlay(&self.tun_interface_config.gateaway(), &self.root_ca.cert)
                .await
                .unwrap_or_else(|e| panic!("overlay failed {e}")); // TODO

        let rfd = tun_device.as_raw_fd();
        log::debug!("Sending TUN fd: {rfd:?}");

        let mut child_socket = tokio::net::UnixStream::from_std(child_socket).unwrap();
        match child_socket.send_fd(rfd).await {
            Ok(()) => {
                log::debug!("Successfully sent tun fd.")
            }
            Err(e) => {
                log::error!("Error sending TUN fd: {e:?}");
                return Err(());
            }
        };

        // 7. Wait until cSoc is closed from the other end.
        child_socket.read_u8().await.unwrap();

        let _ = start_process(bin, args).await; // We don't care about the result.

        child_socket.write_u8(7).await.unwrap();
        child_socket.shutdown().await.unwrap();

        Ok(())
    }

    fn parent(self, parent_socket: UnixStream) -> Result<(), ()> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            self.async_parent(parent_socket).await?;
            Ok(())
        })
    }

    async fn async_parent(self, parent_socket: UnixStream) -> Result<(), ()> {
        //child_socket.shutdown().await;
        let mut parent_socket = tokio::net::UnixStream::from_std(parent_socket).unwrap();

        log::debug!("Receiving TUN fd.");
        let tun_raw_fd = match parent_socket.recv_fd().await {
            Ok(tun_raw_fd) if tun_raw_fd > 0 => {
                log::debug!("Successfully received TUN fd: {tun_raw_fd:?}");
                tun_raw_fd
            }
            Ok(_) => {
                log::error!("Received TUN fd is negative.");
                return Err(());
            }
            Err(e) => {
                log::error!("Error receiving TUN fd: {e:?}");
                return Err(());
            }
        };

        // Create a stream from the TUN fd.
        let mut config = tun::Configuration::default();
        config.raw_fd(tun_raw_fd);
        let tun_device = tun::create_as_async(&config).unwrap();

        let stop_handle = crate::netstack::netstack::run(
            self.tcp_stack,
            self.udp_stack,
            tun_device,
            self.root_ca,
        ); // TODO: use a drop as scope

        // Notify the other end that the network stack is up and can route traffic.
        parent_socket.write_u8(0).await.unwrap();

        // Wait for the child signal that it exited.
        parent_socket.read_u8().await.unwrap();
        parent_socket.shutdown().await.unwrap();

        stop_handle.stop().await;

        Ok(())
    }

    pub unsafe fn run<I, S>(self, bin: &str, args: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        // Create a socket pair - one for the child and one for the parent.
        // NOTE: This needs to be a std socket - we still haven't set up the a
        // tokio runtime at this point to use the tokio equivalent.
        let (parent_socket, child_socket) = match std::os::unix::net::UnixStream::pair() {
            Ok((parent_socket, child_socket)) => (parent_socket, child_socket),
            Err(e) => {
                log::error!("Couldn't create a pair of sockets: {e:?}");
                return; //Err(());
            }
        };

        // Set the sockets as non-blocking, per tokio's requirements.
        match (
            parent_socket.set_nonblocking(true),
            child_socket.set_nonblocking(true),
        ) {
            (Ok(()), Ok(())) => {}
            _ => {
                log::error!("Failed setting sockets to non-blocking mode.");
                return; //Err(());
            }
        };

        // Fork the current process.
        let pid = unsafe { libc::fork() };

        let _ = match pid {
            _pid if pid == 0 => self.child(
                child_socket,
                std::ffi::OsString::from(bin),
                args.into_iter().map(|x| x.as_ref().to_owned()).collect(),
            ),
            _pid if pid > 0 => self.parent(parent_socket),
            _ => Ok(()), // return Err(()),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_start_process() {
        assert!(start_process("echo", vec!["1", "2", "3", "4"])
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_start_process_with_unknown_cmd() {
        assert!(start_process("not_htapod", vec![]).await.is_err());
    }
}
