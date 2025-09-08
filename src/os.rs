use futures::stream::TryStreamExt;
use ipnetwork::IpNetwork;
use rtnetlink::{new_connection, Error, Handle};
use std::{io::Write, net::IpAddr, str::FromStr};

/// Defines the confiration of the tunnel interface.
pub struct TUNInterfaceConfig {
    /// The interface name.
    tun_name: String,
    /// The interface address.
    address: IpAddr,
    /// The interface address network mask.
    netmask: IpAddr,
    /// The gateway address that the interface provides.
    gateway: IpAddr,
}

impl Default for TUNInterfaceConfig {
    /// Creats a default `TUNInterfaceConfig` with a name `htapod` and some address.
    fn default() -> Self {
        let address = ipnet::IpNet::from_str("10.1.11.4/24").unwrap();
        TUNInterfaceConfig {
            tun_name: "htapod".to_owned(),
            address: address.addr(),
            netmask: address.netmask(),
            gateway: IpAddr::from_str("10.1.1.1").unwrap(),
        }
    }
}

impl TUNInterfaceConfig {
    /// Creats a tunnel interface from the config.
    pub async fn create(&self) -> tun::AsyncDevice {
        configure_tun_sinkhole(&self.tun_name, self.address, self.netmask, self.gateway).await
    }

    /// Returns the gateway of the tunnel interface.
    pub fn gateaway(&self) -> IpAddr {
        self.gateway
    }
}

/// Defines the linux namespace environment.
///
/// This allows configuration of which namespaces are unshared before the user process
/// is started.
///
/// By default `htapod` unshares the following namespaces:
/// - user namespace - This allows unprivileged processes to create network interfaces,
///     modify the routing table and mount filesystems.
/// - network namespace - This allows the network interfaces that are present on the host
///     to be invisible to processes running in the new namespace. It also creates a new
///     routing table in the namespace.
/// - mount namespace - Allows the process to isolate the overlay FS mounts from others.
///     `htapod` will mount a new TLS certificate so it can control the trust and
///     "masquarade" as domains which the process connects to.
///
/// Unless you have control over the network and the trusted certificates, you usually
/// want `Namespace::unshare_all()`, which will unshare the above namespaces.
pub struct Namespace {
    unshare_user_namespace: bool,
    unshare_net_namespace: bool,
    unshare_mount_namespace: bool,
}

impl Namespace {
    /// Creates a new namespace environment that will unshare the user, network and mount
    /// namespaces.
    pub fn unshare_all() -> Self {
        Self {
            unshare_user_namespace: true,
            unshare_net_namespace: true,
            unshare_mount_namespace: true,
        }
    }

    /// Sets whether to unshare the user namespace.
    pub fn unshare_user_namespace(mut self, unshare_user_namespace: bool) -> Self {
        self.unshare_user_namespace = unshare_user_namespace;
        self
    }

    /// Sets whether to unshare the network namespace.
    pub fn unshare_net_namespace(mut self, unshare_net_namespace: bool) -> Self {
        self.unshare_net_namespace = unshare_net_namespace;
        self
    }

    /// Sets whether to unshare the mount namespace.
    pub fn unshare_mount_namespace(mut self, unshare_mount_namespace: bool) -> Self {
        self.unshare_mount_namespace = unshare_mount_namespace;
        self
    }

    /// Spawns the namespace environment, unsharing the configured namespaces.
    pub async fn spawn(self) {
        if self.unshare_user_namespace {
            unshare_user_namespace();
        }

        if self.unshare_net_namespace {
            unshare_net_namespace();
        }

        if self.unshare_mount_namespace {
            unshare_mount_namespace();
        }

        match link_up("lo").await {
            Ok(_) => log::debug!("Successfully set local loopback interface up."),
            Err(_) => {
                log::error!("Error bringing local loopback interface up.");
                //return Err(()); TODO
            }
        };
    }
}

impl Default for Namespace {
    /// Returns a namespace environment that will unshare all needed namespaces
    /// (same as `unshare_all`).
    fn default() -> Self {
        Self::unshare_all()
    }
}

fn unshare_user_namespace() {
    // TODO: Refactor to return Result.
    // Get the current user and group IDs before going into a new user namespace.
    let current_uid = users::get_current_uid();
    let current_gid = users::get_current_gid();

    match nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWUSER) {
        Ok(_) => log::debug!("Successfully created a new user namespace."),
        Err(e) => {
            log::error!("Failed to create user namespace: {:?}", e);
            std::process::exit(1);
        }
    }

    // Write the uid_map and gid_map files - we set the current user and group
    // IDs to map to 0 into the new namespace. This makes the current process
    // user act as a root in that user namespace.
    // On some systems, only priv users can create user namespaces. Do this:
    // `sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0`
    // TODO: See if we can check that for the user.
    std::fs::File::create(format!("/proc/self/uid_map"))
        .and_then(|mut f| f.write_all(format!("0 {current_uid} 1\n").as_bytes()))
        .unwrap();
    // The kernel mandates that either:
    // - The parent process has the capability CAP_SETGID OR
    // - We must first deny the use of the `setgroups` syscall by writing to
    //   `/proc/self/setgroups` and there must be a single line in the GID map.
    //
    // Since we don't need more than one GID mapping and we aim for maximum flexibility,
    // we will take the second option.
    //
    // See user_namespaces(7).
    std::fs::File::create(format!("/proc/self/setgroups"))
        .and_then(|mut f| f.write_all(b"deny"))
        .unwrap();
    std::fs::File::create(format!("/proc/self/gid_map"))
        .and_then(|mut f| f.write_all(format!("0 {current_gid} 1\n").as_bytes()))
        .unwrap();
}

fn unshare_net_namespace() {
    // This requires root privileges.
    match nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET) {
        Ok(_) => log::debug!("Successfully created a new network namespace."),
        Err(error) => {
            log::error!("Failed to create network namespace: {:?}.", error);
            std::process::exit(1);
        }
    }
}

fn unshare_mount_namespace() {
    match nix::sched::unshare(
        nix::sched::CloneFlags::CLONE_FS | nix::sched::CloneFlags::CLONE_NEWNS,
    ) {
        Ok(_) => log::debug!("Successfully created a new mount namespace"),
        Err(error) => {
            log::error!("Failed to create mount namespace: {:?}.", error);
            std::process::exit(1); // TODO
        }
    };

    nix::mount::mount(
        Some("ignored"),
        "/",
        Some("ignored"),
        // Do not share the mount.
        nix::mount::MsFlags::MS_PRIVATE | nix::mount::MsFlags::MS_REC,
        Some("ignored"),
    )
    .unwrap_or_else(|e| panic!("Failed to isolate root fs: {e}")); // TODO
}

/// Adds a route to the main routing table.
///
/// - `dest` - The target network of the route.
/// - `gateway` - The network gateway to be used for the given `dest`.
/// - `handle` - A rtnetlink connection handle to use.
#[doc(hidden)]
async fn add_route(dest: IpNetwork, gateway: IpAddr, handle: Handle) -> Result<(), Error> {
    match (dest, gateway) {
        (IpNetwork::V4(dest), IpAddr::V4(gateway)) => {
            let route = handle.route();
            // By default the route will be added to the main routing table.
            route
                .add()
                .v4()
                .destination_prefix(dest.ip(), dest.prefix())
                .gateway(gateway)
                .execute()
                .await?;
            Ok(())
        }
        (IpNetwork::V6(_dest), IpAddr::V6(_gateway)) => {
            todo!("Support for IPv6 not implemented.")
        }
        (_, _) => panic!("Mixing IP address versions"), // TODO
    }
}

/// Bring the network interface with the given name up.
async fn link_up(name: &str) -> Result<(), Error> {
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    let mut links = handle.link().get().match_name(name.to_owned()).execute();
    if let Some(link) = links.try_next().await? {
        handle.link().set(link.header.index).up().execute().await?;
        Ok(())
    } else {
        Err(rtnetlink::Error::RequestFailed)
    }
}

/// Creates and configures a tunnel interface.
///
/// - `tun_name` - The name of the interface.
/// - `address` - The interface address.
/// - `netmask` - The interface address network mask.
/// - `gateway` - The gateway that the interface provides.
async fn configure_tun_sinkhole(
    tun_name: &str,
    address: IpAddr,
    netmask: IpAddr,
    gateway: IpAddr,
) -> tun::AsyncDevice {
    // Create a TUN device.
    log::debug!("Creating TUN device.");
    let mut config = tun::Configuration::default();
    config
        .tun_name(tun_name)
        .address(address)
        .netmask(netmask)
        .destination(gateway)
        .up();
    let tun_device = tun::create_as_async(&config).unwrap();

    // Add an address to the new link.
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    log::debug!("Adding default route.");
    match add_route(
        IpNetwork::from_str("0.0.0.0/0").unwrap(),
        gateway.clone(),
        handle,
    )
    .await
    {
        Ok(()) => log::debug!("Added route to table to the default route table."),
        Err(error) => {
            log::error!("Failed to add route because of error: {:?}.", error);
            std::process::exit(1);
        }
    }

    return tun_device;
}
