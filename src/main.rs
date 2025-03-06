use clap::Parser;
use htapod::{ByPortTCPRouter, HttpFilter, Namespace, PassthroughUDP};
use ipnet::IpNet;
use std::{net::IpAddr, str::FromStr};

#[derive(Parser)]
#[command(name = "htapod")]
#[command(version = "1.0")]
#[command(about = "Tap into all HTTP requests!", long_about = None)]
struct Cli {
    /// Do not switch to a new user namespace.
    #[arg(short, long = "no-unshare")]
    no_unshare: bool,

    /// The name of the TUN device that will be created.
    #[arg(long = "tun-name", default_value = "htapod")]
    tun_name: String,

    /// IP address of the network that the command will see.
    #[arg(long = "subnet", default_value_t = IpNet::from_str("10.1.11.4/24").unwrap())]
    subnet: IpNet,

    /// Gateway
    #[arg(long = "gateway", default_value_t = IpAddr::from_str("10.1.1.1").unwrap())]
    gateway: IpAddr,

    /// The actual command to tap into.
    #[arg(
        last = true,
        allow_hyphen_values = true,
        num_args = 1..
    )]
    command: Vec<String>,
}

fn main() -> Result<(), ()> {
    env_logger::init();
    let cli = Cli::parse();

    let verify_remote_tls_cert = true;
    let tap = htapod::runner::builder()
        .namespace(
            Namespace::new()
                .with_user_namespace(!cli.no_unshare)
                .with_net_namespace(true)
                .with_mount_namespace(true),
        )
        .with_tcp_stack(
            HttpFilter::new(std::io::stdout()),
            ByPortTCPRouter::builder()
                .forward_unsecured(80)
                .forward_with_tls(443)
                .build(),
            verify_remote_tls_cert,
        )
        .with_udp_stack(PassthroughUDP::new())
        .build();

    unsafe { tap.run(cli.command[0].as_str(), &cli.command[1..]) };

    Ok(())
}
