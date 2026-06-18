use clap::Parser;
use htapod::{ByPortTCPRouter, HTTPFilter, Namespace, PassthroughUDP};
use hyper::{
    body::{Body, Incoming},
    Request, Response,
};

#[derive(Parser)]
#[command(name = "htapod")]
#[command(version = "1.0")]
#[command(about = "Tap into all HTTP requests!", long_about = None)]
struct Cli {
    /// The actual command to tap into.
    #[arg(
        last = true,
        allow_hyphen_values = true,
        num_args = 1..
    )]
    command: Vec<String>,
}

fn inspect_request(req: &Request<Incoming>) -> () {
    println!("---> {} {}", req.method(), req.uri());
}
fn inspect_response(res: &Response<Incoming>) -> () {
    println!("<--- {} {}", res.status(), res.size_hint().lower());
}

fn main() -> Result<(), ()> {
    env_logger::init();
    let cli = Cli::parse();

    let verify_remote_tls_cert = true;
    let tap = htapod::runner::builder()
        .with_namespace(Namespace::unshare_all())
        .with_tcp_stack(
            HTTPFilter::new_with_inspect(inspect_request, inspect_response),
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
