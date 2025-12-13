use htapod::router::{ByPortDefaultRouting, MatchAddress};
use htapod::Namespace;
use htapod::{ByPortTCPRouter, PassthroughTCP};
use hyper::server::conn::Http;
use hyper::service::service_fn;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::PrivateKeyDer;
use std::sync::Arc;
use tokio::net::TcpListener;

#[test]
fn test_passthrough_tcp() {
    let _ = env_logger::builder().is_test(true).try_init();
    // Spawn a mock server with a POST path /dino that expects some
    // payload. Then run curl under htapod and check that both the request
    // and the response content is intact.
    let mut server = mockito::Server::new();
    let request_content = "Dinosaur?";
    let response_content = "Dinosaur!";
    let path = "/dino";
    let mock = server
        .mock("POST", path)
        .with_status(200)
        .with_body(response_content)
        .match_body(request_content)
        .create();

    let localhost = "10.10.10.10";
    let htap = htapod::runner::builder()
        .with_namespace(Namespace::unshare_all())
        .with_tcp_stack(
            PassthroughTCP::new(),
            MatchAddress::new(
                localhost.parse().unwrap(),
                "127.0.0.1".parse().unwrap(),
                ByPortTCPRouter::builder()
                    .default_routing(ByPortDefaultRouting::ForwardUnsecured)
                    .build(),
            ),
            true,
        )
        .build();

    let url = format!(
        "{localhost}:{}{path}",
        server.host_with_port().rsplit_once(':').unwrap().1
    );
    // NOTE: We need to keep the file because the `run` will fork a child which
    // will close the tempfile when it exists.
    let response_file = tempfile::Builder::new().keep(true).tempfile().unwrap();
    let cmd = format!(
        "curl -s {url} -d {request_content} -o {}",
        response_file.path().to_str().unwrap()
    );
    let cmd: Vec<&str> = cmd.split(' ').collect();
    unsafe { htap.run(cmd[0], cmd[1..].iter()) };
    mock.assert();
    let actual = std::fs::read_to_string(response_file).unwrap();
    assert_eq!(response_content, actual);
}

pub async fn start_server() -> Result<u16, Box<dyn std::error::Error + Send + Sync>> {
    let subject_alt_names = vec!["127.0.0.1".to_string()];
    let cert = generate_simple_self_signed(subject_alt_names)?;

    // Pick a random available port
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = tcp_listener.local_addr().unwrap().port();

    let certs = vec![cert.cert.der().clone().into_owned()];
    let key = PrivateKeyDer::from_pem_slice(cert.key_pair.serialize_pem().as_bytes()).unwrap();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();

    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    tokio::spawn(async move {
        loop {
            let (stream, _) = tcp_listener.accept().await.unwrap();
            let tls_acceptor = tls_acceptor.clone();

            tokio::spawn(async move {
                let stream = tls_acceptor.accept(stream).await.unwrap();
                let service = service_fn(|_| async {
                    let response = hyper::Response::builder()
                        .version(hyper::Version::HTTP_11)
                        .body(hyper::Body::from("Hello, World!"))
                        .unwrap();
                    Ok::<_, hyper::Error>(response)
                });

                if let Err(err) = Http::new().serve_connection(stream, service).await {
                    println!("Error serving connection: {:?}", err);
                }
            });
        }
    });

    Ok(port)
}

#[test]
fn test_server() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let port = rt.block_on(async { start_server().await.unwrap() });

    let localhost = "10.10.10.10";
    let htap = htapod::runner::builder()
        .with_namespace(Namespace::unshare_all())
        .with_tcp_stack(
            PassthroughTCP::new(),
            MatchAddress::new(
                localhost.parse().unwrap(),
                "127.0.0.1".parse().unwrap(),
                ByPortTCPRouter::builder()
                    .default_routing(ByPortDefaultRouting::ForwardWithTLS)
                    .build(),
            ),
            false,
        )
        .build();

    // NOTE: We need to keep the file because the `run` will fork a child which
    // will close the tempfile when it exists.
    let response_file = tempfile::Builder::new().keep(true).tempfile().unwrap();
    let cmd = format!(
        "curl -vv https://{localhost}:{port}/ -o {}",
        response_file.path().to_str().unwrap()
    );
    let cmd: Vec<&str> = cmd.split(' ').collect();
    unsafe { htap.run(cmd[0], cmd[1..].iter()) };
    let response = std::fs::read_to_string(response_file).unwrap();
    assert_eq!(response, "Hello, World!");
}
