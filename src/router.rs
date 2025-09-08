use std::{collections::HashMap, net::SocketAddr};

#[derive(Clone)]
pub enum TCPTargetAddress {
    Plain(SocketAddr),
    TLS(SocketAddr),
}

pub trait TCPRouter {
    fn resolve(&self, address: &SocketAddr) -> Option<TCPTargetAddress>;
}

pub enum ByPortDefaultRouting {
    Deny,
    ForwardUnsecured,
    ForwardWithTLS,
}

pub struct ByPortTCPRouter {
    default_routing: ByPortDefaultRouting,
    port_to_proto: HashMap<u16, bool>,
}

pub struct ByPortTCPRouterBuilder {
    default_routing: ByPortDefaultRouting,
    port_to_proto: HashMap<u16, bool>,
}

impl ByPortTCPRouter {
    pub fn builder() -> ByPortTCPRouterBuilder {
        ByPortTCPRouterBuilder {
            default_routing: ByPortDefaultRouting::Deny,
            port_to_proto: HashMap::new(),
        }
    }
}

impl ByPortTCPRouterBuilder {
    pub fn default_routing(mut self, routing: ByPortDefaultRouting) -> Self {
        self.default_routing = routing;
        self
    }

    pub fn forward_with_tls(mut self, port: u16) -> Self {
        self.port_to_proto.insert(port, true);
        self
    }

    pub fn forward_unsecured(mut self, port: u16) -> Self {
        self.port_to_proto.insert(port, false);
        self
    }

    pub fn build(self) -> ByPortTCPRouter {
        ByPortTCPRouter {
            default_routing: self.default_routing,
            port_to_proto: self.port_to_proto,
        }
    }
}

impl TCPRouter for ByPortTCPRouter {
    fn resolve(&self, address: &SocketAddr) -> Option<TCPTargetAddress> {
        let address = *address;
        self.port_to_proto
            .get(&address.port())
            .map(|is_tls| {
                if *is_tls {
                    TCPTargetAddress::TLS(address)
                } else {
                    TCPTargetAddress::Plain(address)
                }
            })
            .or(match &self.default_routing {
                ByPortDefaultRouting::Deny => None,
                ByPortDefaultRouting::ForwardUnsecured => Some(TCPTargetAddress::Plain(address)),
                ByPortDefaultRouting::ForwardWithTLS => Some(TCPTargetAddress::TLS(address)),
            })
    }
}

pub struct MatchAddress<R: TCPRouter> {
    address: std::net::IpAddr,
    target: std::net::IpAddr,
    fallback_router: R,
}

impl<R: TCPRouter> MatchAddress<R> {
    pub fn new(address: std::net::IpAddr, target: std::net::IpAddr, router: R) -> Self {
        Self {
            address,
            target,
            fallback_router: router,
        }
    }
}

impl<R: TCPRouter> TCPRouter for MatchAddress<R> {
    fn resolve(&self, address: &SocketAddr) -> Option<TCPTargetAddress> {
        if self.address == address.ip() {
            self.fallback_router
                .resolve(&SocketAddr::new(self.target, address.port()))
        } else {
            self.fallback_router.resolve(address)
        }
    }
}
