# htapod 🦑

Rootlessly tap into a program's network traffic.

`htapod` allows you to wrap an executable and observe all UDP and TCP traffic (including decrypted TLS) to
and from it, without requiring root permissions.

This project was inspired by [httptap](https://github.com/monasticacademy/httptap).
It has a different approach, so it might be interesting to check it out!

**This project is currently work in progress and is purely educational.** There are a lot of
rough edges and you might need to extend the out-of-the-box filters for your use case.

_NOTE_: On some distributions you might need to tweak app armour to allow
unpriviliged users to create user namespaces with `sysctl kernel.apparmor_restrict_unprivileged_userns=0`.

Roadmap:
- Properly parse and summarize HTTP messages.
- Allow to "grep" for certain patterns in the traffic.

Tested on Ubuntu server 24.04.

## Example

As a CLI:

```sh
$ htapod -- python3 -c 'import requests; requests.get('\''https://google.com/'\'')'`
--> GET / 0 bytes
<-- 301 220 bytes
--> GET / 0 bytes
<-- 200 0 bytes # This is a bug - chunked encodings are not yet supported.
```

As a library:

```rust
fn main() {
    let verify_remote_tls_cert = true;

    let htap = htapod::runner::builder()
        .with_namespace(Namespace::unshare_all())
        .with_tcp_stack(
            // Write your own TCP sniffer or use a provided one.
            PassthroughTCP::new(),
            // Route TCP connections as TLS to the outside world.
            ByPortTCPRouter::builder()
                .default_routing(ByPortDefaultRouting::ForwardWithTLS)
                .build(),
            verify_remote_tls_cert,
        )
        .build();

    let cmd: Vec<&str> = "curl -s https://isitfridayyet.net -o /dev/null".split(' ').collect();
    // Unsafe because we fork().
    unsafe { htap.run(cmd[0], cmd[1..].iter()) };
}
```

## How does it work?

<img width="3158" height="2230" alt="htapod-2025-05-06-2057-2" src="https://github.com/user-attachments/assets/b9f8a55d-fb14-434b-9acb-8cf1c682c03b" />

### Networking

A non-root user cannot "stear" all traffic at will, but it could if it _unshares_ the root
level resources of a system. Specifically, `htapod` uses the `unshare` system call to
move into a new user namespace and a new network namespace. In these new namespaces,
it creates a virtual TUN interface and modifies the routing table so all packets
pass through that interface. A TUN interface is a virtual network interface that is
backed by a file descriptor - any traffic that goes into the interface can be read
from the file descriptor as IP packets; similarly, any data written into the file
descriptor goes out of the interface. This means that we need to process IP
packets in user space, instead of TCP ones, and for that we use the `netstack_smoltcp`
crate. This allows us to work with TCP streams and proxy the data to the outside world.

One detail missing from above is how to actually route to the outside world when the
new network namespace does not have access to any of the existing interfaces. To do this,
the program creates a `socketpair` before `fork`-ing and `unshare`-ing. The child
process later sends the TUN file handle through the `socketpair` to the parent process,
allowing it to both receive traffic from within the new namespace and have access
to the interfaces on the machine.

*But what about 127.0.0.1?* `127.0.0.1` is a _martian_ address and the routing table
ignores it (unless you tell the kernel not to). This is a problem for us, because we want to
be able to route traffic from within the new network namespace to the local loopback
in the root network namespace. As a workaround, `htapod` can match
a non-martian address originating from the network namespace and route it to `127.0.0.1`
in the root network namespace. For example, if you have a server running on
`127.0.0.1:8080` in the root network namespace, you can configure `htapod` to route any
traffic destined for `10.10.10.10` to `127.0.0.1` instead. The below code snippet
shows this:

```rust
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
        true,
    )
    .build();
```

#### UDP and SNAT

TCP communication is stateful, meaning there is an established connection between
the peers. When a process in the network namespace attempts to connect to the outside world
`htapod` will terminate the connection and establish a new connection from the root
network namespace from which it will proxy the traffic. For example, the process may
connect from an address `10.10.10.10:56432`, and `htapod` will create a connection from
`192.168.1.1:12345` to `104.16.133.229:443`. It is somewhat intuitive to keep the two
connections associated with each other, so we are essentially doing a SNAT - we know
that traffic coming from `104.16.133.229:443` to `192.168.1.1:12345` must be routed
to the "hidden" (for the outside world) address `10.10.10.10:56432` inside the network
namespace.

For UDP, which is stateless, this is less intuitive - on one hand UDP is "fire and forget",
but on the other hand, applications can build state on top of it. A simple but important
use case for this is DNS resolution - the process can make a DNS query about `cloudflare.com`
by sending a DNS packet from `10.10.10.10:56432` to `1.1.1.1:53`. `htapod` will make the
query on behalf of the process from e.g. `192.168.1.1:53535`. When the DNS server
responds to the query it will send a UDP packet to `192.168.1.1:53535`. Thus, `htapod`
needs to maintain an SNAT for UDP as well to be able to "reverse proxy" the DNS response.

`htapod` currently implements a very simple SNAT for UDP which is "permanent", i.e. there are
no rules or TTL for the SNAT record. However, this works for DNS, though other protocls built
on top of UDP may have problems (QUIC and HTTP3 come to mind).

### Decrypting TLS

`htapod` allows traffic sniffing even for TLS connections. This is done again by
replacing system resources before starting the given command. In this case, `htapod`
`unshare`s the mount namespace as well. This allows it to create an overlay filesystem
mount over the default directories which store trusted certificate authorities
(`/etc/ssl/certs/ca-certificates.crt`). Specifically, it creates a new self-signed
dummy CA certificate and puts it there. Then, once the user command is started, on every TLS connection
attempt, `htapod` will create a new leaf certificate using the dummy CA, using the server
name from the SNI in the handshake. Because typically most TLS stacks use the system CA store,
they will find the dummy CA and hence trust the certificate.

If the process you want to start does not use the system CA, you might need to add the
necessary environment variables to force the use of the new CA. See the `httptap` project,
which does more extensive mocking of the trusted roots out of the box and can help you
out with configuring this.

### Async details

Full disclousure - the async tasks are currently in a bit of a mess. The main goal of this
project was to be a learning exercise in linux and networkig. That said, ideally the situation
can be a lot better in terms of resource utilization and performance. One thing to note is that
before calling `unshare` on the user namespace, we must be running as a single-threaded
process. From the man page of unshare:

> CLONE_NEWUSER requires that the calling process is not threaded;

So any initialisation of the tokio runtime must happen after the `unshare` call if we are
to use multiple threads.

## Resources and references

- https://github.com/monasticacademy/httptap
- https://github.com/giuseppe/slirp-forwarder/blob/master/main.c
- https://github.com/alexander-smoktal/async-send-fd
