# htapod 🦑

Rootlessly tap into a program's network traffic.

`htapod` allows you to wrap an executable and observe all UDP and TCP traffic (including decrypted TLS) to
and from it, without requiring root permissions.

This project was inspired by [httptap](https://github.com/monasticacademy/httptap).
It has a slighly different approach, so it might be interesting to check it out!

**This project is currently work in progress and is purely educational.** There are a lot of
rough edges and you might need to extend the out-of-the-box filters for your use case.

_NOTE_: On some distributions you might need to tweak app armour to allow
unpriviliged users to create user namespaces with `sysctl kernel.apparmor_restrict_unprivileged_userns=0`.

Roadmap:
- Properly parse and summarize HTTP messages.
- Allow to "grep" for certain patterns in the traffic.

## Example

As a CLI:

```sh
$ htapod -- python3 -c 'import requests; requests.get('\''https://google.com/'\'')'`
--> GET / 0 bytes
<-- 301 220 bytes
--> GET / 0 bytes
<-- 200 0 bytes # This is a bug chunked encodings are not yet supported.
```

As a library:

```rust
fn main() {
    let verify_remote_tls_cert = true;

    let htap = htapod::runner::builder()
        .namespace(
            Namespace::new()
                .with_user_namespace(true)
                .with_net_namespace(true)
                .with_mount_namespace(true),
        )
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
it creates a virtual TUN interface and modifies the routing table so all destinations
pass through that interface. From then on, a userspace network stack processes the IP
packets from the TUN interface and proxies the traffic to the outside world.

One detail missing from above is how to actually route to the outside world when the
new network namespace does not have access to any of the existing interfaces. To do this,
the program creates a `socketpair` before `fork`-ing and `unshare`-ing. The child
process later sends the TUN file handle through the `socketpair` to the parent process,
allowing it to both receive traffic from within the new namespace and have access
to the interfaces on the machine.

*But what about 127.0.0.1?* `127.0.0.1` is a _martian_ address and the routing table
ignores it (unless you tell the kernel not to). To overcome this, `htapod` can match
a non-martian address originating from the network namespace and route it to `127.0.0.1`
in the root network namespace. So for example, if you have a server running on
`127.0.0.1:8080`, you can "reserve", say, `10.10.10.10` for it and do

```rust
let localhost = "10.10.10.10";
let htap = htapod::runner::builder()
    .namespace(
        Namespace::new()
            .with_user_namespace(true)
            .with_net_namespace(true)
            .with_mount_namespace(true),
    )
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

The above will configure `htapod` to route a TCP packet for `10.10.10.10`
to `127.0.0.1` instead and will forward the connection as plain TCP.

### Decrypting TLS

`htapod` allows traffic sniffing even for TLS connections. This is done again by
replacing system resources before starting the given command. In this case, `htapod`
`unshare`s the mount namespace as well. This allows it to create an overlay filesystem
mount over the default directories which store trusted certificate authorities
(/etc/ssl/certs/ca-certificates.crt). Specifically, it creates a new self-signed
dummy CA and puts it there. Then, once the user command is started, on every TLS connection
attempt, `htapod` will create a new leaf certificate using the dummy CA, using the server
name from the SNI in the handshake. Because typically most TLS stacks use the system CA store,
they will find the dummy CA and hence trust the certificate.

## Resources and references

- https://github.com/monasticacademy/httptap
- https://github.com/giuseppe/slirp-forwarder/blob/master/main.c
- https://github.com/alexander-smoktal/async-send-fd
