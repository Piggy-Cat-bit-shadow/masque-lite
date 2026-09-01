# masque-lite

`masque-lite` is a minimal Mihomo-compatible CONNECT-IP MASQUE server. It is intentionally not a general-purpose MASQUE implementation.

Current scope: Linux target, IPv4-only policy, HTTP/3 + QUIC, CONNECT-IP request validation, mutual-TLS client authentication, fixed address assignment, and a Linux TUN packet data plane. The recommended shared-profile mode supports many concurrent sessions using the same Mihomo key and visible tunnel IP.

The protocol core is delegated to [MetaCubeX/connect-ip-go](https://github.com/MetaCubeX/connect-ip-go). `usque` documents Cloudflare compatibility differences; `Vincent-bin/masque-server` was used as a reference only and no code was copied.

## Build and key material

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o masque-lite ./cmd/masque-lite
./masque-lite keygen
```

`keygen` emits a P-256 client key pair. Its `private-key` is base64-encoded SEC1 ASN.1 DER and goes directly in Mihomo's `private-key`. Its `public-key` is an uncompressed P-256 key and goes in the server `config.yaml` `client.public_keys` whitelist.

The server persists its QUIC Stateless Reset Key at `/var/lib/masque-lite/stateless-reset.key` by default. It is generated once with mode `0600`; do not copy it into logs or client configuration. A restart loads the same key so stale QUIC connections can be reset promptly.

The legacy single-client configuration remains supported. For concurrent devices, use one independent client key and one `/32` per device:

```yaml
client:
  public_keys:
    - KEY_A
  tunnel_ipv4: 192.0.2.2/32

server:
  tunnel_ipv4: 192.0.2.1/24
  mtu: 1280
  session_idle_timeout: 30m
  session_nat:
    enabled: true
    pool: 192.0.2.128/25
    max_sessions: 120
    reuse_delay: 30m
```

```yaml
clients:
  - name: iphone
    public_keys: [KEY_A]
    tunnel_ipv4: 192.0.2.2/32
  - name: mac
    public_keys: [KEY_B]
    tunnel_ipv4: 192.0.2.3/32

server:
  tunnel_ipv4: 192.0.2.1/24
  mtu: 1280
```

`client` and non-empty `clients` cannot be mixed. A repeated tunnel IP is rejected; a key assigned to different tunnel IPs is rejected. In the recommended shared-profile mode, the same key and visible IP can establish concurrent sessions; each receives a private shadow address. With `session_nat.enabled: false`, legacy same-IP newest-session-wins behavior remains available. Expand the host NAT/firewall subnet when expanding the server subnet; masque-lite does not modify host networking.

Generate a separate P-256 ECDSA server certificate for masque-lite. Do not use an RSA wildcard certificate:

```sh
masque-lite server-keygen -cert /etc/masque-lite/server.crt -key /etc/masque-lite/server.key
```

The command writes the private key only to the requested file, prints the certificate path and a base64 PKIX `public-key`, and refuses to overwrite existing files. Use this server `public-key` in Mihomo's node `public-key` field. This self-signed certificate is intentionally independent of Nginx and other services because Mihomo pins the server public key.

## Mihomo example

```yaml
proxies:
  - name: MASQUE-Lite
    type: masque
    server: example.com
    port: 4433
    private-key: BASE64_P256_CLIENT_PRIVATE_KEY
    public-key: BASE64_P256_SERVER_CERT_PUBLIC_KEY
    ip: 192.0.2.2/32
    mtu: 1280
    udp: true
```

## Linux deployment

Install the binary, certificates, config, and `contrib/masque-lite.service`; create a `masque-lite` user and grant only `CAP_NET_ADMIN`. Ensure `/dev/net/tun` exists, then configure networking explicitly:

```sh
sudo sysctl -w net.ipv4.ip_forward=1
sudo nft add table ip masque_lite
sudo nft 'add chain ip masque_lite postrouting { type nat hook postrouting priority srcnat; policy accept; }'
sudo nft add rule ip masque_lite postrouting oifname "eth0" ip saddr 192.0.2.0/24 masquerade
sudo systemctl enable --now masque-lite
```

Replace `eth0` as needed. The forwarding firewall and MASQUERADE rule must cover the complete server network, including the shadow pool (`192.0.2.0/24` in this example). At startup, masque-lite configures `masque0` itself from `server.tunnel_ipv4` and `server.mtu`, including the IPv4 address, netmask, MTU, and UP flag. The service checks that `/proc/sys/net/ipv4/ip_forward` is `1`, but does not modify sysctl or firewall state.

The legacy `client` block remains supported:

```yaml
client:
  public_keys: [KEY_A]
  tunnel_ipv4: 192.0.2.2/32
server:
  tunnel_ipv4: 192.0.2.1/30
  mtu: 1280
```

For separate visible identities, use the `clients` block with one independent P-256 client key and one `/32` per device:

```yaml
clients:
  - name: iphone
    public_keys: [KEY_A]
    tunnel_ipv4: 192.0.2.2/32
  - name: mac
    public_keys: [KEY_B]
    tunnel_ipv4: 192.0.2.3/32
server:
  tunnel_ipv4: 192.0.2.1/24
  mtu: 1280
```

Do not configure both blocks. The service uses one TUN reader and bounded per-session queues, and does not implement a userspace TCP/IP stack.

The shared-profile mode is the recommended production data plane for multiple users/devices sharing one Mihomo profile:

```yaml
server:
  tunnel_ipv4: 192.0.2.1/24
  mtu: 1280
  session_nat:
    enabled: true
    pool: 192.0.2.128/25
    max_sessions: 120
    reuse_delay: 30m
```

Each session receives a unique internal shadow address from the pool. Packets are rewritten at the TUN boundary so Linux conntrack can distinguish concurrent flows; the visible Mihomo configuration remains unchanged. Shadow addresses are cooled down for `reuse_delay` after close so stale conntrack packets are not delivered to a new session. The pool must be inside the server network, must not contain the server address, and must leave room for network/broadcast addresses. `max_sessions` defaults to 120 and is capped at 4096.

`server.session_idle_timeout` defaults to `30m`. It counts only successfully forwarded CONNECT-IP IPv4 packets, not QUIC keepalive or PING traffic. Set it to `0` to disable business-session idle reclamation. A single global reaper checks sessions once per minute.

Before replacing a running binary, use the configuration-only preflight (it does not create a TUN, listen, or change host state, and does not create the reset-key file):

```sh
masque-lite check-config -config /etc/masque-lite/config.yaml
```

## Validation and memory

Go tests, race tests, vet, and a Linux amd64 build are automated. VPS testing must still verify Mihomo setup, TCP/UDP/DNS/QUIC traffic, reconnect, restart recovery, MTU behavior, and packet-loop absence:

```sh
systemctl show masque-lite.service -p MemoryCurrent -p MemoryPeak
ps -C masque-lite -o pid,rss,vsz,%mem
```
