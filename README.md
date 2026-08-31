# masque-lite

`masque-lite` is a minimal Mihomo-compatible CONNECT-IP MASQUE server. It is intentionally not a general-purpose MASQUE implementation.

Current scope: Linux target, IPv4-only policy, HTTP/3 + QUIC, CONNECT-IP request validation, mutual-TLS client authentication, fixed address assignment, and a Linux TUN packet data plane. It is experimental and awaiting VPS interoperability validation.

The protocol core is delegated to [MetaCubeX/connect-ip-go](https://github.com/MetaCubeX/connect-ip-go). `usque` documents Cloudflare compatibility differences; `Vincent-bin/masque-server` was used as a reference only and no code was copied.

## Build and key material

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o masque-lite ./cmd/masque-lite
./masque-lite keygen
```

`keygen` emits a P-256 client key pair in Mihomo's base64 format. Put the public value in `client.public_keys` and the private value in Mihomo's `private-key`. Mihomo's `public-key` is the server certificate's pinned P-256 public key.

Generate a separate P-256 ECDSA server certificate for masque-lite. Do not use an RSA wildcard certificate:

```sh
masque-lite server-keygen -cert /etc/masque-lite/server.crt -key /etc/masque-lite/server.key
```

The command writes the private key only to the requested file, prints the certificate path and a base64 PKIX `public-key`, and refuses to overwrite existing files. Use the printed `public-key` in Mihomo. This self-signed certificate is intentionally independent of Nginx and other services because Mihomo pins the server public key.

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
sudo nft add rule ip masque_lite postrouting oifname "eth0" ip saddr 192.0.2.0/30 masquerade
sudo systemctl enable masque-lite
sudo systemctl start masque-lite
sudo ip addr add 192.0.2.1/30 dev masque0
sudo ip link set masque0 mtu 1280 up
```

Replace `eth0` and the tunnel subnet as needed. The service does not modify sysctl or firewall state.

## Validation and memory

Go unit tests and a Linux amd64 build are automated. VPS testing must still verify Mihomo setup, TCP/UDP/DNS/QUIC traffic, reconnect, restart recovery, MTU behavior, and packet-loop absence:

```sh
systemctl show masque-lite.service -p MemoryCurrent -p MemoryPeak
ps -C masque-lite -o pid,rss,vsz,%mem
```
