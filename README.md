# masque-lite

`masque-lite` is a minimal Mihomo-compatible CONNECT-IP MASQUE server. It is intentionally not a general-purpose MASQUE implementation.

Current scope: Linux target, IPv4-only policy, HTTP/3 + QUIC, CONNECT-IP request validation, mutual-TLS client authentication, fixed address assignment, and a Linux TUN packet data plane. It is experimental and awaiting VPS interoperability validation.

The protocol core is delegated to [MetaCubeX/connect-ip-go](https://github.com/MetaCubeX/connect-ip-go). `usque` documents Cloudflare compatibility differences; `Vincent-bin/masque-server` was used as a reference only and no code was copied.

## Build and key material

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o masque-lite ./cmd/masque-lite
./masque-lite keygen
```

`keygen` emits a P-256 client key pair. Its `private-key` is base64-encoded SEC1 ASN.1 DER and goes directly in Mihomo's `private-key`. Its `public-key` is an uncompressed P-256 key and goes in the server `config.yaml` `client.public_keys` whitelist.

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
sudo nft add rule ip masque_lite postrouting oifname "eth0" ip saddr 192.0.2.0/30 masquerade
sudo systemctl enable --now masque-lite
```

Replace `eth0` and the tunnel subnet as needed. At startup, masque-lite configures `masque0` itself from `server.tunnel_ipv4` and `server.mtu`, including the IPv4 address, netmask, MTU, and UP flag. The service does not modify sysctl or firewall state.

## Validation and memory

Go unit tests and a Linux amd64 build are automated. VPS testing must still verify Mihomo setup, TCP/UDP/DNS/QUIC traffic, reconnect, restart recovery, MTU behavior, and packet-loop absence:

```sh
systemctl show masque-lite.service -p MemoryCurrent -p MemoryPeak
ps -C masque-lite -o pid,rss,vsz,%mem
```
