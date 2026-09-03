package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func testPublicKey(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y))
}

func TestValidate(t *testing.T) {
	c := Config{Listen: "127.0.0.1:4433", TLS: TLS{Cert: "c", Key: "k"}, Client: Client{PublicKeys: []string{testPublicKey(t)}, TunnelIPv4: "192.0.2.2/32"}, Server: Server{TunnelIPv4: "192.0.2.1/30"}}
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	c.Server.TunnelIPv4 = "::1/128"
	if e := c.Validate(); e == nil {
		t.Fatal("expected IPv6 rejection")
	}
}

func TestLoadSessionIdleTimeoutDefaultAndDisable(t *testing.T) {
	key := testPublicKey(t)
	base := "listen: 127.0.0.1:4433\ntls:\n  cert: c\n  key: k\nclient:\n  public_keys: [" + key + "]\n  tunnel_ipv4: 192.0.2.2/32\nserver:\n  tunnel_ipv4: 192.0.2.1/30\n"
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.SessionIdleTimeout != "1h" {
		t.Fatalf("default idle timeout = %q", c.Server.SessionIdleTimeout)
	}
	if err := os.WriteFile(path, []byte(base+"  session_idle_timeout: 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.SessionIdleTimeout != "0" {
		t.Fatalf("disabled idle timeout = %q", c.Server.SessionIdleTimeout)
	}
	if c.HostNetwork.CheckInterval != "10s" {
		t.Fatalf("default check interval = %q", c.HostNetwork.CheckInterval)
	}
}

func TestMultiClientValidation(t *testing.T) {
	keyA := testPublicKey(t)
	keyB := testPublicKey(t)
	c := Config{Listen: "127.0.0.1:4433", TLS: TLS{Cert: "c", Key: "k"}, Clients: []Client{{Name: "iphone", PublicKeys: []string{keyA}, TunnelIPv4: "192.0.2.2/32"}, {Name: "mac", PublicKeys: []string{keyB}, TunnelIPv4: "192.0.2.3/32"}}, Server: Server{TunnelIPv4: "192.0.2.1/24", MTU: 1280}}
	clients, err := c.ResolvedClients()
	if err != nil || len(clients) != 2 {
		t.Fatalf("clients = %#v, err = %v", clients, err)
	}
	c.Clients[1].TunnelIPv4 = "198.51.100.3/32"
	if _, err := c.ResolvedClients(); err == nil {
		t.Fatal("expected client outside server subnet to fail")
	}
	c.Clients[1].TunnelIPv4 = "192.0.2.2/32"
	if _, err := c.ResolvedClients(); err == nil {
		t.Fatal("expected duplicate IP to fail")
	}
	c.Clients[1].TunnelIPv4 = "192.0.2.3/32"
	c.Clients[1].PublicKeys = []string{keyA}
	c.Clients[1].TunnelIPv4 = "192.0.2.4/32"
	if _, err := c.ResolvedClients(); err == nil {
		t.Fatal("expected duplicate key to fail")
	}
}

func TestSessionNatValidation(t *testing.T) {
	key := testPublicKey(t)
	c := Config{
		Listen: "127.0.0.1:4433",
		TLS:    TLS{Cert: "c", Key: "k"},
		Client: Client{PublicKeys: []string{key}, TunnelIPv4: "192.0.2.2/32"},
		Server: Server{TunnelIPv4: "192.0.2.1/24", SessionNat: SessionNat{Enabled: true, Pool: "192.0.2.128/25", MaxSessions: 120, ReuseDelay: "30m"}},
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.Server.SessionNat.Pool = "192.0.2.0/25"
	if err := c.Validate(); err == nil {
		t.Fatal("expected pool containing server address to fail")
	}
}
