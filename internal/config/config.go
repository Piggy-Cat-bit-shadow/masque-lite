package config

import (
	"fmt"
	"github.com/Piggy-Cat-bit-shadow/masque-lite/internal/auth"
	"gopkg.in/yaml.v3"
	"net/netip"
	"os"
)

type Config struct {
	Listen  string   `yaml:"listen"`
	TLS     TLS      `yaml:"tls"`
	Client  Client   `yaml:"client"`
	Clients []Client `yaml:"clients,omitempty"`
	Server  Server   `yaml:"server"`
}
type TLS struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}
type Client struct {
	Name       string   `yaml:"name,omitempty"`
	PublicKey  string   `yaml:"public_key"`
	PublicKeys []string `yaml:"public_keys"`
	TunnelIPv4 string   `yaml:"tunnel_ipv4"`
}
type ResolvedClient struct {
	Name       string
	PublicKeys []string
	TunnelIPv4 netip.Prefix
}
type Server struct {
	TunnelIPv4 string `yaml:"tunnel_ipv4"`
	MTU        int    `yaml:"mtu"`
}

func Load(path string) (Config, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return Config{}, e
	}
	var c Config
	if e = yaml.Unmarshal(b, &c); e != nil {
		return c, e
	}
	if c.Server.MTU == 0 {
		c.Server.MTU = 1280
	}
	return c, c.Validate()
}
func (c Config) Validate() error {
	if c.Listen == "" || c.TLS.Cert == "" || c.TLS.Key == "" {
		return fmt.Errorf("listen, tls.cert and tls.key are required")
	}
	if len(c.Clients) > 0 && (len(c.Client.PublicKeys) > 0 || c.Client.PublicKey != "" || c.Client.TunnelIPv4 != "") {
		return fmt.Errorf("client and clients cannot both be configured")
	}
	if c.Server.MTU != 0 && (c.Server.MTU < 576 || c.Server.MTU > 65535) {
		return fmt.Errorf("server.mtu must be between 576 and 65535")
	}
	if _, e := c.ResolvedClients(); e != nil {
		return e
	}
	return nil
}

func (c Config) ResolvedClients() ([]ResolvedClient, error) {
	server, e := netip.ParsePrefix(c.Server.TunnelIPv4)
	if e != nil || !server.Addr().Is4() {
		return nil, fmt.Errorf("invalid IPv4 prefix %q", c.Server.TunnelIPv4)
	}
	clients := c.Clients
	if len(clients) == 0 {
		clients = []Client{c.Client}
	}
	if len(clients) == 0 {
		return nil, fmt.Errorf("at least one client is required")
	}
	out := make([]ResolvedClient, 0, len(clients))
	seenIP := map[netip.Addr]bool{}
	seenKey := map[string]bool{}
	for _, cl := range clients {
		p, e := netip.ParsePrefix(cl.TunnelIPv4)
		if e != nil || !p.Addr().Is4() || p.Bits() != 32 {
			return nil, fmt.Errorf("client %q tunnel_ipv4 must be an IPv4 /32", cl.Name)
		}
		if !server.Contains(p.Addr()) || p.Addr() == server.Addr() {
			return nil, fmt.Errorf("client %q tunnel IP is outside server network or equals server", cl.Name)
		}
		if seenIP[p.Addr()] {
			return nil, fmt.Errorf("duplicate client tunnel IP %s", p.Addr())
		}
		seenIP[p.Addr()] = true
		keys := append([]string{}, cl.PublicKeys...)
		if cl.PublicKey != "" {
			keys = append(keys, cl.PublicKey)
		}
		if len(keys) == 0 {
			return nil, fmt.Errorf("client %q has no public key", cl.Name)
		}
		for _, key := range keys {
			if _, e = auth.ValidatePublicKeyString(key); e != nil {
				return nil, fmt.Errorf("client %q public key: %w", cl.Name, e)
			}
			if seenKey[key] {
				return nil, fmt.Errorf("public key assigned to multiple clients")
			}
			seenKey[key] = true
		}
		out = append(out, ResolvedClient{Name: cl.Name, PublicKeys: keys, TunnelIPv4: p})
	}
	return out, nil
}
