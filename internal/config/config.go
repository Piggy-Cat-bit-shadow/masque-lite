package config

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"net/netip"
	"os"
)

type Config struct {
	Listen string `yaml:"listen"`
	TLS    TLS    `yaml:"tls"`
	Client Client `yaml:"client"`
	Server Server `yaml:"server"`
}
type TLS struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}
type Client struct {
	PublicKey  string   `yaml:"public_key"`
	PublicKeys []string `yaml:"public_keys"`
	TunnelIPv4 string   `yaml:"tunnel_ipv4"`
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
	if len(c.Client.PublicKeys) == 0 && c.Client.PublicKey == "" {
		return fmt.Errorf("client.public_keys must contain at least one authorized key")
	}
	if c.Server.MTU != 0 && (c.Server.MTU < 576 || c.Server.MTU > 65535) {
		return fmt.Errorf("server.mtu must be between 576 and 65535")
	}
	for _, s := range []string{c.Client.TunnelIPv4, c.Server.TunnelIPv4} {
		p, e := netip.ParsePrefix(s)
		if e != nil || !p.Addr().Is4() {
			return fmt.Errorf("invalid IPv4 prefix %q", s)
		}
	}
	return nil
}
