package config

import "testing"

func TestValidate(t *testing.T) {
	c := Config{Listen: "127.0.0.1:4433", TLS: TLS{Cert: "c", Key: "k"}, Client: Client{PublicKeys: []string{"x"}, TunnelIPv4: "192.0.2.2/32"}, Server: Server{TunnelIPv4: "192.0.2.1/30"}}
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	c.Server.TunnelIPv4 = "::1/128"
	if e := c.Validate(); e == nil {
		t.Fatal("expected IPv6 rejection")
	}
}
