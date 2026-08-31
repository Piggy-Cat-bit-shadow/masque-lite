package config

import "testing"

func TestValidate(t *testing.T) {
	c := Config{Listen: "127.0.0.1:4433", TLS: TLS{Cert: "c", Key: "k"}, Client: Client{PublicKeys: []string{"BIU3CobtJ5y6P+wvKc7M1XBfS5FhcvLeVkPhObW4s5QY4UvNYuKxtYrZF+4eCxv2AW4OmvowLmN1v6CQVsJ+f9M="}, TunnelIPv4: "192.0.2.2/32"}, Server: Server{TunnelIPv4: "192.0.2.1/30"}}
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	c.Server.TunnelIPv4 = "::1/128"
	if e := c.Validate(); e == nil {
		t.Fatal("expected IPv6 rejection")
	}
}

func TestMultiClientValidation(t *testing.T) {
	keyA := "BIU3CobtJ5y6P+wvKc7M1XBfS5FhcvLeVkPhObW4s5QY4UvNYuKxtYrZF+4eCxv2AW4OmvowLmN1v6CQVsJ+f9M="
	keyB := "BJVHqCpze4DJd2ZMvQDENmffhP3y1iW9t63vgbGvZ2mCC9kAmupPlruK5JYN8ZpAOFBTQ9zetFSFbPIBH3mWbgA="
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
	if _, err := c.ResolvedClients(); err == nil {
		t.Fatal("expected duplicate key to fail")
	}
}
