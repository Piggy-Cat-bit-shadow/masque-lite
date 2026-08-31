package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Piggy-Cat-bit-shadow/masque-lite/internal/auth"
	"github.com/Piggy-Cat-bit-shadow/masque-lite/internal/config"
	"github.com/Piggy-Cat-bit-shadow/masque-lite/internal/session"
	"github.com/Piggy-Cat-bit-shadow/masque-lite/internal/tunnel"
	connectip "github.com/metacubex/connect-ip-go"
	mh "github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
	"github.com/yosida95/uritemplate/v3"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if len(os.Args) > 1 && os.Args[1] == "keygen" {
		keygen()
		return nil
	}
	if len(os.Args) > 1 && os.Args[1] == "server-keygen" {
		serverKeygen(os.Args[2:])
		return nil
	}
	path := flag.String("config", "/etc/masque-lite/config.yaml", "configuration file")
	flag.Parse()
	c, err := config.Load(*path)
	if err != nil {
		return err
	}
	clients, err := c.ResolvedClients()
	if err != nil {
		return err
	}
	byKey := make(map[string]config.ResolvedClient)
	for _, cl := range clients {
		for _, key := range cl.PublicKeys {
			byKey[key] = cl
		}
	}
	cert, err := tls.LoadX509KeyPair(c.TLS.Cert, c.TLS.Key)
	if err != nil {
		return err
	}
	tc := &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}}
	tc.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) != 1 {
			return fmt.Errorf("exactly one client certificate required")
		}
		if _, ok := byKey[auth.PublicKeyBytes(cs.PeerCertificates[0])]; !ok {
			return fmt.Errorf("client certificate public key is not authorized")
		}
		return nil
	}
	serverPrefix, _ := netip.ParsePrefix(c.Server.TunnelIPv4)
	tun, err := tunnel.Open("masque0", c.Server.MTU)
	if err != nil {
		return err
	}
	defer tun.Close()
	if err = tun.Configure(serverPrefix); err != nil {
		return fmt.Errorf("configure masque0: %w", err)
	}
	ln, err := net.ListenPacket("udp", c.Listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	mgr := session.NewManager()
	fatal := make(chan error, 2)
	go tunDispatcher(tun, mgr, c.Server.MTU, fatal)
	qc := &quic.Config{EnableDatagrams: true, HandshakeIdleTimeout: 10 * time.Second, MaxIdleTimeout: 2 * time.Minute, KeepAlivePeriod: 15 * time.Second}
	s := &http3.Server{TLSConfig: tc, QUICConfig: qc, EnableDatagrams: true, Handler: mh.HandlerFunc(func(w mh.ResponseWriter, r *mh.Request) { handleRequest(w, r, c, byKey, mgr, tun) })}
	serveErr := make(chan error, 1)
	go func() { serveErr <- s.Serve(ln) }()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)
	var runErr error
	select {
	case <-sig:
	case runErr = <-serveErr:
		if runErr == net.ErrClosed {
			runErr = nil
		}
	case runErr = <-fatal:
		log.Printf("infrastructure fatal: %v", runErr)
	}
	for _, cl := range mgr.Snapshot() {
		cl.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err = s.Shutdown(ctx); err != nil {
		_ = s.Close()
	}
	return runErr
}

func handleRequest(w mh.ResponseWriter, r *mh.Request, c config.Config, byKey map[string]config.ResolvedClient, mgr *session.Manager, tun *tunnel.Device) {
	parseProtocol, ok := protocolForParse(r.Proto)
	if !ok {
		log.Printf("CONNECT-IP rejected: unsupported protocol %q", r.Proto)
		mh.Error(w, "only CONNECT-IP is supported", mh.StatusNotImplemented)
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 {
		log.Printf("CONNECT-IP rejected: missing client certificate")
		mh.Error(w, "client certificate required", mh.StatusUnauthorized)
		return
	}
	client, ok := byKey[auth.PublicKeyBytes(r.TLS.PeerCertificates[0])]
	if !ok {
		log.Printf("CONNECT-IP rejected: unauthorized client")
		mh.Error(w, "client certificate not authorized", mh.StatusUnauthorized)
		return
	}
	copyReq := *r
	copyReq.Proto = parseProtocol
	req, err := connectip.ParseRequest(&copyReq, uritemplate.MustNew("https://"+r.Host+"/connect-ip"))
	if err != nil {
		log.Printf("CONNECT-IP request parse failed: %v", err)
		mh.Error(w, err.Error(), mh.StatusBadRequest)
		return
	}
	conn, err := (&connectip.Proxy{}).Proxy(w, req)
	if err != nil {
		log.Printf("CONNECT-IP tunnel establishment failed: %v", err)
		return
	}
	if err = conn.AssignAddresses(r.Context(), []netip.Prefix{client.TunnelIPv4}); err != nil {
		log.Printf("AssignAddresses failed: %v", err)
		conn.Close()
		return
	}
	if err = conn.AdvertiseRoute(r.Context(), []connectip.IPRoute{{StartIP: netip.MustParseAddr("0.0.0.0"), EndIP: netip.MustParseAddr("255.255.255.255")}}); err != nil {
		log.Printf("AdvertiseRoute failed: %v", err)
		conn.Close()
		return
	}
	s := session.NewWithContext(r.Context(), client.TunnelIPv4.Addr(), client.Name, conn, func(x *session.Session) { mgr.RemoveIfCurrent(x) })
	go sessionWriter(s, tun, c.Server.MTU)
	old := mgr.Replace(s)
	if old != nil {
		log.Printf("client %s session takeover", client.Name)
	}
	log.Printf("client %s session established", client.Name)
	go sessionReader(s, tun, c.Server.MTU)
	select {
	case <-r.Context().Done():
	case <-s.Ctx.Done():
	}
	s.Close()
	log.Printf("client %s session closed", client.Name)
}

func tunDispatcher(tun *tunnel.Device, mgr *session.Manager, mtu int, fatal chan<- error) {
	buf := make([]byte, 65535)
	for {
		n, err := tun.Read(buf)
		if err != nil {
			fatal <- fmt.Errorf("TUN dispatcher: %w", err)
			return
		}
		if n > mtu {
			continue
		}
		dst, ok := ipv4Destination(buf[:n])
		if !ok {
			continue
		}
		s := mgr.Lookup(dst)
		if s == nil {
			continue
		}
		pkt := append([]byte(nil), buf[:n]...)
		select {
		case s.Outbound <- pkt:
		default:
		}
	}
}
func sessionWriter(s *session.Session, tun *tunnel.Device, mtu int) {
	for {
		select {
		case <-s.Ctx.Done():
			return
		case pkt := <-s.Outbound:
			if len(pkt) > mtu {
				continue
			}
			icmp, err := s.Conn.WritePacket(pkt)
			if len(icmp) > 0 {
				if _, werr := tun.Write(icmp); werr != nil {
					log.Printf("client %s ICMP write failed: %v", s.Identity, werr)
					s.Close()
					return
				}
			}
			if err != nil {
				log.Printf("client %s packet write failed: %v", s.Identity, err)
				s.Close()
				return
			}
		}
	}
}
func sessionReader(s *session.Session, tun *tunnel.Device, mtu int) {
	for {
		pkt, err := s.Conn.ReadPacket()
		if err != nil {
			log.Printf("client %s session read failed: %v", s.Identity, err)
			s.Close()
			return
		}
		if len(pkt) > mtu {
			continue
		}
		src, ok := ipv4Source(pkt)
		if !ok || src != s.ClientIP {
			continue
		}
		select {
		case <-s.Ctx.Done():
			return
		default:
		}
		if _, err = tun.Write(pkt); err != nil {
			log.Printf("client %s TUN write failed: %v", s.Identity, err)
			s.Close()
			return
		}
	}
}
func ipv4Destination(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 || int(pkt[0]&15)*4 < 20 || int(pkt[0]&15)*4 > len(pkt) {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]}), true
}
func ipv4Source(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 || int(pkt[0]&15)*4 < 20 || int(pkt[0]&15)*4 > len(pkt) {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte{pkt[12], pkt[13], pkt[14], pkt[15]}), true
}
func protocolForParse(protocol string) (string, bool) {
	switch protocol {
	case "connect-ip", "cf-connect-ip":
		return "connect-ip", true
	default:
		return "", false
	}
}
