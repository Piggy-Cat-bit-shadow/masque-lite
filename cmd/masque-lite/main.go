package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/Piggy-Cat-bit-shadow/masque-lite/internal/auth"
	"github.com/Piggy-Cat-bit-shadow/masque-lite/internal/config"
	"github.com/Piggy-Cat-bit-shadow/masque-lite/internal/tunnel"
	connectip "github.com/metacubex/connect-ip-go"
	mh "github.com/metacubex/http"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
	"github.com/yosida95/uritemplate/v3"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "keygen" {
		keygen()
		return
	}
	path := flag.String("config", "/etc/masque-lite/config.yaml", "configuration file")
	flag.Parse()
	c, e := config.Load(*path)
	if e != nil {
		log.Fatal(e)
	}
	cert, e := tls.LoadX509KeyPair(c.TLS.Cert, c.TLS.Key)
	if e != nil {
		log.Fatal(e)
	}
	if len(c.Client.PublicKeys) == 0 && c.Client.PublicKey != "" {
		c.Client.PublicKeys = []string{c.Client.PublicKey}
	}
	tc := &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}}
	var sessionMu sync.Mutex
	active := false
	tc.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) != 1 {
			return fmt.Errorf("exactly one client certificate required")
		}
		if !auth.Matches(cs.PeerCertificates[0], c.Client.PublicKeys) {
			return fmt.Errorf("client certificate public key is not authorized")
		}
		return nil
	}
	tun, e := tunnel.Open("masque0", c.Server.MTU)
	if e != nil {
		log.Fatal(e)
	}
	defer tun.Close()
	ln, e := net.ListenPacket("udp", c.Listen)
	if e != nil {
		log.Fatal(e)
	}
	s := &http3.Server{TLSConfig: tc, EnableDatagrams: true, Handler: mh.HandlerFunc(func(w mh.ResponseWriter, r *mh.Request) {
		sessionMu.Lock()
		if active {
			sessionMu.Unlock()
			mh.Error(w, "only one client session is supported", mh.StatusServiceUnavailable)
			return
		}
		active = true
		sessionMu.Unlock()
		defer func() { sessionMu.Lock(); active = false; sessionMu.Unlock() }()
		parseProtocol, ok := protocolForParse(r.Proto)
		if !ok {
			mh.Error(w, "only CONNECT-IP is supported", mh.StatusNotImplemented)
			return
		}
		requestForParse := *r
		requestForParse.Proto = parseProtocol
		req, e := connectip.ParseRequest(&requestForParse, uritemplate.MustNew("https://"+r.Host+"/connect-ip"))
		if e != nil {
			mh.Error(w, e.Error(), mh.StatusBadRequest)
			return
		}
		conn, e := (&connectip.Proxy{}).Proxy(w, req)
		if e != nil {
			return
		}
		clientPrefix, _ := netip.ParsePrefix(c.Client.TunnelIPv4)
		if e = conn.AssignAddresses(r.Context(), []netip.Prefix{clientPrefix}); e != nil {
			conn.Close()
			return
		}
		if e = conn.AdvertiseRoute(r.Context(), []connectip.IPRoute{{StartIP: netip.MustParseAddr("0.0.0.0"), EndIP: netip.MustParseAddr("255.255.255.255")}}); e != nil {
			conn.Close()
			return
		}
		go func() {
			buf := make([]byte, 65535)
			for {
				n, er := tun.Read(buf)
				if er != nil {
					return
				}
				if n > c.Server.MTU {
					continue
				}
				if _, er = conn.WritePacket(buf[:n]); er != nil {
					return
				}
			}
		}()
		go func() {
			for {
				pkt, er := conn.ReadPacket()
				if er != nil {
					return
				}
				if len(pkt) > c.Server.MTU {
					continue
				}
				if _, er = tun.Write(pkt); er != nil {
					return
				}
			}
		}()
		go func() { <-r.Context().Done(); conn.Close() }()
		<-r.Context().Done()
	})}
	go func() {
		if e := s.Serve(ln); e != nil && e != net.ErrClosed {
			log.Print(e)
		}
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	_ = s.Shutdown(context.Background())
}

func protocolForParse(protocol string) (string, bool) {
	switch protocol {
	case "connect-ip", "cf-connect-ip":
		return "connect-ip", true
	default:
		return "", false
	}
}
