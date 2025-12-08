package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"mitmproxy/internal/ca"
	"mitmproxy/internal/config"
	"mitmproxy/internal/dns"
)

type Server struct {
	Config   *config.Config
	CA       *ca.CAManager
	Matcher  *RuleMatcher
	Resolver dns.Resolver
}

func NewServer(cfg *config.Config, caMgr *ca.CAManager, resolver dns.Resolver) *Server {
	return &Server{
		Config:   cfg,
		CA:       caMgr,
		Matcher:  NewRuleMatcher(cfg),
		Resolver: resolver,
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}

	// Normal HTTP Request
	mapping := s.Matcher.Match(r.Host)
	if mapping != nil {
		// Matched: 301 Redirect to HTTPS
		target := "https://" + r.Host + r.URL.Path
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, target, http.StatusMovedPermanently)
		return
	}

	// Not matched: Standard Proxy behavior (Forwarding)
	s.handleStandardHTTP(w, r)
}

func (s *Server) handleStandardHTTP(w http.ResponseWriter, r *http.Request) {
	// Simple forward proxy
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http" // Default for proxy requests usually
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}

	// Create new request
	proxyReq, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	// Copy headers
	for k, vv := range r.Header {
		for _, v := range vv {
			proxyReq.Header.Add(k, v)
		}
	}

	// Use custom transport to ensure no modification (compression) and use our DNS
	transport := &http.Transport{
		DisableCompression: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, _ := net.SplitHostPort(addr)
			ips, err := s.Resolver.LookupHost(ctx, host)
			// Fallback to original addr if resolution fails or no IPs
			if err == nil && len(ips) > 0 {
				addr = net.JoinHostPort(ips[0], port)
			}
			dialer := &net.Dialer{Timeout: 30 * time.Second}
			return dialer.DialContext(ctx, network, addr)
		},
		ResponseHeaderTimeout: 30 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.Host // host:port

	// Hijack the connection to handle the tunnel manually
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// Send 200 Connection Established
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Check for match
	mapping := s.Matcher.Match(host)

	if mapping == nil {
		// No match: Pass-through (Tunnel)
		s.tunnelConnection(clientConn, host)
		return
	}

	// Match Found
	// Resolve Target Address
	targetHost := host
	if mapping.Address != "" {
		targetHost = mapping.Address
	} else {
		// Use custom DNS to resolve original host
		hostOnly, port, _ := net.SplitHostPort(host)
		ips, err := s.Resolver.LookupHost(context.Background(), hostOnly)
		if err == nil && len(ips) > 0 {
			targetHost = net.JoinHostPort(ips[0], port)
		}
	}

	// c1: If Address is set, we used it above.
	// c2: If SNI is present, MITM.
	if mapping.SNI != "" {
		s.performMITM(clientConn, targetHost, mapping)
	} else {
		// Just tunnel to potentially new address
		s.tunnelConnection(clientConn, targetHost)
	}
}

func (s *Server) performMITM(clientConn net.Conn, targetAddr string, mapping *config.Mapping) {
	tlsConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return s.CA.SignCert(hello.ServerName)
		},
	}

	tlsClientConn := tls.Server(clientConn, tlsConfig)
	if err := tlsClientConn.Handshake(); err != nil {
		log.Printf("MITM Client Handshake error: %v", err)
		clientConn.Close()
		return
	}
	defer tlsClientConn.Close()

	// Upstream Connection Setup
	upstreamSNI := mapping.SNI
	if strings.HasPrefix(upstreamSNI, "_") {
		upstreamSNI = ""
	}

	verifyingName := strings.TrimPrefix(mapping.SNI, "_")
	
	// Create custom dialer to use our Resolver
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	
	// Resolve target first using our resolver
	realTargetAddr := targetAddr
	host, port, _ := net.SplitHostPort(targetAddr)
	ips, err := s.Resolver.LookupHost(context.Background(), host)
	if err == nil && len(ips) > 0 {
		realTargetAddr = net.JoinHostPort(ips[0], port)
	}

	rawUpstreamConn, err := dialer.Dial("tcp", realTargetAddr)
	if err != nil {
		log.Printf("Failed to dial upstream %s: %v", targetAddr, err)
		return
	}
	defer rawUpstreamConn.Close()

	upstreamTLSConfig := &tls.Config{
		ServerName: upstreamSNI,
		RootCAs:    s.CA.UpstreamRoots,
	}

	// Manual verification if SNI is empty or special handling needed
	// Standard VerifyConnection with RootCAs set usually works if ServerName matches.
	// We want to verify against `verifyingName`.
	if upstreamSNI == "" && verifyingName != "" {
		upstreamTLSConfig.InsecureSkipVerify = true
		upstreamTLSConfig.VerifyConnection = func(cs tls.ConnectionState) error {
			intermediates := x509.NewCertPool()
			for _, cert := range cs.PeerCertificates[1:] {
				intermediates.AddCert(cert)
			}
			opts := x509.VerifyOptions{
				DNSName:       verifyingName,
				Roots:         s.CA.UpstreamRoots,
				Intermediates: intermediates,
			}
			_, err := cs.PeerCertificates[0].Verify(opts)
			return err
		}
	}

	upstreamTLSConn := tls.Client(rawUpstreamConn, upstreamTLSConfig)
	if err := upstreamTLSConn.Handshake(); err != nil {
		log.Printf("Upstream TLS Handshake failed: %v", err)
		return
	}
	defer upstreamTLSConn.Close()

	// HTTP Request Loop
	clientReader := bufio.NewReader(tlsClientConn)
	upstreamReader := bufio.NewReader(upstreamTLSConn)

	for {
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading request from client: %v", err)
			}
			break
		}

		// Mod Host Header
		if mapping.HostHeader != "" {
			req.Host = mapping.HostHeader
			// req.Header.Set("Host", ...) is handled by Write usually but forcing it is safe
			req.Header.Set("Host", mapping.HostHeader)
		}

		if err := req.Write(upstreamTLSConn); err != nil {
			log.Printf("Error writing request to upstream: %v", err)
			break
		}

		resp, err := http.ReadResponse(upstreamReader, req)
		if err != nil {
			log.Printf("Error reading response from upstream: %v", err)
			break
		}

		if err := resp.Write(tlsClientConn); err != nil {
			log.Printf("Error writing response to client: %v", err)
			break
		}
		
		// Handle Connection: close
		if resp.Close || req.Close {
			break
		}
	}
}

func (s *Server) tunnelConnection(client net.Conn, target string) {
	// Simple TCP tunnel
	host, port, _ := net.SplitHostPort(target)
    // Use custom resolver logic
	ips, err := s.Resolver.LookupHost(context.Background(), host)
    realTarget := target
	if err == nil && len(ips) > 0 {
		realTarget = net.JoinHostPort(ips[0], port)
	}

    targetConn, err := net.DialTimeout("tcp", realTarget, 10*time.Second)
	if err != nil {
		client.Close()
		return
	}

	go func() {
		io.Copy(targetConn, client)
		targetConn.Close()
	}()
	io.Copy(client, targetConn)
	client.Close()
}
