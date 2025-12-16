package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"mitmproxy/internal/ca"
	"mitmproxy/internal/config"
	"mitmproxy/internal/dns"
)

// ============================================================================
// Server Definition
// ============================================================================

type Server struct {
	Config   *config.Config
	CA       *ca.CAManager
	Matcher  *RuleMatcher
	Resolver dns.Resolver
	EchCache sync.Map
}

func NewServer(cfg *config.Config, caMgr *ca.CAManager, resolver dns.Resolver) *Server {
	return &Server{
		Config:   cfg,
		CA:       caMgr,
		Matcher:  NewRuleMatcher(cfg),
		Resolver: resolver,
	}
}

// ============================================================================
// HTTP Handlers
// ============================================================================

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}

	log.Printf("[HTTP] Request %s %s", r.Method, r.URL.String())

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
	log.Printf("[CONNECT] Received request for %s", host)

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
	// c2: If SNI, EchHost, or EchConfigList is present, MITM.
	if mapping.SNI != "" || mapping.EchHost != "" || mapping.EchConfigList != "" {
		// Pass host (original request host) as originalHost
		hostOnly, _, _ := net.SplitHostPort(host)
		if hostOnly == "" {
			hostOnly = host
		} // Handle cases without port if any, though CONNECT usually has port
		s.performMITM(clientConn, targetHost, hostOnly, mapping)
	} else {
		// Just tunnel to potentially new address
		s.tunnelConnection(clientConn, targetHost)
	}
}

// ============================================================================
// MITM Logic
// ============================================================================

func (s *Server) performMITM(clientConn net.Conn, targetAddr, originalHost string, mapping *config.Mapping) {
	// Upstream Connection Setup
	// upstreamSNI is the "Inner SNI" (The real target we want to reach).
	upstreamSNI := mapping.SNI
	if upstreamSNI == "" {
		upstreamSNI = originalHost
	}

	if strings.HasPrefix(upstreamSNI, "_") {
		upstreamSNI = ""
	}

	// ECH Handling
	var echConfig []byte
	var echHostUsed string

	// Explicit Config flag
	isExplicitConfig := mapping.SNI == "" && mapping.EchConfigList != "" && mapping.EchHost != ""

	// If explicit SNI is provided, do NOT use ECH (as per user request).
	echConfig, echHostUsed = s.resolveInitialECH(context.Background(), mapping)

	// Determine verification name (Inner SNI for validation)
	rawSNI := mapping.SNI
	if rawSNI == "" {
		rawSNI = originalHost
	}
	verifyingName := strings.TrimPrefix(rawSNI, "_")

	if len(echConfig) > 0 {
		log.Printf("[MITM] Intercepting %s (User Host: %s)", targetAddr, originalHost)
	} else {
		log.Printf("[MITM] Intercepting %s (User Host: %s). Upstream SNI: %s. Verifying: %s", targetAddr, originalHost, upstreamSNI, verifyingName)
	}

	// 1. Connect to Upstream FIRST to negotiate ALPN
	var upstreamTLSConn *tls.Conn

	// Retry loop for Explicit Config -> EchHost fallback -> EchHost Refresh
	maxAttempts := 1
	if isExplicitConfig {
		maxAttempts = 2
	}

	// Track which host provided the current ECH config (for refreshing)
	wasRefreshed := false

	for attempt := 0; attempt < maxAttempts; attempt++ {
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		realTargetAddr := targetAddr
		host, port, _ := net.SplitHostPort(targetAddr)
		ips, err := s.Resolver.LookupHost(context.Background(), host)
		if err == nil && len(ips) > 0 {
			realTargetAddr = net.JoinHostPort(ips[0], port)
		}

		rawUpstreamConn, err := dialer.Dial("tcp", realTargetAddr)
		if err != nil {
			log.Printf("Failed to dial upstream %s: %v", targetAddr, err)
			clientConn.Close()
			return
		}

		upstreamTLSConfig := &tls.Config{
			ServerName: upstreamSNI,
			RootCAs:    s.CA.UpstreamRoots,
			NextProtos: []string{"h2", "http/1.1"},
		}

		// Re-evaluate ECH config if we are retrying or if explicit config was disabled
		// Note: echConfig might have been set by fallback logic in previous iteration
		if len(echConfig) > 0 {
			logECHConnection(attempt, originalHost, upstreamSNI, mapping, echConfig, echHostUsed)
			upstreamTLSConfig.EncryptedClientHelloConfigList = echConfig
			upstreamTLSConfig.MinVersion = tls.VersionTLS13
		}

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

		upstreamTLSConn = tls.Client(rawUpstreamConn, upstreamTLSConfig)
		if err := upstreamTLSConn.Handshake(); err != nil {
			log.Printf("Upstream TLS Handshake failed: %v", err)
			upstreamTLSConn.Close() // Close the failed connection

			// Retry Logic
			// 1. Explicit Config Failed -> Fallback to EchHost (Cached)
			if !mapping.EchConfigListDisabled && isExplicitConfig {
				log.Printf("Handshake failed with explicit config. Disabling it and querying EchHost (%s)...", mapping.EchHost)
				mapping.EchConfigListDisabled = true // Disable for future

				// Lookup EchHost (Allow Cache)
				newConfig, errLookup := s.getOrLookupECH(context.Background(), mapping.EchHost)
				if errLookup == nil && len(newConfig) > 0 {
					echConfig = newConfig
					echHostUsed = mapping.EchHost
					maxAttempts = 3 // Allow room for one more retry (Refresh) if this fallback fails
					continue
				}
				log.Printf("LookupECH failed or empty for %s: %v", mapping.EchHost, errLookup)
			} else if echHostUsed != "" && !wasRefreshed {
				// 2. Dynamic/Cached Config Failed -> Refresh (Bypass Cache)
				log.Printf("Handshake failed with cached/dynamic config for %s. Refreshing...", echHostUsed)

				newConfig, errLookup := s.Resolver.LookupECH(context.Background(), echHostUsed)
				if errLookup == nil && len(newConfig) > 0 {
					log.Printf("Refreshed ECH config for %s", echHostUsed)
					s.EchCache.Store(echHostUsed, newConfig) // Update Cache
					echConfig = newConfig
					wasRefreshed = true

					// Ensure we have an attempt slot left
					if attempt+1 >= maxAttempts {
						maxAttempts++
					}
					continue
				}
				log.Printf("Refresh LookupECH failed for %s: %v", echHostUsed, errLookup)
			}

			// Final failure (or retry failed)
			clientConn.Close()
			return
		}

		// Success
		break
	}
	// Defer close for the successful connection
	defer upstreamTLSConn.Close()

	// 2. Configure Client TLS based on Upstream ALPN
	negotiatedProtocol := upstreamTLSConn.ConnectionState().NegotiatedProtocol
	clientNextProtos := []string{"http/1.1"} // Default safe fallback
	if negotiatedProtocol != "" {
		clientNextProtos = []string{negotiatedProtocol}
	}

	tlsConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return s.CA.SignCert(hello.ServerName)
		},
		NextProtos: clientNextProtos,
	}

	tlsClientConn := tls.Server(clientConn, tlsConfig)
	if err := tlsClientConn.Handshake(); err != nil {
		log.Printf("MITM Client Handshake error: %v", err)
		clientConn.Close()
		// Upstream will be closed by defer
		return
	}
	defer tlsClientConn.Close()

	// 3. Bidirectional Stream Copy
	go func() {
		_, _ = io.Copy(upstreamTLSConn, tlsClientConn)
		upstreamTLSConn.Close()
	}()

	_, _ = io.Copy(tlsClientConn, upstreamTLSConn)
	// When upstream closes, close client
}

// ============================================================================
// Tunneling
// ============================================================================

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

// ============================================================================
// ECH Helpers
// ============================================================================

// getECHPublicName extracts the public_name from an ECHConfigList.
// Returns empty string if parsing fails or no valid config found.
func getECHPublicName(configList []byte) string {
	if len(configList) < 4 {
		return ""
	}

	// Check for Length Prefix (ECHConfigList is a vector)
	// If first 2 bytes magnitude matches remaining length, skip them.
	p := 0
	totalLen := int(configList[0])<<8 | int(configList[1])
	if totalLen == len(configList)-2 {
		p += 2
	}

	for p+4 <= len(configList) {
		version := int(configList[p])<<8 | int(configList[p+1])
		length := int(configList[p+2])<<8 | int(configList[p+3])
		p += 4

		if p+length > len(configList) {
			break
		}

		content := configList[p : p+length]
		p += length // Move to next config for next iteration

		if version != 0xfe0d {
			// Unknown version, skip
			continue
		}

		if len(content) < 5 {
			continue
		}
		// 1(ID) + 2(KEM) = 3. PkLen at 3,4.
		pkLen := int(content[3])<<8 | int(content[4])
		off := 5 + pkLen

		if len(content) < off+2 {
			continue
		}
		csLen := int(content[off])<<8 | int(content[off+1])
		off += 2 + csLen

		if len(content) < off+2 {
			continue
		}
		// MaxNameLen at off, NameLen at off+1
		nameLen := int(content[off+1])
		off += 2

		if len(content) < off+nameLen {
			continue
		}
		return string(content[off : off+nameLen])
	}
	return ""
}

// getOrLookupECH checks the cache first, otherwise performs DNS lookup.
func (s *Server) getOrLookupECH(ctx context.Context, host string) ([]byte, error) {
	if val, ok := s.EchCache.Load(host); ok {
		log.Printf("[ECH] Cache hit for %s", host)
		return val.([]byte), nil
	}

	config, err := s.Resolver.LookupECH(ctx, host)
	if err == nil && len(config) > 0 {
		s.EchCache.Store(host, config)
	}
	return config, err
}

// resolveInitialECH determines the ECH config before the connection loop.
// Returns (echConfig, echHostUsed). If SNI is set, ECH is disabled.
func (s *Server) resolveInitialECH(ctx context.Context, mapping *config.Mapping) ([]byte, string) {
	if mapping.SNI != "" {
		return nil, ""
	}

	candidates := []string{}
	if mapping.EchHost != "" {
		candidates = append(candidates, mapping.EchHost)
	}

	if mapping.EchConfigList != "" && !mapping.EchConfigListDisabled {
		cfg, err := base64.StdEncoding.DecodeString(mapping.EchConfigList)
		if err != nil {
			log.Printf("Invalid ECH ConfigList base64: %v", err)
			return nil, ""
		}
		return cfg, ""
	}

	// If no explicit config OR it is disabled, try candidate lookup
	for _, cand := range candidates {
		if cand == "" {
			continue
		}
		cfg, err := s.getOrLookupECH(ctx, cand)
		if err == nil && len(cfg) > 0 {
			log.Printf("Found ECH Config for %s", cand)
			return cfg, cand
		}
	}
	return nil, ""
}

// logECHConnection logs the ECH connection details for debugging.
func logECHConnection(attempt int, originalHost, upstreamSNI string, mapping *config.Mapping, echConfig []byte, echHostUsed string) {
	outerSNI := mapping.EchHost
	if echHostUsed != "" {
		outerSNI = echHostUsed
	}

	if mapping.EchConfigList != "" && !mapping.EchConfigListDisabled && attempt == 0 {
		extracted := getECHPublicName(echConfig)
		if extracted != "" {
			outerSNI = extracted
		} else if outerSNI == "" {
			outerSNI = "(Implicit/From Config)"
		}
	} else if outerSNI == "" {
		outerSNI = "(Implicit/From Config)"
	}

	prefix := "[ECH] Enabled"
	if attempt > 0 {
		prefix = "[ECH] Retry attempt"
	}
	log.Printf("%s. User Host: %s. Inner SNI: %s. Outer SNI: %s. (Config len: %d)", prefix, originalHost, upstreamSNI, outerSNI, len(echConfig))
}
