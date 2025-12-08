package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"path/filepath"

	"mitmproxy/internal/ca"
	"mitmproxy/internal/config"
	"mitmproxy/internal/dns"
	"mitmproxy/internal/proxy"
)

func main() {
	configPath := flag.String("config", "rules.json", "Path to the configuration JSON file")
	dnsAddr := flag.String("dns", "8.8.8.8:53", "DNS server address (ip:port for standard, https://... for DoH)")
	port := flag.Int("port", 8080, "Port to listen on")
	configDir := flag.String("config-dir", "config", "Directory to store/read CA certificates")
	flag.Parse()

	// 1. Load Rules Config
	// It's possible the file doesn't exist yet, but prompt implies required?
	// "由命令行参数指定从一个 JSON 文件读取 host 列表".
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config from %s: %v", *configPath, err)
	}
	log.Printf("Loaded config from %s", *configPath)

	// 2. Setup CA
	caMgr, err := ca.LoadOrGenerateMITMCA(*configDir)
	if err != nil {
		log.Fatalf("Failed to load/generate MITM CA: %v", err)
	}
	log.Printf("MITM CA loaded/generated in %s", *configDir)

	// Load Upstream Verification CA
	// User said: "config 目录下的 cacert.pem 由用户提供" in the directory.
	// We'll look for it in *configDir/cacert.pem
	upstreamCAPath := filepath.Join(*configDir, "cacert.pem")
	if err := caMgr.LoadUpstreamCA(upstreamCAPath); err != nil {
		// Does fail if missing?
		// Plan said yes, strict. logic implies "verify target... using cacert.pem".
		log.Fatalf("Failed to load upstream verification CA from %s: %v", upstreamCAPath, err)
	}
	log.Printf("Loaded Upstream CA from %s", upstreamCAPath)

	// 3. Setup DNS
	resolver := dns.NewResolver(*dnsAddr)
	log.Printf("Using DNS resolver: %s", *dnsAddr)

	// 4. Setup Proxy Server
	srv := proxy.NewServer(cfg, caMgr, resolver)

	// 5. Start Listener
	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Starting MITM Proxy on %s", addr)
	if err := http.ListenAndServe(addr, srv); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
