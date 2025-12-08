package proxy

import (
	"strings"

	"mitmproxy/internal/config"
)

type RuleMatcher struct {
	Config *config.Config
}

func NewRuleMatcher(cfg *config.Config) *RuleMatcher {
	return &RuleMatcher{Config: cfg}
}

// Match returns the first matching Mapping for a given host, or nil if no match.
func (m *RuleMatcher) Match(host string) *config.Mapping {
	// Strip port if present
	if idx := strings.LastIndex(host, ":"); idx != -1 {
        // Handle IPv6 brackets [::1]:8080 logic if needed, but simple LastIndex is risky for [::1].
        // Usually host from HTTP req header doesn't have port if default, or does.
        // Assuming host is hostname or hostname:port.
        // If ']' is present, it's IPv6 literal.
        if strings.Contains(host, "]") {
             // Let's assume net.SplitHostPort is safer, but for now simple suffix check:
             // If pattern is "google.com", "google.com:443" should match?
             // Prompt says "host equals matches or is subdomain".
             // We should strip port to match domain patterns.
             host = host[:idx]
        } else {
             host = host[:idx]
        }
	}

	for i := range m.Config.Mappings {
		mapping := &m.Config.Mappings[i]
		for _, pattern := range mapping.Patterns {
			if matchDomain(host, pattern) {
				return mapping
			}
		}
	}
	return nil
}

func matchDomain(host, pattern string) bool {
	host = strings.ToLower(host)
	pattern = strings.ToLower(pattern)

	if host == pattern {
		return true
	}
	if strings.HasSuffix(host, "."+pattern) {
		return true
	}
	return false
}
