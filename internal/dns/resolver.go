package dns

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupECH(ctx context.Context, host string) ([]byte, error)
}

type StandardResolver struct {
	Server string // host:port
}

func NewStandardResolver(server string) *StandardResolver {
	return &StandardResolver{Server: server}
}

func (r *StandardResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.RecursionDesired = true

	in, _, err := c.ExchangeContext(ctx, m, r.Server)
	if err != nil {
		return nil, err
	}

	var parsed []string
	for _, ans := range in.Answer {
		if a, ok := ans.(*dns.A); ok {
			parsed = append(parsed, a.A.String())
		}
	}
	return parsed, nil
}

func (r *StandardResolver) LookupECH(ctx context.Context, host string) ([]byte, error) {
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeHTTPS)
	m.RecursionDesired = true

	in, _, err := c.ExchangeContext(ctx, m, r.Server)
	if err != nil {
		return nil, err
	}

	for _, ans := range in.Answer {
		if h, ok := ans.(*dns.HTTPS); ok {
			for _, val := range h.Value {
				if val.Key() == 5 { // 5 = SVCB_ECH
					if ech, ok := val.(*dns.SVCBECHConfig); ok {
						return ech.ECH, nil
					}
				}
			}
		}
	}
	return nil, fmt.Errorf("no ECH config found for %s (or type mismatch)", host)
}

type DoHResolver struct {
	Endpoint string
	Client   *http.Client
}

func NewDoHResolver(endpoint string) *DoHResolver {
	return &DoHResolver{
		Endpoint: endpoint,
		Client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: false}, // DoH should be secure
			},
			Timeout: 5 * time.Second,
		},
	}
}

func (r *DoHResolver) doQuery(ctx context.Context, host string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), qtype)
	m.RecursionDesired = true

	data, err := m.Pack()
	if err != nil {
		return nil, err
	}

	b64 := base64.RawURLEncoding.EncodeToString(data)
	url := fmt.Sprintf("%s?dns=%s", r.Endpoint, b64)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")

	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var in dns.Msg
	if err := in.Unpack(body); err != nil {
		return nil, err
	}
	return &in, nil
}

func (r *DoHResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	in, err := r.doQuery(ctx, host, dns.TypeA)
	if err != nil {
		return nil, err
	}
	var parsed []string
	for _, ans := range in.Answer {
		if a, ok := ans.(*dns.A); ok {
			parsed = append(parsed, a.A.String())
		}
	}
	return parsed, nil
}

func (r *DoHResolver) LookupECH(ctx context.Context, host string) ([]byte, error) {
	in, err := r.doQuery(ctx, host, dns.TypeHTTPS)
	if err != nil {
		return nil, err
	}

	for _, ans := range in.Answer {
		if h, ok := ans.(*dns.HTTPS); ok {
			for _, val := range h.Value {
				if val.Key() == 5 { // 5 = SVCB_ECH
					if ech, ok := val.(*dns.SVCBECHConfig); ok {
						return ech.ECH, nil
					}
				}
			}
		}
	}
	return nil, fmt.Errorf("no ECH config found")
}

func NewResolver(addr string) Resolver {
	// If explicit https scheme, treat as DoH
	if strings.HasPrefix(addr, "https://") {
		return NewDoHResolver(addr)
	}
	// If standard 8.8.8.8:443 format but without scheme, might be DoT or weird DNS port.
	// Spec says "support ordinary dns and dns over https".
	// "Default 8.8.8.8:53".
	// I'll assume anything starting with https:// is DoH, everything else is standard UDP DNS.
	return NewStandardResolver(addr)
}
