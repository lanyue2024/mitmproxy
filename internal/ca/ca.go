package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type CAManager struct {
	CACert        *x509.Certificate
	CAPrivKey     *rsa.PrivateKey
	UpstreamRoots *x509.CertPool
}

// LoadOrGenerateMITMCA loads the MITM CA from configDir or generates it if missing.
func LoadOrGenerateMITMCA(configDir string) (*CAManager, error) {
	caCertPath := filepath.Join(configDir, "mitm_ca.pem")
	caKeyPath := filepath.Join(configDir, "mitm_ca_key.pem")

	mgr := &CAManager{}

	// Try loading existing CA
	certPEM, errCert := os.ReadFile(caCertPath)
	keyPEM, errKey := os.ReadFile(caKeyPath)

	if errCert == nil && errKey == nil {
		// Parse Certificate
		block, _ := pem.Decode(certPEM)
		if block == nil {
			return nil, errors.New("failed to parse CA certificate PEM")
		}
		mgr.CACert, errCert = x509.ParseCertificate(block.Bytes)
		if errCert != nil {
			return nil, errCert
		}

		// Parse Private Key
		block, _ = pem.Decode(keyPEM)
		if block == nil {
			return nil, errors.New("failed to parse CA private key PEM")
		}
		mgr.CAPrivKey, errKey = x509.ParsePKCS1PrivateKey(block.Bytes)
		if errKey != nil {
			// Try PKCS8
			k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			mgr.CAPrivKey = k.(*rsa.PrivateKey)
		}
	} else {
		// Generate new CA
		fmt.Println("Generating new MITM CA...")
		if err := mgr.generateCA(caCertPath, caKeyPath); err != nil {
			return nil, fmt.Errorf("failed to generate CA: %w", err)
		}
	}

	return mgr, nil
}

func (m *CAManager) generateCA(certPath, keyPath string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Go MITM Proxy CA",
			Organization: []string{"Go MITM Proxy"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * 10 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	// Save Certificate
	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	// Save Key
	keyOut, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	m.CACert = &template
	m.CAPrivKey = priv
	return nil
}

// LoadUpstreamCA loads the user-provided cacert.pem for verifying upstream servers.
func (m *CAManager) LoadUpstreamCA(path string) error {
	pemData, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
            // It's optional? Plan said user provides it. 
            // If missing, we should probably fail or warn if verifying upstream is required.
            // Requirement said: "c2... verify target tls cert using config/cacert.pem"
            // So it implies we MUST use it. Be strict.
			return fmt.Errorf("upstream CA file not found at %s: %w", path, err)
		}
		return err
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return errors.New("failed to append existing CA certificates")
	}
	m.UpstreamRoots = pool
	return nil
}

// SignCert generates a leaf certificate for the given SNI, signed by the MITM CA.
func (m *CAManager) SignCert(sni string) (*tls.Certificate, error) {
	// Generate ephemeral private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

    // Determine correctness for serial number (random is good practice)
    serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
    serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: sni,
			Organization: []string{"Go MITM Proxy Interception"},
		},
		DNSNames:    []string{sni},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour), // Short lived
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, m.CACert, &priv.PublicKey, m.CAPrivKey)
	if err != nil {
		return nil, err
	}

    // Reuse the parsing logic provided by tls.X509KeyPair structure logic
    // But we have raw bytes.
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tlsCert, nil
}
