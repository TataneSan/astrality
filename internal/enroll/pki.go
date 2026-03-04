package enroll

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type CA struct {
	Cert       *x509.Certificate
	Key        *rsa.PrivateKey
	CertPEM    []byte
	KeyPEM     []byte
	CertPath   string
	KeyPath    string
	ServerCert string
	ServerKey  string
}

func EnsureCA(dataDir string) (*CA, error) {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, err
	}
	certPath := filepath.Join(dataDir, "ca.pem")
	keyPath := filepath.Join(dataDir, "ca-key.pem")

	if _, err := os.Stat(certPath); err == nil {
		return loadCA(certPath, keyPath)
	}

	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "astrality-ca",
			Organization: []string{"astrality"},
		},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	if err := os.WriteFile(certPath, certPEM, 0o640); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	return loadCA(certPath, keyPath)
}

func loadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	cblock, _ := pem.Decode(certPEM)
	if cblock == nil {
		return nil, fmt.Errorf("invalid ca cert pem")
	}
	kblock, _ := pem.Decode(keyPEM)
	if kblock == nil {
		return nil, fmt.Errorf("invalid ca key pem")
	}
	cert, err := x509.ParseCertificate(cblock.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS1PrivateKey(kblock.Bytes)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key, CertPEM: certPEM, KeyPEM: keyPEM, CertPath: certPath, KeyPath: keyPath}, nil
}

func (c *CA) IssueNodeCert(nodeID string, ttl time.Duration) (certPEM, keyPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: nodeID, Organization: []string{"astrality-node"}},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.Cert, &key.PublicKey, c.Key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM, nil
}

func (c *CA) EnsureServerCert(dataDir string, sans []string) (certPath string, keyPath string, err error) {
	certPath = filepath.Join(dataDir, "server.pem")
	keyPath = filepath.Join(dataDir, "server-key.pem")
	if _, err := os.Stat(certPath); err == nil {
		return certPath, keyPath, nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "astrality-server", Organization: []string{"astrality"}},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, s := range sans {
		if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
			continue
		}
		if strings.TrimSpace(s) != "" {
			tpl.DNSNames = append(tpl.DNSNames, strings.TrimSpace(s))
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.Cert, &key.PublicKey, c.Key)
	if err != nil {
		return "", "", err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	if err := os.WriteFile(certPath, certPEM, 0o640); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}
