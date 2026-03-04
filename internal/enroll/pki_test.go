package enroll

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestIssueNodeCert(t *testing.T) {
	dir := t.TempDir()
	ca, err := EnsureCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, _, err := ca.IssueNodeCert("node-123", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(certPEM)
	if blk == nil {
		t.Fatal("expected cert pem")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "node-123" {
		t.Fatalf("unexpected CN: %s", cert.Subject.CommonName)
	}
}
