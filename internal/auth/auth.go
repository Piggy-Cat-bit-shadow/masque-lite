package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
)

func Fingerprint(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(h[:])
}
func PublicKeyBytes(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(ellipticMarshal(cert))
}
func ellipticMarshal(cert *x509.Certificate) []byte {
	if p, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		if p.Curve != elliptic.P256() {
			return nil
		}
		return elliptic.Marshal(elliptic.P256(), p.X, p.Y)
	}
	return nil
}
func Matches(cert *x509.Certificate, allowed []string) bool {
	got := PublicKeyBytes(cert)
	for _, want := range allowed {
		if got == want {
			return true
		}
	}
	return false
}
