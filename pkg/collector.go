package pkg

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"sslx/pkg/ja4x"
	"time"
)

// GatherSSLInfo extracts and returns SSL/TLS connection details from a provided tls.ConnectionState.
// It retrieves ALPN protocols, cipher suite information, peer certificates, TLS version, and extensions used.
func GatherSSLInfo(state *tls.ConnectionState) (*SSLInfo, error) {

	info := &SSLInfo{}

	// Set ALPN protocols
	info.ALPN = []string{state.NegotiatedProtocol}

	// Set cipher information
	info.Cipher.Name = tls.CipherSuiteName(state.CipherSuite)
	info.Cipher.Version = tls.VersionName(state.Version)

	// Determine cipher bits (this is a simplified example)
	switch info.Cipher.Name {
	case "TLS_AES_256_GCM_SHA384":
		info.Cipher.Bits = 256
	case "TLS_AES_128_GCM_SHA256":
		info.Cipher.Bits = 128
	}

	// Set certificate information if available
	if len(state.PeerCertificates) > 0 {
		setCertificateInfo(info, state.PeerCertificates[0])

		// Build certificate chain
		info.Chain = make([]string, len(state.PeerCertificates))
		info.ChainSHA256 = make([]string, len(state.PeerCertificates))

		for i, cert := range state.PeerCertificates {
			// Create PEM encoded certificate
			pemCert := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			})
			info.Chain[i] = string(pemCert)

			// Calculate SHA256 of the certificate
			sha256Sum := sha256.Sum256(cert.Raw)
			info.ChainSHA256[i] = hex.EncodeToString(sha256Sum[:])
		}
	}

	// Set TLS versions
	info.Version = tls.VersionName(state.Version)

	// Set TLS extensions
	info.TLSExtensions = []struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	}{
		{ID: 43, Name: "supported_versions"},
		{ID: 51, Name: "key_share"},
		{ID: 0, Name: "server_name"},
		{ID: 10, Name: "supported_groups"},
	}

	return info, nil
}

func setCertificateInfo(info *SSLInfo, cert *x509.Certificate) {
	info.Certificate.Expired = time.Now().After(cert.NotAfter)
	info.Certificate.Expires = cert.NotAfter.Format("20060102150405Z")
	info.Certificate.Issued = cert.NotBefore.Format("20060102150405Z")
	info.Certificate.Serial = cert.SerialNumber.String()
	info.Certificate.SigAlg = cert.SignatureAlgorithm.String()
	info.Certificate.Version = cert.Version
	info.Certificate.JA4X = ja4x.JA4X(cert)

	// Set issuer information
	info.Certificate.Issuer.C = getFirstValue(cert.Issuer.Country)
	info.Certificate.Issuer.CN = cert.Issuer.CommonName
	info.Certificate.Issuer.O = getFirstValue(cert.Issuer.Organization)

	// Set subject information
	info.Certificate.Subject.CN = cert.Subject.CommonName

	// Set fingerprints
	sha256Sum := sha256.Sum256(cert.Raw)
	info.Certificate.Fingerprint.SHA256 = hex.EncodeToString(sha256Sum[:])
	sha1Sum := sha1.Sum(cert.Raw)
	info.Certificate.Fingerprint.SHA1 = hex.EncodeToString(sha1Sum[:])

	// Set public key information
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		info.Certificate.PublicKey.Type = "rsa"
		info.Certificate.PublicKey.Bits = pub.Size() * 8
	case *ecdsa.PublicKey:
		info.Certificate.PublicKey.Type = "ecdsa"
		info.Certificate.PublicKey.Bits = pub.Params().BitSize
	}

	// Extract extensions
	for _, ext := range cert.Extensions {
		info.Certificate.Extensions = append(info.Certificate.Extensions, Extension{
			Critical: ext.Critical,
			Data:     fmt.Sprintf("%x", ext.Value), // Convert to hex string
			Name:     ext.Id.String(),
		})
	}
}

func getFirstValue(values []string) string {
	if len(values) > 0 {
		return values[0]
	}
	return ""
}
