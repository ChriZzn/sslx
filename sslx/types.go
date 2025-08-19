package sslx

// SSLInfo represents detailed SSL/TLS connection data including certificate, cipher, and protocol information.
type SSLInfo struct {
	ALPN []string `json:"alpn"`

	Certificate struct {
		Expired     bool        `json:"expired"`
		Expires     string      `json:"expires"`
		Issued      string      `json:"issued"`
		Extensions  []Extension `json:"extensions"`
		JA4X        string      `json:"ja4x"`
		Fingerprint struct {
			SHA1   string `json:"sha1"`
			SHA256 string `json:"sha256"`
		} `json:"fingerprint"`
		Issuer struct {
			C  string `json:"c,omitempty"`
			CN string `json:"cn,omitempty"`
			O  string `json:"o,omitempty"`
		} `json:"issuer"`
		PublicKey struct {
			Bits int    `json:"bits"`
			Type string `json:"type"`
		} `json:"pubkey"`
		Serial  string `json:"serial"`
		SigAlg  string `json:"sig_alg"`
		Subject struct {
			CN string `json:"cn"`
		} `json:"subject"`
		Version int `json:"version"`
	} `json:"cert"`
	Chain       []string `json:"chain"`
	ChainSHA256 []string `json:"chain_sha256"`
	Cipher      struct {
		Bits    int    `json:"bits"`
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"cipher"`
	TLSExtensions []struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	} `json:"tlsext"`
	Version string `json:"version"`
}

type Extension struct {
	Critical bool   `json:"critical"`
	Data     string `json:"data"`
	Name     string `json:"name"`
}
