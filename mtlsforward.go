// Package mtlsforward implements a middleware for
// Traefik Proxy that forwards mTLS certificates inside
// HTTP headers.
package mtlsforward

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// defaults adapted from traefik
const (
	xForwardedTLSClientCertDefault     = "X-Forwarded-Tls-Client-Cert"
	xForwardedTLSClientCertChainPrefix = "X-Forwarded-Tls-Client-Cert-Chain"
)

// Config handles configuration of the sslClientCert (e.g. SSL_CLIENT_CERT) and sslCertChainPrefix (e.g. SSL_CERT_CHAIN) headers.
type Config struct {
	Headers       map[string]string
	EncodePem     bool
	SanitizePem   bool
	EncodeURL     bool
	RemoveNewline bool
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Headers: map[string]string{
			"sslClientCert":      xForwardedTLSClientCertDefault,
			"sslCertChainPrefix": xForwardedTLSClientCertChainPrefix,
		},
		EncodePem:     false,
		SanitizePem:   false,
		EncodeURL:     false,
		RemoveNewline: true,
	}
}

// New created a new plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// Ensure headers map is initialized
	if config.Headers == nil {
		config.Headers = make(map[string]string)
	}

	// Set defaults for missing header keys
	if _, ok := config.Headers["sslClientCert"]; !ok {
		config.Headers["sslClientCert"] = xForwardedTLSClientCertDefault
	}
	if _, ok := config.Headers["sslCertChainPrefix"]; !ok {
		config.Headers["sslCertChainPrefix"] = xForwardedTLSClientCertChainPrefix
	}

	return &mTLSForward{
		headers:       config.Headers,
		encodePem:     config.EncodePem,
		sanitizePem:   config.SanitizePem,
		encodeURL:     config.EncodeURL,
		removeNewline: config.RemoveNewline,
		next:          next,
		name:          name,
	}, nil
}

type mTLSForward struct {
	headers       map[string]string
	encodePem     bool
	sanitizePem   bool
	encodeURL     bool
	removeNewline bool
	next          http.Handler
	name          string
}

// this is copied from the original passTlsClientCert middleware in traefik
func sanitize(cert []byte) string {
	return strings.NewReplacer(
		"-----BEGIN CERTIFICATE-----", "",
		"-----END CERTIFICATE-----", "",
		"\n", "",
	).Replace(string(cert))
}

func (m *mTLSForward) encodeCertificate(certBytes *[]byte) string {
	encodedCert := ""

	if m.encodePem {
		if m.sanitizePem {
			encodedCert = sanitize(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: *certBytes}))
		} else {
			encodedCert = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: *certBytes}))
		}
	} else {
		encodedCert = base64.StdEncoding.EncodeToString(*certBytes)
	}

	if m.encodeURL {
		encodedCert = url.QueryEscape(encodedCert)
	}

	if !m.encodeURL && m.removeNewline {
		encodedCert = strings.ReplaceAll(encodedCert, "\n", " ")
	}
	return encodedCert
}

func (m *mTLSForward) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	// are we using mTLS?
	if request.TLS != nil && len(request.TLS.PeerCertificates) > 0 {
		for i, cert := range request.TLS.PeerCertificates {
			fmt.Println("Found certificate with subject", cert.Subject, "issued by", cert.Issuer)
			certString := m.encodeCertificate(&cert.Raw)
			if i == 0 {
				request.Header.Set(m.headers["sslClientCert"], certString)
			} else {
				// part of chain
				headerName := m.headers["sslCertChainPrefix"] + "_" + strconv.Itoa(i-1)
				request.Header.Set(headerName, certString)
			}
		}
	}
	fmt.Println("Ready for next plugin")

	// call to next plugin
	m.next.ServeHTTP(writer, request)
}
