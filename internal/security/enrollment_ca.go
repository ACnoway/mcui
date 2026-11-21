package security

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"sort"
)

const MaxEnrollmentCABytes = 16 << 10

// ReadEnrollmentCA reads an explicitly supplied certificate-only bootstrap CA
// bundle. Its bounded, canonical PEM form can be embedded in an install command.
func ReadEnrollmentCA(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, MaxEnrollmentCABytes+1))
	if err != nil {
		return nil, err
	}
	return CanonicalEnrollmentCA(raw)
}

func CanonicalEnrollmentCA(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > MaxEnrollmentCABytes {
		return nil, errors.New("invalid enrollment CA bundle size")
	}
	var certs [][]byte
	for rest := bytes.TrimSpace(raw); len(rest) > 0; {
		// Decode can skip invalid PEM or other text before a valid block.
		start := []byte("-----BEGIN CERTIFICATE-----")
		end := []byte("-----END CERTIFICATE-----")
		if !bytes.HasPrefix(rest, start) {
			return nil, errors.New("enrollment CA must contain only CA certificates")
		}
		stop := bytes.Index(rest, end)
		if stop < len(start) || bytes.Contains(rest[len(start):stop], []byte("-----BEGIN ")) {
			return nil, errors.New("invalid enrollment CA certificate block")
		}
		stop += len(end)
		block, tail := pem.Decode(rest[:stop])
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(tail) != 0 {
			return nil, errors.New("invalid enrollment CA certificate block")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA {
			return nil, errors.New("enrollment CA contains an invalid or non-CA certificate")
		}
		certs = append(certs, cert.Raw)
		rest = bytes.TrimSpace(rest[stop:])
	}
	if len(certs) == 0 {
		return nil, errors.New("enrollment CA contains no certificates")
	}
	sort.Slice(certs, func(i, j int) bool { return bytes.Compare(certs[i], certs[j]) < 0 })
	var out bytes.Buffer
	for i, cert := range certs {
		if i > 0 && bytes.Equal(certs[i-1], cert) {
			continue
		}
		if err := pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
			return nil, err
		}
	}
	if out.Len() > MaxEnrollmentCABytes {
		return nil, errors.New("canonical enrollment CA bundle exceeds size limit")
	}
	return out.Bytes(), nil
}
