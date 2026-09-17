// Copyright (C) 2026 Podomy.
// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/podomy/concord/internal/certs"
)

// loadTLSConfig loads this node's cert/key and the CA trust pool for the HTTPS server.
// Client certificates are verified by CA signature and node usages only;
// certificate validity windows are not enforced.
// RequireAnyClientCert performs no validation itself, so VerifyConnection
// is the sole authentication check, on every connection including
// resumptions: without the callback this side would accept strangers.
func loadTLSConfig(caFile, certFile, keyFile string) (*tls.Config, error) {
	cert, pool, ca, err := loadCertAndPool(caFile, certFile, keyFile)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		ClientAuth:             tls.RequireAnyClientCert,
		SessionTicketsDisabled: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyPeerCert(cs.PeerCertificates, ca)
		},
		NextProtos:   []string{"h2"},
		ClientCAs:    pool,
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
	}, nil
}

// loadClientTLSConfig loads material for outbound mTLS dials.
//
// Peer certs are verified by CA signature and node usages only (no
// hostname/IP check, no validity window). Skipping stdlib verification
// is safe only because VerifyConnection fully authenticates every
// connection, including resumptions: without the callback this side
// would accept strangers. Nodes dial
// by memberlist IP while cert SANs carry node id / advertise IP; requiring the
// dial string to match SAN would break LAN peers without a matching IP SAN.
func loadClientTLSConfig(caFile, certFile, keyFile string) (*tls.Config, error) {
	cert, pool, ca, err := loadCertAndPool(caFile, certFile, keyFile)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		NextProtos:             []string{"h2"},
		RootCAs:                pool,
		Certificates:           []tls.Certificate{cert},
		InsecureSkipVerify:     true, //nolint:gosec // hostname skipped; VerifyConnection enforces CA signature
		SessionTicketsDisabled: true, // avoid resume bypassing custom verify.
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyPeerCert(cs.PeerCertificates, ca)
		},
	}, nil
}

func loadCertAndPool(caFile, certFile, keyFile string) (tls.Certificate, *x509.CertPool, *x509.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("load node cert/key: %w", err)
	}

	// #nosec G304: ca path is local runtime configuration, not user-controlled input.
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("read ca: %w", err)
	}

	// decode caPEM
	block, _ := pem.Decode(caPEM)
	if block == nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("caPEM decoding failed") //nolint:perfsprint // plain sentinel, no wrap target
	}

	if block.Type != "CERTIFICATE" {
		return tls.Certificate{}, nil, nil, fmt.Errorf("decoded PEM is not a certificate") //nolint:perfsprint // plain sentinel, no wrap target
	}

	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("parse ca certificate: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return tls.Certificate{}, nil, nil, fmt.Errorf("no CA certs in %s", caFile)
	}

	return cert, pool, ca, nil
}

// verifyPeerCert checks that the peer leaf was signed by ca and carries
// node credentials. Certificate validity windows are not enforced;
// see certs.VerifyNodeCert.
func verifyPeerCert(peerCerts []*x509.Certificate, ca *x509.Certificate) error {
	if len(peerCerts) == 0 {
		return fmt.Errorf("peer certificate missing") //nolint:perfsprint // plain sentinel
	}

	leaf := peerCerts[0]
	err := certs.VerifyNodeCert(leaf, ca)
	if err != nil {
		return fmt.Errorf("verify node cert: %w", err)
	}

	return nil
}
