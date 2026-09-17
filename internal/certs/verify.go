// Copyright (C) 2026 Podomy.
// SPDX-License-Identifier: AGPL-3.0-or-later

package certs

import (
	"crypto/x509"
	"fmt"
	"slices"
)

// VerifyNodeCert checks that leaf was signed by ca and carries node
// credentials. It never consults any clock: certificate validity
// windows are intentionally unenforced.
func VerifyNodeCert(leaf, ca *x509.Certificate) error {
	err := checkCertAuthority(leaf, ca)
	if err != nil {
		return err
	}

	err = checkNodeUsages(leaf)
	if err != nil {
		return err
	}

	err = leaf.CheckSignatureFrom(ca)
	if err != nil {
		return fmt.Errorf("leaf is not a child of ca: %w", err)
	}

	return nil
}

// checkCertAuthority requires a CA parent and a non-CA leaf.
func checkCertAuthority(leaf, ca *x509.Certificate) error {
	if ca == nil || !ca.IsCA {
		return fmt.Errorf("ca is not a certificate authority") //nolint:perfsprint // plain sentinel, no wrap target
	}

	if leaf == nil || leaf.IsCA {
		return fmt.Errorf("leaf is not a node certificate") //nolint:perfsprint // plain sentinel, no wrap target
	}

	return nil
}

// checkNodeUsages requires node credential usages on leaf.
func checkNodeUsages(leaf *x509.Certificate) error {
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("leaf cannot sign data") //nolint:perfsprint // plain sentinel, no wrap target
	}

	if !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return fmt.Errorf("leaf cannot be used for server auth") //nolint:perfsprint // plain sentinel, no wrap target
	}

	return nil
}
