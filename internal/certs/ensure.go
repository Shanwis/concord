// Copyright (C) 2026 Podomy.
// SPDX-License-Identifier: AGPL-3.0-or-later

package certs

import (
	"fmt"
	"os"
)

// Ensure returns the default CA paths for transport after checking the
// operator-provisioned CA material exists.
//
// Policy: ca.crt and ca.key must already be on disk (factory, flash drive,
// etc.). No certificates are minted here; node identity lives in the Noise
// static key, not in node.crt. Normal node bootstrap never creates a CA:
// createCA/WriteCA are not on this path. WriteCA is only for offline
// provisioning tools and tests.
func Ensure() (Paths, error) {
	paths, err := DefaultPaths()
	if err != nil {
		return Paths{}, err
	}

	if err := requireCA(paths); err != nil {
		return Paths{}, err
	}

	return paths, nil
}

// requireCA checks that ca.crt and ca.key exist (operator-provisioned CA).
func requireCA(paths Paths) error {
	for _, p := range []string{paths.CA, paths.CAKey} {
		if _, err := os.Stat(p); err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("CA not provisioned: missing %s (place ca.crt and ca.key under the certs directory)", p)
			}
			return fmt.Errorf("stat %s: %w", p, err)
		}
	}
	return nil
}
