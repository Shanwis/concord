// Copyright (C) 2026 Podomy.
// SPDX-License-Identifier: AGPL-3.0-or-later

package certs

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/google/uuid"
)

// nodeKeyDomain prefixes every signed Noise key binding so the CA signature
// can never be mistaken for a signature over any other message.
const nodeKeyDomain = "concord-noise-static-key:"

// SignNodeKey signs the binding between a node ID, a key generation, and a
// Noise static public key using the fleet CA key. The signature is the node's
// membership credential. No timestamp and no validity window are involved.
//
// VerifyNodeKey must rebuild the identical message, including nodeKeyDomain.
func SignNodeKey(nodeID uuid.UUID, generation uint64, pub []byte) ([]byte, error) {
	if len(pub) != 32 {
		return nil, fmt.Errorf("public key must be 32 bytes") //nolint:perfsprint // plain sentinel, no wrap target
	}

	paths, err := DefaultPaths()
	if err != nil {
		return nil, fmt.Errorf("default paths: %w", err)
	}

	_, caKey, err := loadCA(paths)
	if err != nil {
		return nil, fmt.Errorf("load ca: %w", err)
	}

	msg := make([]byte, 0, len(nodeKeyDomain)+len(nodeID)+8+len(pub))
	msg = append(msg, nodeKeyDomain...)
	msg = append(msg, nodeID[:]...)
	msg = binary.BigEndian.AppendUint64(msg, generation)
	msg = append(msg, pub...)

	sum := sha256.Sum256(msg)
	sig, err := rsa.SignPKCS1v15(nil, caKey, crypto.SHA256, sum[:])
	if err != nil {
		return nil, fmt.Errorf("sign node key: %w", err)
	}

	return sig, nil
}
