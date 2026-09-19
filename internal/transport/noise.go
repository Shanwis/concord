// Copyright (C) 2026 Podomy.
// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
)

// StaticKey is this node's Noise static keypair as raw Curve25519 bytes.
type StaticKey struct {
	Private []byte
	Public  []byte
}

// EnsureStaticKey loads or generates the Noise static key under
// <config>/concord/noise/secret.key.
//
// The file holds 32 raw bytes (mode 0600). A file of any other length is an
// error and is never overwritten. The private half is never logged.
func EnsureStaticKey() (StaticKey, error) {
	path, err := noiseKeyPath()
	if err != nil {
		return StaticKey{}, err
	}

	// #nosec G304: path is local runtime configuration, not user input.
	raw, err := os.ReadFile(path)
	if err == nil {
		return staticKeyFromPrivate(raw)
	}
	if !os.IsNotExist(err) {
		return StaticKey{}, fmt.Errorf("read noise key: %w", err)
	}

	return generateStaticKey(path)
}

// noiseKeyPath returns the on-disk location of the Noise static key.
func noiseKeyPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("get user config dir: %w", err)
	}

	return filepath.Join(dir, "concord", "noise", "secret.key"), nil
}

// staticKeyFromPrivate validates raw private key bytes and derives the public
// half.
func staticKeyFromPrivate(raw []byte) (StaticKey, error) {
	if len(raw) != 32 {
		return StaticKey{}, fmt.Errorf("noise key: got %d bytes, want 32", len(raw))
	}

	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return StaticKey{}, fmt.Errorf("parse noise key: %w", err)
	}

	return StaticKey{Private: raw, Public: key.PublicKey().Bytes()}, nil
}

// generateStaticKey creates a new keypair and writes the private half to path.
func generateStaticKey(path string) (StaticKey, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return StaticKey{}, fmt.Errorf("generate noise key: %w", err)
	}

	err = os.MkdirAll(filepath.Dir(path), 0o700)
	if err != nil {
		return StaticKey{}, fmt.Errorf("create noise dir: %w", err)
	}

	private := key.Bytes()
	err = os.WriteFile(path, private, 0o600)
	if err != nil {
		return StaticKey{}, fmt.Errorf("write noise key: %w", err)
	}

	return StaticKey{Private: private, Public: key.PublicKey().Bytes()}, nil
}
