// Copyright (C) 2026 Podomy.
// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
)

// noiseDirName is the config subdirectory holding Noise identity material.
const noiseDirName = "noise"

// noiseKeyFileName is the file holding this node's Noise static private key.
const noiseKeyFileName = "secret.key"

// noiseGenerationFileName is the file holding this node's Noise key rotation
// counter. Generation 0 is the first static key. Rotation means writing a new
// static key and bumping this counter, then restarting so the new parcel is
// signed and gossiped.
const noiseGenerationFileName = "generation"

// generationWidth is the byte width of the encoded rotation counter: one
// big-endian uint64. The generation file holds exactly this many bytes.
const generationWidth = 8

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

// noiseDir returns the on-disk directory for Noise identity material.
func noiseDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("get user config dir: %w", err)
	}

	return filepath.Join(dir, "concord", noiseDirName), nil
}

// noiseKeyPath returns the on-disk location of the Noise static key.
func noiseKeyPath() (string, error) {
	dir, err := noiseDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, noiseKeyFileName), nil
}

// noiseGenerationPath returns the on-disk location of the rotation counter.
func noiseGenerationPath() (string, error) {
	dir, err := noiseDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, noiseGenerationFileName), nil
}

// EnsureGenerationCounter loads this node's Noise key rotation counter,
// creating it at 0 on first use. The file holds one big-endian uint64 (mode
// 0600). A counter without a static key is meaningless, so runtime always
// ensures the key first; a missing file here means first boot, not an error.
func EnsureGenerationCounter() (uint64, error) {
	path, err := noiseGenerationPath()
	if err != nil {
		return 0, err
	}

	// #nosec G304: path is local runtime configuration, not user input.
	raw, err := os.ReadFile(path)
	if err == nil {
		if len(raw) != generationWidth {
			return 0, fmt.Errorf("noise generation: got %d bytes, want %d", len(raw), generationWidth)
		}
		return binary.BigEndian.Uint64(raw), nil
	}
	if !os.IsNotExist(err) {
		return 0, fmt.Errorf("read noise generation: %w", err)
	}

	err = os.MkdirAll(filepath.Dir(path), 0o700)
	if err != nil {
		return 0, fmt.Errorf("create noise dir: %w", err)
	}

	zero := make([]byte, generationWidth)
	err = os.WriteFile(path, zero, 0o600)
	if err != nil {
		return 0, fmt.Errorf("write noise generation: %w", err)
	}

	return 0, nil
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
