// Copyright (C) 2026 Podomy.
// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureStaticKeyGeneratesAndReloads(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	key, err := EnsureStaticKey()
	if err != nil {
		t.Fatalf("unexpected error generating noise key: %v", err)
	}

	if len(key.Private) != 32 || len(key.Public) != 32 {
		t.Fatalf("expected 32-byte key halves, got %d and %d", len(key.Private), len(key.Public))
	}

	// Calling again loads the same key from disk.
	second, err := EnsureStaticKey()
	if err != nil {
		t.Fatalf("unexpected error reloading noise key: %v", err)
	}

	if !bytes.Equal(second.Private, key.Private) ||
		!bytes.Equal(second.Public, key.Public) {
		t.Fatalf("expected reloaded key to match generated key")
	}

	// The file lives under concord/noise/secret.key with mode 0600.
	keyPath := filepath.Join(tmpDir, "concord", "noise", "secret.key")
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat noise key: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 file mode, got %o", info.Mode().Perm())
	}
}

func TestEnsureStaticKeyRejectsWrongLength(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	keyPath := filepath.Join(tmpDir, "concord", "noise", "secret.key")

	err := os.MkdirAll(filepath.Dir(keyPath), 0o700)
	if err != nil {
		t.Fatalf("create noise dir: %v", err)
	}

	short := []byte("too-short")
	err = os.WriteFile(keyPath, short, 0o600)
	if err != nil {
		t.Fatalf("write short key: %v", err)
	}

	_, err = EnsureStaticKey()
	if err == nil {
		t.Fatalf("expected error for wrong-length key file")
	}

	// The bad file is left in place, never overwritten.
	// #nosec G304: path is inside the test temp dir.
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	if !bytes.Equal(raw, short) {
		t.Fatalf("expected bad key file to be preserved")
	}
}
