// Copyright (C) 2026 Podomy.
// SPDX-License-Identifier: AGPL-3.0-or-later

package integration_test

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/podomy/concord/internal/certs"
	"github.com/podomy/concord/internal/journal"
	"github.com/podomy/concord/internal/journalreader"
	"github.com/podomy/concord/internal/journalview"
	"github.com/podomy/concord/internal/kvstore"
	"github.com/podomy/concord/internal/peerdiscovery"
	"github.com/podomy/concord/internal/peersync"
	"github.com/podomy/concord/internal/transport"
)

// TestTwoNodeEventSync validates that two nodes discover each other via
// memberlist and sync a journal event from A to B through the pull loop.
//
// This test only exercises the event sync layer (peersync). Container
// lifecycle, networking (bridge/veth/nat), and image pulling require
// root privileges and a running zot registry, those belong in a
// separate integration test.
func TestTwoNodeEventSync(t *testing.T) {
	dirA, dirB := t.TempDir(), t.TempDir()
	idA, idB := uuid.New(), uuid.New()

	provisionNodes(t, idA, idB, dirA, dirB)
	noiseA, noiseB := provisionNoise(t, idA, idB, dirA, dirB)

	kvA := openKV(t, filepath.Join(dirA, "concord", "bbolt.db"))
	jA := openJSONL(t, filepath.Join(dirA, "concord", "journal.jsonl"))
	_, viewsA := initViews(t, kvA, filepath.Join(dirA, "concord", "journal.jsonl"))

	kvB := openKV(t, filepath.Join(dirB, "concord", "bbolt.db"))
	jB := openJSONL(t, filepath.Join(dirB, "concord", "journal.jsonl"))
	eventsByIDB, viewsB := initViews(t, kvB, filepath.Join(dirB, "concord", "journal.jsonl"))

	logger := zaptest.NewLogger(t)
	t.Setenv("XDG_CONFIG_HOME", dirA)

	// Node A.
	ctxA, cancelA := context.WithCancel(t.Context())
	t.Cleanup(cancelA)

	peerA := startMemberlist(t, logger, idA, netip.MustParseAddrPort("127.0.0.1:17946"), nil, noiseA.gossipBinding())
	t.Cleanup(func() { shutDown(t, peerA) })

	origPort := transport.Port
	transport.Port = "18443"
	t.Cleanup(func() { transport.Port = origPort })

	caPathA := filepath.Join(dirA, "concord", "certs", "ca.crt")
	caCertA, err := transport.LoadCACert(caPathA)
	if err != nil {
		t.Fatalf("load ca A: %v", err)
	}
	if err := transport.Start(ctxA, logger, noiseA.static, noiseA.parcelBytes(), transport.CAVerifier(caCertA)); err != nil {
		t.Fatalf("A transport: %v", err)
	}

	if err := journalview.RecordNodeStarted(ctxA, logger, jA, viewsA, idA, netip.MustParseAddrPort("127.0.0.1:17946")); err != nil {
		t.Fatalf("A record started: %v", err)
	}

	// Node B.
	ctxB, cancelB := context.WithCancel(t.Context())
	t.Cleanup(cancelB)

	peerB := startMemberlist(t, logger, idB, netip.MustParseAddrPort("127.0.0.1:17947"),
		[]netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:17946")}, noiseB.gossipBinding())
	t.Cleanup(func() { shutDown(t, peerB) })

	caPathB := filepath.Join(dirB, "concord", "certs", "ca.crt")
	caCertB, err := transport.LoadCACert(caPathB)
	if err != nil {
		t.Fatalf("load ca B: %v", err)
	}
	clientB := transport.NewClient(noiseB.static, noiseB.parcelBytes(), transport.CAVerifier(caCertB))

	go peersync.RunPullLoop(ctxB, logger, idB, peerB, clientB, jB, viewsB, eventsByIDB)

	time.Sleep(2 * time.Second) // let memberlist gossip propagate.

	testEvent := journal.NewEvent(idA, "sync.test", json.RawMessage(`{}`))
	if err := journalview.RecordEvent(ctxA, jA, viewsA, testEvent); err != nil {
		t.Fatalf("record event: %v", err)
	}

	got := waitForEvent(t, eventsByIDB, testEvent.ID, 20*time.Second)
	if got.NodeID != idA {
		t.Fatalf("event node_id = %s, want %s", got.NodeID, idA)
	}
	if got.Type != "sync.test" {
		t.Fatalf("event type = %s, want sync.test", got.Type)
	}
	t.Log("event sync test PASSED: event synced from A to B via pull loop")

	// Large page: 8 KiB exceeds HTTP transport read buffers, so the body must
	// stream from the still-open Noise session. It stays below the journal
	// line limit.
	bigEvent := journal.NewEvent(idA, "sync.test.big", json.RawMessage(`{"data":"`+strings.Repeat("x", 8<<10)+`"}`))
	if err := journalview.RecordEvent(ctxA, jA, viewsA, bigEvent); err != nil {
		t.Fatalf("record big event: %v", err)
	}

	gotBig := waitForEvent(t, eventsByIDB, bigEvent.ID, 20*time.Second)
	if len(gotBig.Payload) != len(bigEvent.Payload) {
		t.Fatalf("big payload = %d bytes, want %d", len(gotBig.Payload), len(bigEvent.Payload))
	}
	t.Log("event sync test PASSED: 8 KiB event synced from A to B via pull loop")
}

func provisionNodes(t *testing.T, idA, idB uuid.UUID, dirA, dirB string) {
	t.Helper()

	// Provision CA and node A certs in dirA.
	t.Setenv("XDG_CONFIG_HOME", dirA)
	if err := certs.WriteCA(); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	if _, err := certs.Ensure(idA, netip.Addr{}); err != nil {
		t.Fatalf("ensure node A certs: %v", err)
	}

	// Copy CA to dirB so node B shares the same CA trust root.
	certsDirB := filepath.Join(dirB, "concord", "certs")
	if err := os.MkdirAll(certsDirB, 0o700); err != nil {
		t.Fatalf("mkdir certs B: %v", err)
	}
	certsDirA := filepath.Join(dirA, "concord", "certs")
	copyFile(t, filepath.Join(certsDirA, "ca.crt"), filepath.Join(certsDirB, "ca.crt"))
	copyFile(t, filepath.Join(certsDirA, "ca.key"), filepath.Join(certsDirB, "ca.key"))

	// Ensure node B certs using the copied CA.
	t.Setenv("XDG_CONFIG_HOME", dirB)
	if _, err := certs.Ensure(idB, netip.Addr{}); err != nil {
		t.Fatalf("ensure node B certs: %v", err)
	}
}

// nodeNoise bundles one test node's Noise identity: static keypair plus the
// CA-signed identity it gossips.
type nodeNoise struct {
	id     uuid.UUID
	static transport.StaticKey
	sig    []byte
	gen    uint64
}

// gossipBinding converts to the peerdiscovery gossip shape: public key plus
// generation only. The CA signature travels inside the Noise session.
func (n nodeNoise) gossipBinding() peerdiscovery.NoiseIdentity {
	return peerdiscovery.NoiseIdentity{
		Pub:        n.static.Public,
		Signature:  n.sig,
		Generation: n.gen,
	}
}

// parcelBytes encodes this node's session parcel.
func (n nodeNoise) parcelBytes() []byte {
	return transport.EncodeParcel(n.id, n.gen, n.sig)
}

// provisionNoise generates per-node Noise keys and CA-signed generation-0
// parcels under each node's own XDG dir. Must run after provisionNodes so the
// CA exists in both dirs.
func provisionNoise(t *testing.T, idA, idB uuid.UUID, dirA, dirB string) (nodeNoise, nodeNoise) {
	t.Helper()

	t.Setenv("XDG_CONFIG_HOME", dirA)
	staticA, err := transport.EnsureStaticKey()
	if err != nil {
		t.Fatalf("ensure noise key A: %v", err)
	}
	sigA, err := certs.SignNodeKey(idA, 0, staticA.Public)
	if err != nil {
		t.Fatalf("sign noise key A: %v", err)
	}

	t.Setenv("XDG_CONFIG_HOME", dirB)
	staticB, err := transport.EnsureStaticKey()
	if err != nil {
		t.Fatalf("ensure noise key B: %v", err)
	}
	sigB, err := certs.SignNodeKey(idB, 0, staticB.Public)
	if err != nil {
		t.Fatalf("sign noise key B: %v", err)
	}

	t.Setenv("XDG_CONFIG_HOME", dirA)

	return nodeNoise{id: idA, static: staticA, sig: sigA},
		nodeNoise{id: idB, static: staticB, sig: sigB}
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	// #nosec G304 - test helper with trusted temp dir paths.
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	// #nosec G703 - test helper with trusted temp dir paths.
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
}

func openKV(t *testing.T, path string) *kvstore.KVStore {
	t.Helper()
	kv, err := kvstore.OpenDBPath(path)
	if err != nil {
		t.Fatalf("open kv %s: %v", path, err)
	}
	return kv
}

func openJSONL(t *testing.T, path string) *journal.JSONL {
	t.Helper()
	j, err := journal.OpenJSONLPath(path)
	if err != nil {
		t.Fatalf("open journal %s: %v", path, err)
	}
	return j
}

func initViews(t *testing.T, kv *kvstore.KVStore, journalPath string) (*journalview.EventsByID, []journalview.View) {
	t.Helper()
	eventsByID := journalview.NewEventsByID(kv)
	views := []journalview.View{
		eventsByID,
		journalview.NewEventsByNode(kv),
		journalview.NewEventsByType(kv),
	}
	jr, err := journalreader.OpenJSONLReaderPath(journalPath)
	if err != nil {
		t.Fatalf("open journal reader: %v", err)
	}
	defer jr.Close() //nolint:errcheck // best-effort in test
	for _, view := range views {
		if err := view.Rebuild(context.Background(), jr); err != nil {
			t.Fatalf("rebuild view: %v", err)
		}
	}
	return eventsByID, views
}

// testGossipKeyValue is the fixed cluster-wide secret shared by all test
// nodes, mirroring one operator-provisioned key per test cluster.
var testGossipKeyValue = []byte("0123456789abcdef0123456789abcdef")

func startMemberlist(t *testing.T, logger *zap.Logger, id uuid.UUID, bind netip.AddrPort, join []netip.AddrPort, identity peerdiscovery.NoiseIdentity) *peerdiscovery.MemberService {
	t.Helper()
	provisionGossipKey(t)
	ms, err := peerdiscovery.Start(logger, peerdiscovery.Node{ID: id, Address: bind}, join, netip.Addr{}, identity)
	if err != nil {
		t.Fatalf("memberlist start: %v", err)
	}
	return ms
}

// provisionGossipKey writes the fixed cluster-wide test secret into the
// current XDG config dir, mirroring one operator-provisioned key shared by
// every node in the test cluster.
func provisionGossipKey(t *testing.T) {
	t.Helper()
	dir, err := os.UserConfigDir()
	if err != nil {
		t.Fatalf("user config dir: %v", err)
	}
	keyDir := filepath.Join(dir, "concord", "memberservice")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatalf("create key dir: %v", err)
	}
	// #nosec G703 - test helper with trusted temp dir paths.
	if err := os.WriteFile(filepath.Join(keyDir, "secret.key"), testGossipKeyValue, 0o600); err != nil {
		t.Fatalf("write gossip key: %v", err)
	}
}

func shutDown(t *testing.T, ms *peerdiscovery.MemberService) {
	t.Helper()
	if err := ms.Shutdown(); err != nil {
		t.Logf("memberlist shutdown: %v", err)
	}
}

func waitForEvent(t *testing.T, byID *journalview.EventsByID, id uuid.UUID, timeout time.Duration) *journal.Event {
	t.Helper()
	pollCtx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	for {
		if pollCtx.Err() != nil {
			t.Fatalf("timed out waiting for event %s", id)
		}
		e, err := byID.Get(pollCtx, id)
		if err == nil && e != nil {
			return e
		}
		time.Sleep(200 * time.Millisecond)
	}
}
