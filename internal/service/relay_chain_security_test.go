package service

import (
	"errors"
	"testing"
	"time"

	"nodectl/internal/database"
	"nodectl/internal/version"
)

func TestRelayChainCreateRejectsOnlineInsecureEndpoint(t *testing.T) {
	for _, insecureID := range []string{"relay000001", "exit0000001"} {
		t.Run(insecureID, func(t *testing.T) {
			db := relayChainTestDB(t)
			addRelayChainTestNodes(t, db)
			relayChainOnline = func(string) bool { return true }
			relayChainSecureWS = func(id string) bool { return id != insecureID }
			dispatches := 0
			relayChainDispatch = func(string, string, interface{}, time.Duration) (*AgentCommandResult, error) {
				dispatches++
				return &AgentCommandResult{Status: "ok"}, nil
			}
			if chain, err := CreateRelayChain("relay", "exit"); chain != nil || !errors.Is(err, errRelayChainSecureWSRequired) {
				t.Fatal("online insecure endpoint must reject creation with the WSS error")
			}
			var count int64
			if err := db.Model(&database.RelayChain{}).Count(&count).Error; err != nil || count != 0 || dispatches != 0 {
				t.Fatal("insecure creation persisted or dispatched a private chain")
			}
		})
	}
}

func TestRelayChainSyncRequiresSecureOnlineBeforeLoadingSecrets(t *testing.T) {
	for _, tc := range []struct {
		name           string
		online, secure bool
	}{{"secure", true, true}, {"insecure", true, false}, {"offline", false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			db := relayChainTestDB(t)
			relayChainOnline = func(string) bool { return tc.online }
			relayChainSecureWS = func(string) bool { return tc.secure }
			dispatches := 0
			relayChainDispatch = func(string, string, interface{}, time.Duration) (*AgentCommandResult, error) {
				dispatches++
				return &AgentCommandResult{Status: "ok"}, nil
			}
			// Without the guard this missing table would fail the private-set read.
			if !tc.online || !tc.secure {
				if err := db.Migrator().DropTable(&database.RelayChain{}); err != nil {
					t.Fatal(err)
				}
			}
			err := SyncRelayChainsToNode("relay000001")
			if tc.online && tc.secure {
				if err != nil || dispatches != 1 {
					t.Fatal("secure WSS did not dispatch the authoritative set")
				}
			} else if !errors.Is(err, errRelayChainSecureWSRequired) || dispatches != 0 {
				t.Fatal("insecure/offline sync read or sent private payload")
			}
		})
	}
}

func TestRelayChainReconcileNeverAppliesOverInsecureWS(t *testing.T) {
	db := relayChainTestDB(t)
	addRelayChainTestNodes(t, db)
	relayChainOnline = func(string) bool { return false }
	relayChainSecureWS = func(string) bool { return false }
	dispatches := 0
	relayChainDispatch = func(string, string, interface{}, time.Duration) (*AgentCommandResult, error) {
		dispatches++
		return &AgentCommandResult{Status: "ok"}, nil
	}
	chain, err := CreateRelayChain("relay", "exit")
	if err != nil || chain.Status != ChainPending || dispatches != 0 {
		t.Fatal("offline creation must stay pending without dispatch")
	}
	relayChainOnline = func(string) bool { return true }
	ReconcileRelayChainsForNode("relay000001")
	if err := db.First(chain, "id = ?", chain.ID).Error; err != nil || chain.Status != ChainError || chain.LastError != errRelayChainSecureWSRequired.Error() || dispatches != 0 {
		t.Fatal("insecure reconcile sent chain-apply or omitted the WSS error")
	}
	// The same chain can recover once both endpoints establish WSS.
	relayChainSecureWS = func(string) bool { return true }
	ReconcileRelayChainsForNode("relay000001")
	if err := db.First(chain, "id = ?", chain.ID).Error; err != nil || chain.Status != ChainActive || dispatches != 2 {
		t.Fatal("secure reconnect did not resume Exit then Relay")
	}
	// Delete carries only the ID, so insecure WS may remove an existing chain.
	relayChainSecureWS = func(string) bool { return false }
	if err := DeleteRelayChain(chain.ID); err != nil || dispatches != 4 {
		t.Fatal("ID-only delete must remain allowed over WS")
	}
}

func TestRelayChainSecretSendGuardRejectsOfflineAndInsecure(t *testing.T) {
	relayChainTestDB(t)
	dispatches := 0
	relayChainDispatch = func(string, string, interface{}, time.Duration) (*AgentCommandResult, error) {
		dispatches++
		return &AgentCommandResult{Status: "ok"}, nil
	}
	for _, action := range []string{"chain-apply", "chain-sync"} {
		for _, online := range []bool{false, true} {
			relayChainOnline = func(string) bool { return online }
			relayChainSecureWS = func(string) bool { return false }
			if err := sendRelayChainCommand("relay000001", action, nil); !errors.Is(err, errRelayChainSecureWSRequired) {
				t.Fatal("private command bypassed secure send guard")
			}
		}
	}
	if dispatches != 0 {
		t.Fatal("private command reached dispatcher without WSS")
	}
}

func TestRelayChainStagingVersionGateDoesNotChangeProductionFloor(t *testing.T) {
	old := version.Version
	t.Cleanup(func() { version.Version = old })
	for _, panel := range []string{"dev", "v0.4.76-custom.9", "v0.4.76-custom.9-rc"} {
		version.Version = panel
		for _, agent := range []string{"v0.2.77", "v0.2.78-alpha", "v0.2.77-rc", "v0.2.78-rc", "v0.2.78", "v0.2.79"} {
			want := agent == "v0.2.78" || agent == "v0.2.79" || (panel == "v0.4.76-custom.9-rc" && agent == "v0.2.78-rc")
			if got := relayChainAgentVersionSupported(agent); got != want {
				t.Fatalf("Panel %s / Agent %s accepted=%v want=%v", panel, agent, got, want)
			}
		}
	}
}
