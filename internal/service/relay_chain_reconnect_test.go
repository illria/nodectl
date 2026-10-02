package service

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"nodectl/internal/database"
	"nodectl/internal/relaychain"
)

func TestActiveRelayChainReconnectReappliesAndProbes(t *testing.T) {
	for _, tc := range []struct {
		name, reconnectID string
		probeReachable    bool
	}{
		{"Relay reachable", "relay000001", true},
		{"Relay probe failure", "relay000001", false},
		{"Exit reachable", "exit0000001", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := relayChainTestDB(t)
			addRelayChainTestNodes(t, db)
			relayChainOnline = func(string) bool { return true }
			var commands []string
			probeCalls, probeReachable := 0, true
			reconnecting := false
			relayChainDispatch = func(id, action string, payload interface{}, _ time.Duration) (*AgentCommandResult, error) {
				commands = append(commands, action+":"+id)
				if action == "chain-sync" {
					set, ok := payload.([]relaychain.Config)
					if !ok || len(set) != 1 {
						t.Fatal("reconnect did not send the authoritative chain set")
					}
					return &AgentCommandResult{Status: "ok"}, nil
				}
				config, ok := payload.(relaychain.Config)
				if !ok || action != "chain-apply" {
					t.Fatal("unexpected reconnect command")
				}
				if id == "exit0000001" && config.Role != relaychain.RoleExit ||
					id == "relay000001" && config.Role != relaychain.RoleRelay {
					t.Fatal("chain-apply sent the wrong endpoint role")
				}
				if reconnecting && id == "exit0000001" {
					provider, err := GenerateChainNodesYAML()
					if err != nil || strings.Contains(provider, "198.51.100.10") {
						t.Fatal("active chain remained published during reconnect validation")
					}
				}
				if config.Role == relaychain.RoleRelay {
					probeCalls++ // Agent acknowledges only after its TCP probe.
					if !probeReachable {
						return &AgentCommandResult{Status: "error"}, nil
					}
				}
				return &AgentCommandResult{Status: "ok"}, nil
			}
			chain, err := CreateRelayChain("relay", "exit")
			if err != nil || chain.Status != ChainActive {
				t.Fatal("could not establish initial active chain")
			}
			before := *chain
			commands, probeCalls, probeReachable, reconnecting = nil, 0, tc.probeReachable, true
			if err := restoreRelayChainsForNode(tc.reconnectID); err != nil {
				t.Fatal("secure authoritative sync failed on reconnect")
			}
			wantCommands := []string{
				"chain-sync:" + tc.reconnectID,
				"chain-apply:exit0000001",
				"chain-apply:relay000001",
			}
			if !reflect.DeepEqual(commands, wantCommands) || probeCalls != 1 {
				t.Fatalf("reconnect must apply Exit, then Relay and probe: commands=%v probes=%d", commands, probeCalls)
			}
			if err := db.First(chain, "id = ?", chain.ID).Error; err != nil {
				t.Fatal(err)
			}
			assertRelayChainIdentityUnchanged(t, before, *chain)
			provider, err := GenerateChainNodesYAML()
			if err != nil {
				t.Fatal(err)
			}
			if tc.probeReachable {
				if chain.Status != ChainActive || !strings.Contains(provider, chain.RelayIP) {
					t.Fatal("successful reconnect did not restore published active chain")
				}
			} else if chain.Status != ChainError || strings.Contains(provider, chain.RelayIP) ||
				!strings.Contains(provider, "无中转链-不可用") {
				t.Fatal("failed Relay probe left an active chain in /sub/chains")
			}
		})
	}
}

func TestAuthoritativeChainSyncFailureInvalidatesActiveChain(t *testing.T) {
	for _, tc := range []struct {
		name          string
		insecure      bool
		failure       string
		wantSyncCalls int
	}{
		{"insecure reconnect", true, "", 0},
		{"dispatch failure", false, "dispatch", 1},
		{"Agent rejected reload", false, "rejected", 1},
		{"successful secure sync", false, "", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := relayChainTestDB(t)
			addRelayChainTestNodes(t, db)
			relayChainOnline = func(string) bool { return true }
			relayChainDispatch = func(string, string, interface{}, time.Duration) (*AgentCommandResult, error) {
				return &AgentCommandResult{Status: "ok"}, nil
			}
			chain, err := CreateRelayChain("relay", "exit")
			if err != nil || chain.Status != ChainActive {
				t.Fatal("could not establish initial active chain")
			}
			if tc.insecure {
				relayChainSecureWS = func(id string) bool { return id != "relay000001" }
			}
			syncCalls, applyCalls := 0, 0
			relayChainDispatch = func(_ string, action string, _ interface{}, _ time.Duration) (*AgentCommandResult, error) {
				if action == "chain-sync" {
					syncCalls++
					switch tc.failure {
					case "dispatch":
						return nil, errors.New("synthetic transport failure")
					case "rejected":
						return &AgentCommandResult{Status: "error"}, nil
					}
				} else if action == "chain-apply" {
					applyCalls++
				}
				return &AgentCommandResult{Status: "ok"}, nil
			}
			err = restoreRelayChainsForNode("relay000001")
			if syncCalls != tc.wantSyncCalls {
				t.Fatalf("chain-sync calls=%d want=%d", syncCalls, tc.wantSyncCalls)
			}
			if err := db.First(chain, "id = ?", chain.ID).Error; err != nil {
				t.Fatal(err)
			}
			provider, providerErr := GenerateChainNodesYAML()
			if providerErr != nil {
				t.Fatal(providerErr)
			}
			if tc.insecure || tc.failure != "" {
				wantReason := relayChainAuthoritativeSyncFailure
				if tc.insecure {
					wantReason = errRelayChainSecureWSRequired.Error()
					if !errors.Is(err, errRelayChainSecureWSRequired) {
						t.Fatal("insecure reconnect did not return the WSS error")
					}
				}
				if err == nil || applyCalls != 0 || chain.Status != ChainError || chain.LastError != wantReason ||
					strings.Contains(provider, chain.RelayIP) || strings.Contains(chain.LastError, chain.RelayPassword) ||
					strings.Contains(chain.LastError, chain.ExitPassword) {
					t.Fatal("failed authoritative sync retained or reapplied a published chain")
				}
			} else if err != nil || applyCalls != 2 || chain.Status != ChainActive || !strings.Contains(provider, chain.RelayIP) {
				t.Fatal("successful secure sync incorrectly invalidated the active chain")
			}
		})
	}
}

func TestInvalidateActiveRelayChainsForNodeLeavesOtherStatesUntouched(t *testing.T) {
	db := relayChainTestDB(t)
	rows := []database.RelayChain{
		{ID: "chain-0000000000000011", RelayInstallID: "relay000001", ExitInstallID: "exit0000001", Enabled: true, Status: ChainActive},
		{ID: "chain-0000000000000012", RelayInstallID: "other000001", ExitInstallID: "other000002", Enabled: true, Status: ChainActive},
		{ID: "chain-0000000000000013", RelayInstallID: "relay000001", ExitInstallID: "exit0000001", Enabled: true, Status: ChainPending},
		{ID: "chain-0000000000000014", RelayInstallID: "relay000001", ExitInstallID: "exit0000001", Enabled: false, Status: ChainPendingDelete},
	}
	for i := range rows {
		if err := db.Create(&rows[i]).Error; err != nil {
			t.Fatal(err)
		}
	}
	// GORM's default:true needs an explicit update for this disabled row.
	if err := db.Model(&rows[3]).UpdateColumn("enabled", false).Error; err != nil {
		t.Fatal(err)
	}
	invalidateActiveRelayChainsForNode("relay000001", relayChainAuthoritativeSyncFailure)
	want := []string{ChainError, ChainActive, ChainPending, ChainPendingDelete}
	for i := range rows {
		if err := db.First(&rows[i], "id = ?", rows[i].ID).Error; err != nil || rows[i].Status != want[i] {
			t.Fatalf("invalidated wrong chain status at %d: %v", i, err)
		}
	}
}
