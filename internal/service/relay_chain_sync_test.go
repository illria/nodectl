package service

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"nodectl/internal/database"
	"nodectl/internal/relaychain"
)

func TestRelayChainWSSyncAuthoritativeOnEachConnection(t *testing.T) {
	db := relayChainTestDB(t)
	relayChainOnline = func(string) bool { return true }
	for i, status := range []string{ChainActive, ChainPending, ChainError, ChainPendingDelete} {
		chain := database.RelayChain{
			ID:             []string{"chain-0000000000000001", "chain-0000000000000002", "chain-0000000000000003", "chain-0000000000000004"}[i],
			RelayInstallID: "relay000001", ExitInstallID: "exit0000001", Enabled: true, Status: status,
			RelayListenPort: 31001 + i, RelayMethod: relaychain.Method, RelayPassword: "synthetic-relay-key",
			ExitIP: "203.0.113.10", ExitListenPort: 32001 + i, ExitMethod: relaychain.Method, ExitPassword: "synthetic-exit-key",
		}
		if err := db.Create(&chain).Error; err != nil {
			t.Fatal(err)
		}
	}
	disabled := database.RelayChain{ID: "chain-0000000000000005", RelayInstallID: "relay000001", ExitInstallID: "exit0000001", Enabled: false, Status: ChainActive}
	if err := db.Create(&disabled).Error; err != nil {
		t.Fatal(err)
	}
	// GORM applies the model's default:true when Create receives a zero bool.
	// Persist the disabled state explicitly, as the production delete path does.
	if err := db.Model(&disabled).UpdateColumn("enabled", false).Error; err != nil {
		t.Fatal(err)
	}
	var sets [][]relaychain.Config
	relayChainDispatch = func(id, action string, payload interface{}, _ time.Duration) (*AgentCommandResult, error) {
		if id != "relay000001" || action != "chain-sync" {
			t.Fatalf("unexpected WS command target/action: %s %s", id, action)
		}
		set, ok := payload.([]relaychain.Config)
		if !ok || set == nil {
			t.Fatal("authoritative payload must be an array, including empty []")
		}
		sets = append(sets, set)
		return &AgentCommandResult{Status: "ok"}, nil
	}
	// Every binding/reconnect invokes the same full-set sync, even for active chains.
	for range 2 {
		if err := SyncRelayChainsToNode("relay000001"); err != nil {
			t.Fatal(err)
		}
	}
	if len(sets) != 2 || len(sets[0]) != 3 || !reflect.DeepEqual(sets[0], sets[1]) {
		t.Fatal("reconnect failed to resend active/pending/error authoritative set")
	}
	for i, config := range sets[0] {
		if config.Role != relaychain.RoleRelay || config.ID != []string{"chain-0000000000000001", "chain-0000000000000002", "chain-0000000000000003"}[i] {
			t.Fatal("authoritative set included a disabled/deleting chain or wrong role")
		}
	}
	if err := db.Where("relay_install_id = ?", "relay000001").Delete(&database.RelayChain{}).Error; err != nil {
		t.Fatal(err)
	}
	if err := SyncRelayChainsToNode("relay000001"); err != nil || len(sets) != 3 || len(sets[2]) != 0 {
		t.Fatalf("empty authoritative set not dispatched: %v", err)
	}
}

func TestRelayChainWSSyncReportsDispatchFailure(t *testing.T) {
	db := relayChainTestDB(t)
	relayChainOnline = func(string) bool { return true }
	active := database.RelayChain{ID: "chain-0000000000000001", RelayInstallID: "relay000001", ExitInstallID: "exit0000001", Enabled: true, Status: ChainActive}
	deleting := database.RelayChain{ID: "chain-0000000000000002", RelayInstallID: "relay000001", ExitInstallID: "exit0000001", Enabled: false, Status: ChainPendingDelete}
	if err := db.Create(&active).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&deleting).Error; err != nil {
		t.Fatal(err)
	}
	for _, result := range []*AgentCommandResult{nil, {Status: "error"}} {
		relayChainDispatch = func(string, string, interface{}, time.Duration) (*AgentCommandResult, error) { return result, nil }
		if err := SyncRelayChainsToNode("relay000001"); err == nil {
			t.Fatal("nil/error Agent result acknowledged as successful sync")
		}
	}
	relayChainDispatch = func(string, string, interface{}, time.Duration) (*AgentCommandResult, error) {
		return nil, errors.New("synthetic offline Agent")
	}
	if err := SyncRelayChainsToNode("relay000001"); err == nil {
		t.Fatal("dispatch failure acknowledged as successful sync")
	}
	if err := db.First(&active, "id = ?", active.ID).Error; err != nil || active.Status != ChainError {
		t.Fatal("failed authoritative reload left a chain advertised as active")
	}
	if err := db.First(&deleting, "id = ?", deleting.ID).Error; err != nil || deleting.Status != ChainPendingDelete {
		t.Fatal("failed authoritative reload changed pending deletion")
	}
}
