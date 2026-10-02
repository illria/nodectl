package service

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"nodectl/internal/database"
	"nodectl/internal/logger"
	"nodectl/internal/relaychain"

	"github.com/glebarez/sqlite"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func relayChainTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "relay-chains.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	if err := db.AutoMigrate(&database.NodePool{}, &database.RelayChain{}); err != nil {
		t.Fatalf("migrate test database: %v", err)
	}
	oldDB, oldLog, oldOnline, oldDispatch, oldSecure := database.DB, logger.Log, relayChainOnline, relayChainDispatch, relayChainSecureWS
	database.DB = db
	relayChainSecureWS = func(string) bool { return true }
	logger.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Cleanup(func() {
		database.DB, logger.Log = oldDB, oldLog
		relayChainOnline, relayChainDispatch, relayChainSecureWS = oldOnline, oldDispatch, oldSecure
	})
	return db
}

func addRelayChainTestNodes(t *testing.T, db *gorm.DB) {
	t.Helper()
	for _, node := range []database.NodePool{
		{UUID: "relay", InstallID: "relay000001", AgentVersion: "v0.2.78", Name: "Relay", IPV4: "198.51.100.10", RoutingType: 1,
			LinkPorts: map[string]int{"ss": 31000}, Links: map[string]string{"ss": "ss://YWVzLTEyOC1nY206c2VjcmV0@198.51.100.10:31001#test"}},
		{UUID: "exit", InstallID: "exit0000001", AgentVersion: "v0.2.78", Name: "Exit", IPV4: "203.0.113.20", RoutingType: 2,
			LinkPorts: map[string]int{"ss": 32000}},
	} {
		if err := db.Create(&node).Error; err != nil {
			t.Fatalf("create node: %v", err)
		}
	}
}

type chainCommand struct {
	installID string
	action    string
	chain     relaychain.Config
}

func TestRelayChainCreateApplyIdempotentAndPrivate(t *testing.T) {
	db := relayChainTestDB(t)
	addRelayChainTestNodes(t, db)
	relayChainOnline = func(string) bool { return true }
	var commands []chainCommand
	relayChainDispatch = func(id, action string, payload interface{}, _ time.Duration) (*AgentCommandResult, error) {
		commands = append(commands, chainCommand{installID: id, action: action, chain: payload.(relaychain.Config)})
		return &AgentCommandResult{Status: "ok"}, nil
	}
	chain, err := CreateRelayChain("relay", "exit")
	if err != nil {
		t.Fatalf("create chain: %v", err)
	}
	if chain.Status != ChainActive || len(commands) != 2 || commands[0].installID != "exit0000001" ||
		commands[0].chain.Role != relaychain.RoleExit || commands[1].installID != "relay000001" ||
		commands[1].chain.Role != relaychain.RoleRelay {
		t.Fatalf("unexpected apply order/status: %q %#v", chain.Status, commands)
	}
	for _, cmd := range commands {
		if err := cmd.chain.Validate(); err != nil {
			t.Fatalf("invalid %s config: %v", cmd.chain.Role, err)
		}
	}
	if chain.RelayListenPort == 31000 || chain.RelayListenPort == 31001 || chain.ExitListenPort == 32000 {
		t.Fatalf("allocated occupied port: relay=%d exit=%d", chain.RelayListenPort, chain.ExitListenPort)
	}
	if !strings.HasPrefix(chain.CompositeLink, "ss://") || !strings.Contains(chain.CompositeLink, "198.51.100.10:") {
		t.Fatalf("invalid composite link")
	}
	again, err := CreateRelayChain("relay", "exit")
	if err != nil || again.ID != chain.ID || again.RelayPassword != chain.RelayPassword ||
		again.ExitPassword != chain.ExitPassword || again.RelayListenPort != chain.RelayListenPort {
		t.Fatalf("idempotent create changed chain: %v, %#v", err, again)
	}
	var count int64
	if err := db.Model(&database.RelayChain{}).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("chain rows = %d, error = %v", count, err)
	}
	publicJSON, err := json.Marshal(chain)
	if err != nil || strings.Contains(string(publicJSON), chain.RelayPassword) ||
		strings.Contains(string(publicJSON), chain.ExitPassword) || strings.Contains(string(publicJSON), chain.CompositeLink) {
		t.Fatalf("chain secrets leaked in ordinary API JSON: %v", err)
	}
	configs, err := AgentRelayChains("exit0000001")
	if err != nil || len(configs) != 1 || configs[0].Role != relaychain.RoleExit || configs[0].ExitPassword != "" {
		t.Fatalf("exit received wrong private config: %v %#v", err, configs)
	}
}

func TestRelayChainRetryAndPendingDeleteReconcile(t *testing.T) {
	db := relayChainTestDB(t)
	addRelayChainTestNodes(t, db)
	online := map[string]bool{"exit0000001": false, "relay000001": false}
	relayChainOnline = func(id string) bool { return online[id] }
	var commands []chainCommand
	relayChainDispatch = func(id, action string, payload interface{}, _ time.Duration) (*AgentCommandResult, error) {
		commands = append(commands, chainCommand{installID: id, action: action})
		return &AgentCommandResult{Status: "ok"}, nil
	}
	chain, err := CreateRelayChain("relay", "exit")
	if err != nil || chain.Status != ChainPending || len(commands) != 0 {
		t.Fatalf("offline create = %v, %#v, calls=%d", err, chain, len(commands))
	}
	online["exit0000001"] = true
	ReconcileRelayChainsForNode("exit0000001")
	if err := db.First(chain, "id = ?", chain.ID).Error; err != nil || chain.Status != ChainPending || len(commands) != 1 || commands[0].installID != "exit0000001" {
		t.Fatalf("partial apply = %v, %#v, calls=%#v", err, chain, commands)
	}
	configs, err := AgentRelayChains("exit0000001")
	if err != nil || len(configs) != 1 {
		t.Fatalf("pending Exit disappeared from startup authority: %v %#v", err, configs)
	}
	online["relay000001"] = true
	if _, err := RetryRelayChain(chain.ID); err != nil {
		t.Fatalf("retry chain: %v", err)
	}
	if err := db.First(chain, "id = ?", chain.ID).Error; err != nil || chain.Status != ChainActive {
		t.Fatalf("retry status = %v, %q", err, chain.Status)
	}
	online["relay000001"] = false
	if err := DeleteRelayChain(chain.ID); err != nil {
		t.Fatalf("delete chain: %v", err)
	}
	if err := db.First(chain, "id = ?", chain.ID).Error; err != nil || chain.Status != ChainPendingDelete || chain.Enabled {
		t.Fatalf("pending delete = %v, %#v", err, chain)
	}
	configs, err = AgentRelayChains("exit0000001")
	if err != nil || len(configs) != 0 {
		t.Fatalf("deleted chain remains in startup authority: %v %#v", err, configs)
	}
	online["relay000001"] = true
	ReconcileRelayChainsForNode("relay000001")
	var count int64
	if err := db.Model(&database.RelayChain{}).Where("id = ?", chain.ID).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("pending delete did not finish: rows=%d err=%v", count, err)
	}
}

func TestRelayChainApplyFailureAndInvalidRole(t *testing.T) {
	db := relayChainTestDB(t)
	addRelayChainTestNodes(t, db)
	if _, err := CreateRelayChain("exit", "relay"); err == nil {
		t.Fatal("reversed routing roles accepted")
	}
	if err := db.Model(&database.NodePool{}).Where("uuid = ?", "relay").Update("routing_type", 0).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := CreateRelayChain("relay", "exit"); err == nil {
		t.Fatal("disabled node accepted as relay")
	}
	if err := db.Model(&database.NodePool{}).Where("uuid = ?", "relay").Update("routing_type", 1).Error; err != nil {
		t.Fatal(err)
	}
	relayChainOnline = func(string) bool { return true }
	var actions []string
	relayChainDispatch = func(id, action string, _ interface{}, _ time.Duration) (*AgentCommandResult, error) {
		actions = append(actions, id+":"+action)
		if id == "exit0000001" {
			return nil, errors.New("agent unavailable")
		}
		return &AgentCommandResult{Status: "ok"}, nil
	}
	chain, err := CreateRelayChain("relay", "exit")
	if err != nil || chain.Status != ChainError || len(actions) != 1 || !strings.HasPrefix(actions[0], "exit0000001:") {
		t.Fatalf("exit failure continued to relay: %v %#v %#v", err, chain, actions)
	}
	relayChainDispatch = func(id, action string, _ interface{}, _ time.Duration) (*AgentCommandResult, error) {
		return &AgentCommandResult{Status: "ok"}, nil
	}
	if retried, err := RetryRelayChain(chain.ID); err != nil || retried.Status != ChainActive {
		t.Fatalf("retry after Agent error: %v %#v", err, retried)
	}
}

func TestAllocateChainPortChecksNodeAndExistingChains(t *testing.T) {
	occupied := make(map[string]int, chainMaxPort-chainMinPort)
	for port := chainMinPort; port <= chainMaxPort; port++ {
		if port != chainMaxPort {
			occupied[strconv.Itoa(port)] = port
		}
	}
	node := database.NodePool{UUID: "relay", LinkPorts: occupied}
	port, err := allocateChainPort(node, nil)
	if err != nil || port != chainMaxPort {
		t.Fatalf("only free port = %d, error = %v", port, err)
	}
	if _, err := allocateChainPort(node, []database.RelayChain{{RelayNodeUUID: "relay", RelayListenPort: chainMaxPort}}); err == nil {
		t.Fatal("port already used by another chain was reused")
	}
}

func TestRelayChainAgentVersionGate(t *testing.T) {
	for _, endpoint := range []string{"relay", "exit"} {
		for _, tc := range []struct {
			version string
			allowed bool
		}{
			{"", false}, {"dev", false}, {"0.2.9", false}, {"0.2.77", false}, {"v0.2.77", false},
			{"v0.2.78-alpha", false}, {"0.2.78", true}, {"v0.2.78", true}, {"v0.2.79", true}, {"v0.3.0", true},
		} {
			t.Run(endpoint+"/"+tc.version, func(t *testing.T) {
				db := relayChainTestDB(t)
				addRelayChainTestNodes(t, db)
				if err := db.Model(&database.NodePool{}).Where("uuid = ?", endpoint).Update("agent_version", tc.version).Error; err != nil {
					t.Fatal(err)
				}
				relayChainOnline = func(string) bool { return false }
				relayChainDispatch = func(string, string, interface{}, time.Duration) (*AgentCommandResult, error) {
					t.Fatal("version gate test must not dispatch to offline Agents")
					return nil, errors.New("unexpected dispatch")
				}
				chain, err := CreateRelayChain("relay", "exit")
				if tc.allowed {
					if err != nil || chain == nil || chain.Status != ChainPending {
						t.Fatalf("supported %s version %q rejected: %v", endpoint, tc.version, err)
					}
					return
				}
				if err == nil || err.Error() != "中转链要求 Relay 和 Exit Agent >= v0.2.78，请先升级 Agent" || chain != nil {
					t.Fatalf("unsupported %s version %q accepted or wrong error: %v", endpoint, tc.version, err)
				}
				var count int64
				if err := db.Model(&database.RelayChain{}).Count(&count).Error; err != nil || count != 0 {
					t.Fatalf("version rejection created chain rows: count=%d err=%v", count, err)
				}
			})
		}
	}
}

func assertRelayChainIdentityUnchanged(t *testing.T, before, after database.RelayChain) {
	t.Helper()
	if before.ID != after.ID || before.RelayListenPort != after.RelayListenPort || before.ExitListenPort != after.ExitListenPort ||
		before.RelayPassword != after.RelayPassword || before.ExitPassword != after.ExitPassword ||
		before.RelayMethod != after.RelayMethod || before.ExitMethod != after.ExitMethod {
		t.Fatal("reconcile/retry changed chain ID, ports, methods, or secrets")
	}
}

func TestRelayChainRelayAddressDriftUpdatesSubscription(t *testing.T) {
	db := relayChainTestDB(t)
	addRelayChainTestNodes(t, db)
	relayChainOnline = func(string) bool { return true }
	var commands []chainCommand
	relayChainDispatch = func(id, action string, payload interface{}, _ time.Duration) (*AgentCommandResult, error) {
		commands = append(commands, chainCommand{installID: id, action: action, chain: payload.(relaychain.Config)})
		return &AgentCommandResult{Status: "ok"}, nil
	}
	chain, err := CreateRelayChain("relay", "exit")
	if err != nil {
		t.Fatal(err)
	}
	before := *chain
	commands = nil
	if err := db.Model(&database.NodePool{}).Where("uuid = ?", "relay").UpdateColumns(map[string]interface{}{
		"ipv4": "198.51.100.30", "name": "Relay moved",
	}).Error; err != nil {
		t.Fatal(err)
	}
	ReconcileRelayChainNodeAddress("relay")
	if err := db.First(chain, "id = ?", chain.ID).Error; err != nil {
		t.Fatal(err)
	}
	assertRelayChainIdentityUnchanged(t, before, *chain)
	if chain.RelayIP != "198.51.100.30" || chain.RelayName != "Relay moved" || chain.ExitIP != before.ExitIP ||
		chain.Status != ChainActive || !strings.Contains(chain.CompositeLink, "@198.51.100.30:") || len(commands) != 0 {
		t.Fatal("Relay drift did not update only its published address/name")
	}
	output, err := GenerateChainNodesYAML()
	if err != nil {
		t.Fatal(err)
	}
	var provider ClashProvider
	if err := yaml.Unmarshal([]byte(output), &provider); err != nil {
		t.Fatal(err)
	}
	if len(provider.Proxies) != 1 || provider.Proxies[0].Server != chain.RelayIP || provider.Proxies[0].Name != "Relay moved → Exit" {
		t.Fatalf("composite subscription still has stale address/name")
	}
}

func TestRelayChainExitAddressDriftReappliesExitBeforeRelay(t *testing.T) {
	db := relayChainTestDB(t)
	addRelayChainTestNodes(t, db)
	relayChainOnline = func(string) bool { return true }
	var commands []chainCommand
	relayChainDispatch = func(id, action string, payload interface{}, _ time.Duration) (*AgentCommandResult, error) {
		commands = append(commands, chainCommand{installID: id, action: action, chain: payload.(relaychain.Config)})
		return &AgentCommandResult{Status: "ok"}, nil
	}
	chain, err := CreateRelayChain("relay", "exit")
	if err != nil {
		t.Fatal(err)
	}
	before := *chain
	commands = nil
	if err := db.Model(&database.NodePool{}).Where("uuid = ?", "exit").UpdateColumns(map[string]interface{}{
		"ipv4": "203.0.113.40", "name": "Exit moved",
	}).Error; err != nil {
		t.Fatal(err)
	}
	relayChainDispatch = func(id, action string, payload interface{}, _ time.Duration) (*AgentCommandResult, error) {
		var persisted database.RelayChain
		if err := db.First(&persisted, "id = ?", chain.ID).Error; err != nil || persisted.Status != ChainPending || persisted.ExitIP != "203.0.113.40" {
			t.Fatal("Exit drift must be persisted as pending before dispatch")
		}
		commands = append(commands, chainCommand{installID: id, action: action, chain: payload.(relaychain.Config)})
		return &AgentCommandResult{Status: "ok"}, nil
	}
	ReconcileRelayChainNodeAddress("exit")
	if err := db.First(chain, "id = ?", chain.ID).Error; err != nil {
		t.Fatal(err)
	}
	assertRelayChainIdentityUnchanged(t, before, *chain)
	if chain.ExitIP != "203.0.113.40" || chain.ExitName != "Exit moved" || chain.RelayIP != before.RelayIP || chain.Status != ChainActive ||
		chain.CompositeLink != chainShareLink(*chain) || len(commands) != 2 || commands[0].installID != chain.ExitInstallID ||
		commands[0].chain.Role != relaychain.RoleExit || commands[1].installID != chain.RelayInstallID ||
		commands[1].chain.Role != relaychain.RoleRelay || commands[1].chain.ExitIP != chain.ExitIP {
		t.Fatal("Exit drift did not apply Exit before Relay with the new outbound address")
	}
}

func TestRelayChainAddressDriftWaitsForEitherOfflineEndpoint(t *testing.T) {
	for _, offlineID := range []string{"relay000001", "exit0000001"} {
		t.Run(offlineID, func(t *testing.T) {
			db := relayChainTestDB(t)
			addRelayChainTestNodes(t, db)
			online := map[string]bool{"relay000001": true, "exit0000001": true}
			relayChainOnline = func(id string) bool { return online[id] }
			var commands []chainCommand
			relayChainDispatch = func(id, action string, payload interface{}, _ time.Duration) (*AgentCommandResult, error) {
				commands = append(commands, chainCommand{installID: id, action: action, chain: payload.(relaychain.Config)})
				return &AgentCommandResult{Status: "ok"}, nil
			}
			chain, err := CreateRelayChain("relay", "exit")
			if err != nil {
				t.Fatal(err)
			}
			before := *chain
			commands = nil
			online[offlineID] = false
			if err := db.Model(&database.NodePool{}).Where("uuid = ?", "exit").Update("ipv4", "203.0.113.50").Error; err != nil {
				t.Fatal(err)
			}
			ReconcileRelayChainNodeAddress("exit")
			if err := db.First(chain, "id = ?", chain.ID).Error; err != nil || chain.Status != ChainPending || chain.ExitIP != "203.0.113.50" || len(commands) != 0 {
				t.Fatalf("offline endpoint drift should remain pending without dispatch: %v", err)
			}
			assertRelayChainIdentityUnchanged(t, before, *chain)
			online[offlineID] = true
			ReconcileRelayChainsForNode(offlineID)
			if err := db.First(chain, "id = ?", chain.ID).Error; err != nil || chain.Status != ChainActive || len(commands) != 2 ||
				commands[0].chain.Role != relaychain.RoleExit || commands[1].chain.Role != relaychain.RoleRelay || commands[1].chain.ExitIP != chain.ExitIP {
				t.Fatalf("reconnect did not complete address drift recovery: %v", err)
			}
			assertRelayChainIdentityUnchanged(t, before, *chain)
		})
	}
}

func TestRelayChainRelayProbeRejectionRemainsErrorUntilRetry(t *testing.T) {
	db := relayChainTestDB(t)
	addRelayChainTestNodes(t, db)
	relayChainOnline = func(string) bool { return true }
	probeFails := true
	var commands []chainCommand
	relayChainDispatch = func(id, action string, payload interface{}, _ time.Duration) (*AgentCommandResult, error) {
		commands = append(commands, chainCommand{installID: id, action: action, chain: payload.(relaychain.Config)})
		if id == "relay000001" && probeFails {
			return &AgentCommandResult{Status: "error"}, nil
		}
		return &AgentCommandResult{Status: "ok"}, nil
	}
	chain, err := CreateRelayChain("relay", "exit")
	if err != nil || chain == nil || chain.Status != ChainError || len(commands) != 2 {
		t.Fatalf("Relay command failure did not prevent active: %v", err)
	}
	before := *chain
	var persisted database.RelayChain
	if err := db.First(&persisted, "id = ?", chain.ID).Error; err != nil || persisted.Status != ChainError {
		t.Fatalf("Relay failure state not persisted: %v", err)
	}
	probeFails = false
	retried, err := RetryRelayChain(chain.ID)
	if err != nil || retried.Status != ChainActive {
		t.Fatalf("successful retry did not activate chain: %v", err)
	}
	assertRelayChainIdentityUnchanged(t, before, *retried)
}
