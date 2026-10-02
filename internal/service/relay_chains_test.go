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
	oldDB, oldLog, oldOnline, oldDispatch := database.DB, logger.Log, relayChainOnline, relayChainDispatch
	database.DB = db
	logger.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Cleanup(func() {
		database.DB, logger.Log = oldDB, oldLog
		relayChainOnline, relayChainDispatch = oldOnline, oldDispatch
	})
	return db
}

func addRelayChainTestNodes(t *testing.T, db *gorm.DB) {
	t.Helper()
	for _, node := range []database.NodePool{
		{UUID: "relay", InstallID: "relay000001", Name: "Relay", IPV4: "198.51.100.10", RoutingType: 1,
			LinkPorts: map[string]int{"ss": 31000}, Links: map[string]string{"ss": "ss://YWVzLTEyOC1nY206c2VjcmV0@198.51.100.10:31001#test"}},
		{UUID: "exit", InstallID: "exit0000001", Name: "Exit", IPV4: "203.0.113.20", RoutingType: 2,
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
