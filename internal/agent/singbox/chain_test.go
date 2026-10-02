package singbox

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"nodectl/internal/relaychain"
)

func fakeChainKey(b byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 16))
}

func testChain(role string) relaychain.Config {
	chain := relaychain.Config{
		ID: "chain-0123456789abcdef", Role: role, ListenPort: 31000,
		Method: relaychain.Method, Password: fakeChainKey(1),
	}
	if role == relaychain.RoleRelay {
		chain.ExitIP = "203.0.113.12"
		chain.ExitPort = 32000
		chain.ExitMethod = relaychain.Method
		chain.ExitPassword = fakeChainKey(2)
	}
	return chain
}

func newChainTestManager(t *testing.T) *ConfigManager {
	t.Helper()
	dir := t.TempDir()
	return NewConfigManagerWithPaths(filepath.Join(dir, "singbox.json"), filepath.Join(dir, "protocols.json"), filepath.Join(dir, "certs"))
}

func decodedChainConfig(t *testing.T, cm *ConfigManager) struct {
	Inbounds []struct {
		Type, Tag, Method, Password string
		ListenPort                  int `json:"listen_port"`
	} `json:"inbounds"`
	Outbounds []struct {
		Type, Tag, Server, Method, Password string
		ServerPort                          int `json:"server_port"`
	} `json:"outbounds"`
	Route struct {
		Final string `json:"final"`
		Rules []struct {
			Inbound  []string `json:"inbound"`
			Action   string   `json:"action"`
			Outbound string   `json:"outbound"`
		} `json:"rules"`
	} `json:"route"`
} {
	t.Helper()
	var cfg struct {
		Inbounds []struct {
			Type, Tag, Method, Password string
			ListenPort                  int `json:"listen_port"`
		} `json:"inbounds"`
		Outbounds []struct {
			Type, Tag, Server, Method, Password string
			ServerPort                          int `json:"server_port"`
		} `json:"outbounds"`
		Route struct {
			Final string `json:"final"`
			Rules []struct {
				Inbound  []string `json:"inbound"`
				Action   string   `json:"action"`
				Outbound string   `json:"outbound"`
			} `json:"rules"`
		} `json:"route"`
	}
	data, err := cm.GenerateConfig()
	if err != nil {
		t.Fatalf("generate config: %v", err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	return cfg
}

func TestRelayChainGeneratesInboundOutboundAndRoute(t *testing.T) {
	cm := newChainTestManager(t)
	chain := testChain(relaychain.RoleRelay)
	cm.Chains = []relaychain.Config{chain}
	cfg := decodedChainConfig(t, cm)
	if len(cfg.Inbounds) != 1 || cfg.Inbounds[0].Tag != "chain-client-0123456789abcdef" ||
		cfg.Inbounds[0].Type != "shadowsocks" || cfg.Inbounds[0].ListenPort != chain.ListenPort ||
		cfg.Inbounds[0].Password != chain.Password {
		t.Fatalf("relay inbound = %#v", cfg.Inbounds)
	}
	if len(cfg.Outbounds) != 2 || cfg.Outbounds[1].Tag != "chain-out-0123456789abcdef" ||
		cfg.Outbounds[1].Type != "shadowsocks" || cfg.Outbounds[1].Server != chain.ExitIP ||
		cfg.Outbounds[1].ServerPort != chain.ExitPort || cfg.Outbounds[1].Password != chain.ExitPassword {
		t.Fatalf("relay outbound = %#v", cfg.Outbounds)
	}
	if len(cfg.Route.Rules) != 1 || !reflect.DeepEqual(cfg.Route.Rules[0].Inbound, []string{cfg.Inbounds[0].Tag}) ||
		cfg.Route.Rules[0].Action != "route" || cfg.Route.Rules[0].Outbound != cfg.Outbounds[1].Tag || cfg.Route.Final != "direct-out" {
		t.Fatalf("relay route = %#v", cfg.Route)
	}
}

func TestExitChainRoutesDirectlyWithoutOutboundSecret(t *testing.T) {
	cm := newChainTestManager(t)
	chain := testChain(relaychain.RoleExit)
	cm.Chains = []relaychain.Config{chain}
	cfg := decodedChainConfig(t, cm)
	if len(cfg.Inbounds) != 1 || cfg.Inbounds[0].Tag != "chain-exit-0123456789abcdef" || cfg.Inbounds[0].Password != chain.Password {
		t.Fatalf("exit inbound = %#v", cfg.Inbounds)
	}
	if len(cfg.Outbounds) != 1 || cfg.Outbounds[0].Tag != "direct-out" ||
		len(cfg.Route.Rules) != 1 || cfg.Route.Rules[0].Outbound != "direct-out" ||
		!reflect.DeepEqual(cfg.Route.Rules[0].Inbound, []string{cfg.Inbounds[0].Tag}) {
		t.Fatalf("exit route/outbounds = %#v %#v", cfg.Route, cfg.Outbounds)
	}
}

func TestChainsPersistAcrossManagerRestart(t *testing.T) {
	cm := newChainTestManager(t)
	chains := []relaychain.Config{testChain(relaychain.RoleRelay)}
	if err := cm.ReplaceChains(chains); err != nil {
		t.Fatalf("save chains: %v", err)
	}
	info, err := os.Stat(cm.chainsPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("chain cache permissions = %v, stat error = %v", info, err)
	}
	previous, err := cm.GenerateConfig()
	if err != nil {
		t.Fatal(err)
	}
	restarted := NewConfigManagerWithPaths(cm.configPath, cm.protocolsPath, cm.certDir)
	if err := restarted.LoadChainsFromCache(); err != nil {
		t.Fatalf("load chains: %v", err)
	}
	current, err := restarted.GenerateConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(restarted.Chains, chains) || !bytes.Equal(previous, current) {
		t.Fatal("chain state changed after manager restart")
	}
	if err := restarted.ReplaceChains(nil); err != nil {
		t.Fatalf("clear stale chains: %v", err)
	}
	if err := cm.LoadChainsFromCache(); err != nil || len(cm.Chains) != 0 {
		t.Fatalf("deleted panel chain survived cache reconciliation: %v, %#v", err, cm.Chains)
	}
}

func TestChainPortConflictsWithAgentProtocolAndOtherChain(t *testing.T) {
	cm := newChainTestManager(t)
	cm.Protocols.SetEnabled(ProtoSS, true)
	cm.Protocols.SS.Port = 31000
	cm.Chains = []relaychain.Config{testChain(relaychain.RoleRelay)}
	if _, err := cm.GenerateConfig(); err == nil {
		t.Fatal("chain port colliding with ordinary SS protocol was accepted")
	}
	cm.Protocols.SetEnabled(ProtoSS, false)
	other := testChain(relaychain.RoleExit)
	other.ID = "chain-fedcba9876543210"
	cm.Chains = append(cm.Chains, other)
	if _, err := cm.GenerateConfig(); err == nil {
		t.Fatal("duplicate chain inbound port was accepted")
	}
}
