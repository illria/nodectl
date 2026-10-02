package agent

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"nodectl/internal/agent/singbox"
	"nodectl/internal/relaychain"
)

func commandTestChain(role string) relaychain.Config {
	return relaychain.Config{
		ID: "chain-0123456789abcdef", Role: role, ListenPort: 31001,
		Method: relaychain.Method, Password: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16)),
		ExitIP: "203.0.113.10", ExitPort: 32001, ExitMethod: relaychain.Method,
		ExitPassword: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 16)),
	}
}

// The real cache and JSON generation are exercised; only process installation
// and reload are replaced so unit tests never launch sing-box or use the network.
func chainCommandTestRuntime(t *testing.T) (*Runtime, *singbox.ConfigManager, string) {
	t.Helper()
	dir := t.TempDir()
	cm := singbox.NewConfigManagerWithPaths(filepath.Join(dir, "singbox-config.json"), filepath.Join(dir, "protocols.json"), filepath.Join(dir, "certs"))
	rt := &Runtime{singboxMgr: singbox.NewManagerWithConfig(cm, nil)}
	oldApply := chainSetApply
	chainSetApply = func(runtime *Runtime, chains []relaychain.Config) error {
		manager := runtime.ensureSingboxManager().GetConfigManager()
		if err := manager.ReplaceChains(chains); err != nil {
			return err
		}
		return manager.GenerateAndSave()
	}
	t.Cleanup(func() { chainSetApply = oldApply })
	return rt, cm, dir
}

func runChainTestCommand(t *testing.T, rt *Runtime, action string, payload interface{}) CommandResult {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var replies []CommandResult
	rt.handleCommand(ServerCommand{Action: action, Payload: raw}, func(result CommandResult) { replies = append(replies, result) })
	if len(replies) != 2 || replies[0].Type != "accepted" || replies[1].Type != "result" {
		t.Fatalf("unexpected command lifecycle: %#v", replies)
	}
	return replies[1]
}

func TestChainSyncReplacesCompleteSetAndClearsStaleConfig(t *testing.T) {
	rt, cm, dir := chainCommandTestRuntime(t)
	stale := commandTestChain(relaychain.RoleExit)
	stale.ID = "chain-aaaaaaaaaaaaaaaa"
	stale.ListenPort = 33001
	if err := cm.ReplaceChains([]relaychain.Config{stale}); err != nil {
		t.Fatal(err)
	}
	authoritative := []relaychain.Config{commandTestChain(relaychain.RoleRelay), commandTestChain(relaychain.RoleExit)}
	authoritative[1].ID = "chain-bbbbbbbbbbbbbbbb"
	authoritative[1].ListenPort = 33002
	for _, set := range [][]relaychain.Config{authoritative, {}} {
		result := runChainTestCommand(t, rt, "chain-sync", set)
		if result.Status != "ok" || !reflect.DeepEqual(cm.Chains, append([]relaychain.Config(nil), set...)) {
			t.Fatalf("complete replacement failed: status=%s count=%d", result.Status, len(cm.Chains))
		}
		restarted := singbox.NewConfigManagerWithPaths(cm.GetConfigPath(), filepath.Join(dir, "protocols.json"), filepath.Join(dir, "certs"))
		if err := restarted.LoadChainsFromCache(); err != nil || !reflect.DeepEqual(restarted.Chains, cm.Chains) {
			t.Fatalf("cache differs after restart: %v", err)
		}
		for _, filename := range []string{"chains.json", "singbox-config.json"} {
			info, err := os.Stat(filepath.Join(dir, filename))
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("%s permissions invalid: %v", filename, err)
			}
		}
		data, err := os.ReadFile(cm.GetConfigPath())
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(stale.TagSuffix())) {
			t.Fatal("stale chain survived authoritative replacement")
		}
		if len(set) == 0 && (bytes.Contains(data, []byte("chain-client-")) || bytes.Contains(data, []byte("chain-exit-")) || bytes.Contains(data, []byte("chain-out-")) || bytes.Contains(data, []byte(`"route"`))) {
			t.Fatal("empty sync retained chain inbound/outbound/routes")
		}
	}
}

func TestChainSyncRejectsInvalidSetAndReportsReloadFailure(t *testing.T) {
	rt, cm, _ := chainCommandTestRuntime(t)
	for _, payload := range []interface{}{nil, map[string]string{"id": "bad"}, []relaychain.Config{{ID: "invalid"}}} {
		if result := runChainTestCommand(t, rt, "chain-sync", payload); result.Status != "error" || len(cm.Chains) != 0 {
			t.Fatal("invalid authoritative set was accepted")
		}
	}
	chainSetApply = func(*Runtime, []relaychain.Config) error { return errors.New("reload failed") }
	if result := runChainTestCommand(t, rt, "chain-sync", []relaychain.Config{commandTestChain(relaychain.RoleExit)}); result.Status != "error" {
		t.Fatal("failed reload was acknowledged as successful")
	}
}

func TestChainApplyProbeCommandStatuses(t *testing.T) {
	rt, cm, _ := chainCommandTestRuntime(t)
	oldDial := chainProbeDial
	t.Cleanup(func() { chainProbeDial = oldDial })
	for _, reachable := range []bool{false, true} {
		chainProbeDial = func(string, string, time.Duration) (net.Conn, error) {
			if !reachable {
				return nil, errors.New("synthetic blocked TCP port")
			}
			conn, peer := net.Pipe()
			peer.Close()
			return conn, nil
		}
		chain := commandTestChain(relaychain.RoleRelay)
		result := runChainTestCommand(t, rt, "chain-apply", chain)
		want := "error"
		if reachable {
			want = "ok"
		}
		if result.Status != want || len(cm.Chains) != 1 || cm.Chains[0] != chain {
			t.Fatalf("probe reachable=%v result=%s count=%d", reachable, result.Status, len(cm.Chains))
		}
		if bytes.Contains([]byte(result.Message), []byte(chain.Password)) || bytes.Contains([]byte(result.Message), []byte(chain.ExitPassword)) {
			t.Fatal("command result exposed chain credentials")
		}
	}
}

func TestChainApplySameConfigProbesAgain(t *testing.T) {
	rt, cm, _ := chainCommandTestRuntime(t)
	oldDial := chainProbeDial
	t.Cleanup(func() { chainProbeDial = oldDial })
	probeCalls := 0
	chainProbeDial = func(network, address string, timeout time.Duration) (net.Conn, error) {
		probeCalls++
		conn, peer := net.Pipe()
		_ = peer.Close()
		return conn, nil
	}
	chain := commandTestChain(relaychain.RoleRelay)
	for range 2 {
		if result := runChainTestCommand(t, rt, "chain-apply", chain); result.Status != "ok" {
			t.Fatal("identical chain-apply did not acknowledge its probe")
		}
	}
	if probeCalls != 2 || len(cm.Chains) != 1 || cm.Chains[0] != chain {
		t.Fatalf("repeat apply skipped Relay probe or changed chain: probes=%d count=%d", probeCalls, len(cm.Chains))
	}
}
