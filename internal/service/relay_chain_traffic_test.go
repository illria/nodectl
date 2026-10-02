package service

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"nodectl/internal/database"
	"nodectl/internal/relaychain"
)

func TestRelayChainTrafficHandlersReconcileAddressAsynchronously(t *testing.T) {
	for _, handler := range []string{"node_online", "links_update"} {
		for _, address := range []string{"ipv4", "ipv6"} {
			t.Run(handler+"/"+address, func(t *testing.T) {
				db := relayChainTestDB(t)
				addRelayChainTestNodes(t, db)
				oldGeoIP := GlobalGeoIP
				GlobalGeoIP = nil
				t.Cleanup(func() { GlobalGeoIP = oldGeoIP })

				newIP := "203.0.113.60"
				payload := map[string]string{"ipv4": newIP}
				if address == "ipv6" {
					if err := db.Model(&database.NodePool{}).Where("uuid = ?", "exit").UpdateColumns(map[string]interface{}{
						"ipv4": "", "ipv6": "2001:db8::10",
					}).Error; err != nil {
						t.Fatal(err)
					}
					newIP = "2001:db8::20"
					payload = map[string]string{"ipv6": "[" + newIP + "]"}
				}
				relayChainOnline = func(string) bool { return true }
				relayChainDispatch = func(string, string, interface{}, time.Duration) (*AgentCommandResult, error) {
					return &AgentCommandResult{Status: "ok"}, nil
				}
				chain, err := CreateRelayChain("relay", "exit")
				if err != nil {
					t.Fatal(err)
				}
				before := *chain
				commands := make(chan chainCommand, 4)
				relayChainDispatch = func(id, action string, payload interface{}, _ time.Duration) (*AgentCommandResult, error) {
					config, ok := payload.(relaychain.Config)
					if !ok {
						return nil, errors.New("unexpected chain payload type")
					}
					select {
					case commands <- chainCommand{installID: id, action: action, chain: config}:
						return &AgentCommandResult{Status: "ok"}, nil
					default:
						return nil, errors.New("unexpected extra chain command")
					}
				}
				rawPayload, err := json.Marshal(payload)
				if err != nil {
					t.Fatal(err)
				}
				msg := wsMessage{Type: handler, InstallID: "exit0000001", Payload: rawPayload}
				hub := &TrafficHub{}
				handlerDone := make(chan struct{})
				relayChainMu.Lock()
				lockHeld := true
				defer func() {
					if lockHeld {
						relayChainMu.Unlock()
					}
				}()
				go func() {
					defer close(handlerDone)
					if handler == "node_online" {
						hub.handleNodeOnline(msg, "203.0.113.60")
					} else {
						hub.handleLinksUpdate(msg, "203.0.113.60")
					}
				}()
				returnedWhileLocked := false
				select {
				case <-handlerDone:
					returnedWhileLocked = true
				case <-time.After(2 * time.Second):
					t.Error("WS handler blocked on relayChainMu instead of scheduling address reconcile")
				}
				if returnedWhileLocked {
					var node database.NodePool
					if err := db.First(&node, "uuid = ?", "exit").Error; err != nil || preferredNodeIP(node) != newIP {
						t.Errorf("handler returned before saving the reported address: %v", err)
					}
					if len(commands) != 0 {
						t.Error("chain dispatch bypassed relayChainMu")
					}
				}
				relayChainMu.Unlock()
				lockHeld = false
				// The timeout path also allows an incorrectly synchronous handler
				// to finish before fixture globals can be restored.
				select {
				case <-handlerDone:
				case <-time.After(5 * time.Second):
					t.Fatal("WS handler did not finish after releasing relayChainMu")
				}
				var applied []chainCommand
				for len(applied) < 2 {
					select {
					case command := <-commands:
						applied = append(applied, command)
					case <-time.After(5 * time.Second):
						t.Fatal("handler did not schedule complete Exit address reconcile")
					}
				}
				// The final dispatch happens inside relayChainMu. Acquiring it
				// here waits for the background status save and all global reads.
				relayChainMu.Lock()
				relayChainMu.Unlock()
				if applied[0].installID != "exit0000001" || applied[0].action != "chain-apply" || applied[0].chain.Role != relaychain.RoleExit ||
					applied[1].installID != "relay000001" || applied[1].action != "chain-apply" ||
					applied[1].chain.Role != relaychain.RoleRelay || applied[1].chain.ExitIP != newIP {
					t.Error("handler reconcile did not apply Exit then Relay with the new Exit address")
				}
				if err := db.First(chain, "id = ?", chain.ID).Error; err != nil || chain.ExitIP != newIP || chain.Status != ChainActive {
					t.Fatalf("handler reconcile did not persist the active updated chain: %v", err)
				}
				assertRelayChainIdentityUnchanged(t, before, *chain)
			})
		}
	}
}
