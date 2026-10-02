package service

import "nodectl/internal/database"

// SyncRelayChainsToNode sends a complete authoritative set on every WS bind,
// including active chains and an empty array after the final chain is removed.
// Serialize snapshot + dispatch with CRUD/reconciliation so an older snapshot
// cannot overwrite a newer chain-apply or chain-delete command.
func SyncRelayChainsToNode(installID string) error {
	relayChainMu.Lock()
	defer relayChainMu.Unlock()

	// Check before loading the private set. The dispatcher checks the current
	// connection again while holding agentMu through the write.
	if !relayChainOnline(installID) || !relayChainSecureWS(installID) {
		return errRelayChainSecureWSRequired
	}
	chains, err := AgentRelayChains(installID)
	if err != nil {
		return err
	}
	if err := sendRelayChainCommand(installID, "chain-sync", chains); err != nil {
		// A lost cache or failed reload must not leave an un-restored chain
		// advertised as active. The bind caller retries these through the normal
		// Exit -> Relay apply path, including the Relay connectivity probe.
		var active []database.RelayChain
		if database.DB.Where("enabled = ? AND status = ? AND (relay_install_id = ? OR exit_install_id = ?)",
			true, ChainActive, installID, installID).Find(&active).Error == nil {
			for i := range active {
				setRelayChainStatus(&active[i], ChainError, "Agent failed to sync chain set")
			}
		}
		return err
	}
	return nil
}
