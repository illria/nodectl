package service

import (
	"nodectl/internal/database"
	"nodectl/internal/logger"
)

const relayChainAuthoritativeSyncFailure = "Agent failed authoritative chain sync"

// Caller holds relayChainMu so a concurrent apply cannot restore active while
// the failed authoritative sync is being invalidated. No secret is read here.
func invalidateActiveRelayChainsForNode(installID, safeReason string) {
	if err := database.DB.Model(&database.RelayChain{}).
		Where("enabled = ? AND status = ? AND (relay_install_id = ? OR exit_install_id = ?)",
			true, ChainActive, installID, installID).
		Updates(map[string]interface{}{"status": ChainError, "last_error": safeReason}).Error; err != nil {
		logger.Log.Error("标记 Agent 中转链同步失败", "install_id", installID, "error", err)
	}
}

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
		invalidateActiveRelayChainsForNode(installID, errRelayChainSecureWSRequired.Error())
		return errRelayChainSecureWSRequired
	}
	chains, err := AgentRelayChains(installID)
	if err != nil {
		invalidateActiveRelayChainsForNode(installID, relayChainAuthoritativeSyncFailure)
		return err
	}
	if err := sendRelayChainCommand(installID, "chain-sync", chains); err != nil {
		invalidateActiveRelayChainsForNode(installID, relayChainAuthoritativeSyncFailure)
		return err
	}
	return nil
}

// A failed authoritative sync cannot be made healthy by individual applies on
// this same bind. The next connection retries the full set.
func restoreRelayChainsForNode(installID string) error {
	if err := SyncRelayChainsToNode(installID); err != nil {
		return err
	}
	ReconcileRelayChainsForNode(installID)
	return nil
}
