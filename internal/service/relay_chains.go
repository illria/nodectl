package service

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"nodectl/internal/database"
	"nodectl/internal/logger"
	"nodectl/internal/relaychain"

	"golang.org/x/mod/semver"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

const (
	ChainPending         = "pending"
	ChainActive          = "active"
	ChainError           = "error"
	ChainPendingDelete   = "pending_delete"
	chainMinAgentVersion = "v0.2.78"
	chainMinPort         = 30000
	chainMaxPort         = 49999
)

var (
	relayChainMu       sync.Mutex
	relayChainOnline   = IsNodeOnline
	relayChainDispatch = DispatchCommandToNode
)

// CreateRelayChain reuses an existing pair (including its ports and secrets).
// A temporarily offline Agent leaves the new chain pending for retry.
func CreateRelayChain(relayUUID, exitUUID string) (*database.RelayChain, error) {
	relayChainMu.Lock()
	defer relayChainMu.Unlock()

	if relayUUID == "" || exitUUID == "" || relayUUID == exitUUID {
		return nil, fmt.Errorf("中转和落地必须是两个不同的 NodeCTL 节点")
	}
	var relay, exit database.NodePool
	if err := database.DB.First(&relay, "uuid = ?", relayUUID).Error; err != nil {
		return nil, fmt.Errorf("中转节点不存在: %w", err)
	}
	if err := database.DB.First(&exit, "uuid = ?", exitUUID).Error; err != nil {
		return nil, fmt.Errorf("落地节点不存在: %w", err)
	}
	if relay.RoutingType != 1 || relay.IsBlocked || exit.RoutingType != 2 || exit.IsBlocked {
		return nil, fmt.Errorf("节点角色无效：中转必须为 routing_type=1，落地必须为 routing_type=2")
	}
	if relay.InstallID == "" || exit.InstallID == "" {
		return nil, fmt.Errorf("中转与落地都必须是 NodeCTL Agent 管理节点")
	}
	if relay.InstallID == exit.InstallID {
		return nil, fmt.Errorf("中转与落地必须由不同的 Agent 管理")
	}
	if !relayChainAgentVersionSupported(relay.AgentVersion) || !relayChainAgentVersionSupported(exit.AgentVersion) {
		return nil, fmt.Errorf("中转链要求 Relay 和 Exit Agent >= v0.2.78，请先升级 Agent")
	}
	relayIP := preferredNodeIP(relay)
	exitIP := preferredNodeIP(exit)
	if relayIP == "" || exitIP == "" {
		return nil, fmt.Errorf("两个 Agent 节点都必须先上报真实 IPv4 或 IPv6 地址")
	}

	var existing database.RelayChain
	err := database.DB.Where("relay_node_uuid = ? AND exit_node_uuid = ?", relayUUID, exitUUID).First(&existing).Error
	if err == nil {
		if existing.Status == ChainPendingDelete {
			return nil, fmt.Errorf("这条中转链仍在等待删除")
		}
		applyRelayChainLocked(&existing)
		return &existing, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	var chains []database.RelayChain
	if err := database.DB.Find(&chains).Error; err != nil {
		return nil, err
	}
	relayPort, err := allocateChainPort(relay, chains)
	if err != nil {
		return nil, err
	}
	exitPort, err := allocateChainPort(exit, chains)
	if err != nil {
		return nil, err
	}
	id, err := newChainID()
	if err != nil {
		return nil, err
	}
	relaySecret, err := newChainSecret()
	if err != nil {
		return nil, err
	}
	exitSecret, err := newChainSecret()
	if err != nil {
		return nil, err
	}
	chain := database.RelayChain{
		ID: id, RelayNodeUUID: relay.UUID, ExitNodeUUID: exit.UUID,
		RelayInstallID: relay.InstallID, ExitInstallID: exit.InstallID,
		RelayName: relay.Name, ExitName: exit.Name,
		RelayIP: relayIP, ExitIP: exitIP, Enabled: true, Status: ChainPending,
		RelayListenPort: relayPort, RelayMethod: relaychain.Method, RelayPassword: relaySecret,
		ExitListenPort: exitPort, ExitMethod: relaychain.Method, ExitPassword: exitSecret,
	}
	chain.CompositeLink = chainShareLink(chain)
	// GORM's SQL logger must not print a slow/failed INSERT containing secrets.
	if err := database.DB.Session(&gorm.Session{Logger: gormlogger.Default.LogMode(gormlogger.Silent)}).Create(&chain).Error; err != nil {
		return nil, fmt.Errorf("保存中转链失败")
	}
	applyRelayChainLocked(&chain)
	return &chain, nil
}

func ListRelayChains() ([]database.RelayChain, error) {
	var chains []database.RelayChain
	err := database.DB.Order("created_at DESC").Find(&chains).Error
	return chains, err
}

// RelayChainNodeInUse protects chain endpoints from deletion or role/address
// changes while an Agent may still have the corresponding inbound installed.
func RelayChainNodeInUse(nodeUUID string) (bool, error) {
	var count int64
	err := database.DB.Model(&database.RelayChain{}).
		Where("relay_node_uuid = ? OR exit_node_uuid = ?", nodeUUID, nodeUUID).
		Count(&count).Error
	return count > 0, err
}

func RetryRelayChain(id string) (*database.RelayChain, error) {
	relayChainMu.Lock()
	defer relayChainMu.Unlock()
	var chain database.RelayChain
	if err := database.DB.First(&chain, "id = ?", id).Error; err != nil {
		return nil, err
	}
	if chain.Status == ChainPendingDelete {
		deleteRelayChainLocked(&chain)
	} else {
		applyRelayChainLocked(&chain)
	}
	return &chain, nil
}

func DeleteRelayChain(id string) error {
	relayChainMu.Lock()
	defer relayChainMu.Unlock()
	var chain database.RelayChain
	if err := database.DB.First(&chain, "id = ?", id).Error; err != nil {
		return err
	}
	deleteRelayChainLocked(&chain)
	return nil
}

func applyRelayChainLocked(chain *database.RelayChain) {
	if chain.Status == ChainPendingDelete {
		return
	}
	if !relayChainOnline(chain.ExitInstallID) {
		setRelayChainStatus(chain, ChainPending, "Exit Agent offline")
		return
	}
	if err := sendRelayChainCommand(chain.ExitInstallID, "chain-apply", exitAgentChain(*chain)); err != nil {
		setRelayChainStatus(chain, ChainError, "Exit Agent failed to apply chain")
		return
	}
	if !relayChainOnline(chain.RelayInstallID) {
		setRelayChainStatus(chain, ChainPending, "Relay Agent offline")
		return
	}
	if err := sendRelayChainCommand(chain.RelayInstallID, "chain-apply", relayAgentChain(*chain)); err != nil {
		setRelayChainStatus(chain, ChainError, "Relay Agent failed to apply chain")
		return
	}
	setRelayChainStatus(chain, ChainActive, "")
}

func deleteRelayChainLocked(chain *database.RelayChain) {
	chain.Enabled = false
	setRelayChainStatus(chain, ChainPendingDelete, "")
	allDeleted := true
	for _, installID := range []string{chain.RelayInstallID, chain.ExitInstallID} {
		if !relayChainOnline(installID) {
			allDeleted = false
			continue
		}
		if err := sendRelayChainCommand(installID, "chain-delete", map[string]string{"id": chain.ID}); err != nil {
			allDeleted = false
		}
	}
	if !allDeleted {
		setRelayChainStatus(chain, ChainPendingDelete, "等待离线 Agent 恢复或重试删除")
		return
	}
	if err := database.DB.Delete(chain).Error; err != nil {
		setRelayChainStatus(chain, ChainPendingDelete, "删除数据库记录失败")
	}
}

func setRelayChainStatus(chain *database.RelayChain, status, message string) {
	chain.Status, chain.LastError = status, message
	if err := database.DB.Model(chain).Updates(map[string]interface{}{
		"status": status, "last_error": message, "enabled": chain.Enabled,
	}).Error; err != nil {
		logger.Log.Error("保存中转链状态失败", "chain_id", chain.ID, "status", status, "error", err)
	}
	logger.Log.Info("中转链状态", "chain_id", chain.ID, "relay_node", chain.RelayNodeUUID,
		"exit_node", chain.ExitNodeUUID, "status", status,
		"relay_port", chain.RelayListenPort, "exit_port", chain.ExitListenPort)
}

func sendRelayChainCommand(installID, action string, payload interface{}) error {
	result, err := relayChainDispatch(installID, action, payload, 90*time.Second)
	if err != nil {
		return err
	}
	if result == nil || result.Status != "ok" {
		return fmt.Errorf("Agent rejected %s", action)
	}
	return nil
}

func exitAgentChain(c database.RelayChain) relaychain.Config {
	return relaychain.Config{ID: c.ID, Role: relaychain.RoleExit,
		ListenPort: c.ExitListenPort, Method: c.ExitMethod, Password: c.ExitPassword}
}

func relayAgentChain(c database.RelayChain) relaychain.Config {
	return relaychain.Config{ID: c.ID, Role: relaychain.RoleRelay,
		ListenPort: c.RelayListenPort, Method: c.RelayMethod, Password: c.RelayPassword,
		ExitIP: c.ExitIP, ExitPort: c.ExitListenPort,
		ExitMethod: c.ExitMethod, ExitPassword: c.ExitPassword}
}

// AgentRelayChains is the complete authoritative set sent over WS chain-sync.
// Pending/error chains remain in the set: an Exit may already be configured
// before the Relay command succeeds, and a reconnect must not erase it.
func AgentRelayChains(installID string) ([]relaychain.Config, error) {
	var chains []database.RelayChain
	if err := database.DB.Where("enabled = ? AND status <> ? AND (relay_install_id = ? OR exit_install_id = ?)",
		true, ChainPendingDelete, installID, installID).Order("id ASC").Find(&chains).Error; err != nil {
		return nil, err
	}
	result := make([]relaychain.Config, 0, len(chains))
	for _, chain := range chains {
		if chain.RelayInstallID == installID {
			result = append(result, relayAgentChain(chain))
		} else {
			result = append(result, exitAgentChain(chain))
		}
	}
	return result, nil
}

// ReconcileRelayChainsForNode resumes pending work when an Agent reconnects.
func ReconcileRelayChainsForNode(installID string) {
	relayChainMu.Lock()
	defer relayChainMu.Unlock()
	var chains []database.RelayChain
	if err := database.DB.Where("(relay_install_id = ? OR exit_install_id = ?) AND status IN ?",
		installID, installID, []string{ChainPending, ChainError, ChainPendingDelete}).Find(&chains).Error; err != nil {
		logger.Log.Error("读取待恢复中转链失败", "install_id", installID, "error", err)
		return
	}
	for i := range chains {
		if chains[i].Status == ChainPendingDelete {
			deleteRelayChainLocked(&chains[i])
		} else {
			applyRelayChainLocked(&chains[i])
		}
	}
}

// ReconcileRelayChainNodeAddress follows the latest reported endpoint address.
// Relay address changes affect the client subscription only. Exit address
// changes require the Exit inbound before replacing the Relay outbound.
func ReconcileRelayChainNodeAddress(nodeUUID string) {
	relayChainMu.Lock()
	defer relayChainMu.Unlock()

	var node database.NodePool
	if err := database.DB.First(&node, "uuid = ?", nodeUUID).Error; err != nil {
		logger.Log.Error("读取中转链节点地址失败", "node_uuid", nodeUUID, "error", err)
		return
	}
	var chains []database.RelayChain
	if err := database.DB.Where("enabled = ? AND status <> ? AND (relay_node_uuid = ? OR exit_node_uuid = ?)",
		true, ChainPendingDelete, nodeUUID, nodeUUID).Find(&chains).Error; err != nil {
		logger.Log.Error("读取节点中转链失败", "node_uuid", nodeUUID, "error", err)
		return
	}
	ip := preferredNodeIP(node)
	for i := range chains {
		chain := &chains[i]
		updates := make(map[string]interface{})
		addressChanged, exitAddressChanged := false, false
		if chain.RelayNodeUUID == nodeUUID {
			if ip != "" && chain.RelayIP != ip {
				chain.RelayIP = ip
				updates["relay_ip"] = ip
				addressChanged = true
			}
			if chain.RelayName != node.Name {
				chain.RelayName = node.Name
				updates["relay_name"] = node.Name
			}
		} else {
			if ip != "" && chain.ExitIP != ip {
				chain.ExitIP = ip
				updates["exit_ip"] = ip
				addressChanged, exitAddressChanged = true, true
			}
			if chain.ExitName != node.Name {
				chain.ExitName = node.Name
				updates["exit_name"] = node.Name
			}
		}
		if len(updates) == 0 {
			continue
		}
		chain.CompositeLink = chainShareLink(*chain)
		updates["composite_link"] = chain.CompositeLink
		if exitAddressChanged {
			chain.Status, chain.LastError = ChainPending, ""
			updates["status"], updates["last_error"] = ChainPending, ""
		}
		// CompositeLink contains credentials; keep it out of GORM SQL logs and
		// database-driver error details as well as application logs.
		if err := database.DB.Session(&gorm.Session{Logger: gormlogger.Default.LogMode(gormlogger.Silent)}).Model(chain).Updates(updates).Error; err != nil {
			logger.Log.Error("保存中转链节点地址失败", "chain_id", chain.ID, "node_uuid", nodeUUID)
			continue
		}
		if addressChanged && (!relayChainOnline(chain.RelayInstallID) || !relayChainOnline(chain.ExitInstallID)) {
			setRelayChainStatus(chain, ChainPending, "等待离线 Agent 恢复后应用节点地址")
			continue
		}
		if exitAddressChanged {
			applyRelayChainLocked(chain)
		}
	}
}

func relayChainAgentVersionSupported(version string) bool {
	version = normalizeSemver(version)
	return semver.IsValid(version) && semver.Compare(version, chainMinAgentVersion) >= 0
}

func preferredNodeIP(node database.NodePool) string {
	for _, candidate := range []string{node.IPV4, strings.Trim(node.IPV6, "[]")} {
		if ip := net.ParseIP(strings.TrimSpace(candidate)); ip != nil && ip.IsGlobalUnicast() {
			return ip.String()
		}
	}
	return ""
}

func allocateChainPort(node database.NodePool, chains []database.RelayChain) (int, error) {
	used := make(map[int]bool)
	for _, port := range node.LinkPorts {
		if port > 0 {
			used[port] = true
		}
	}
	for _, link := range node.Links {
		if proxy := ParseProxyLink(link, "", "", false); proxy != nil && proxy.Port > 0 {
			used[proxy.Port] = true
		}
	}
	for _, chain := range chains {
		if chain.RelayNodeUUID == node.UUID {
			used[chain.RelayListenPort] = true
		}
		if chain.ExitNodeUUID == node.UUID {
			used[chain.ExitListenPort] = true
		}
	}
	span := chainMaxPort - chainMinPort + 1
	start, err := rand.Int(rand.Reader, big.NewInt(int64(span)))
	if err != nil {
		return 0, err
	}
	for offset := 0; offset < span; offset++ {
		port := chainMinPort + (int(start.Int64())+offset)%span
		if !used[port] {
			return port, nil
		}
	}
	return 0, fmt.Errorf("节点 %s 没有可用的中转链端口", node.UUID)
}

func newChainID() (string, error) {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "chain-" + hex.EncodeToString(bytes), nil
}

func newChainSecret() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

func chainDisplayName(chain database.RelayChain) string {
	return chain.RelayName + " → " + chain.ExitName
}

func chainShareLink(chain database.RelayChain) string {
	credentials := base64.StdEncoding.EncodeToString([]byte(chain.RelayMethod + ":" + chain.RelayPassword))
	address := net.JoinHostPort(chain.RelayIP, strconv.Itoa(chain.RelayListenPort))
	return "ss://" + credentials + "@" + address + "#" + url.PathEscape(chainDisplayName(chain))
}
