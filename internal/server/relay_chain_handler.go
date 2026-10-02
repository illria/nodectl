package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"nodectl/internal/database"
	"nodectl/internal/service"
)

func apiRelayChainOptions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var nodes []database.NodePool
	if err := database.DB.Where("routing_type IN ? AND is_blocked = ?", []int{1, 2}, false).
		Order("name ASC").Find(&nodes).Error; err != nil {
		sendJSON(w, "error", "读取节点失败")
		return
	}
	options := make([]map[string]interface{}, 0, len(nodes))
	for _, node := range nodes {
		if node.InstallID == "" {
			continue
		}
		options = append(options, map[string]interface{}{
			"uuid": node.UUID, "name": node.Name, "routing_type": node.RoutingType,
			"ipv4": node.IPV4, "ipv6": node.IPV6, "agent_version": node.AgentVersion,
		})
	}
	sendJSON(w, "success", map[string]interface{}{"nodes": options})
}

func apiRelayChainList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	chains, err := service.ListRelayChains()
	if err != nil {
		sendJSON(w, "error", "读取中转链失败")
		return
	}
	sendJSON(w, "success", map[string]interface{}{"chains": chains})
}

func relayChainRequestID(w http.ResponseWriter, r *http.Request) (string, error) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		return "", err
	}
	return strings.TrimSpace(req.ID), nil
}

func apiRelayChainCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		RelayUUID string `json:"relay_uuid"`
		ExitUUID  string `json:"exit_uuid"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		sendJSON(w, "error", "请求格式错误")
		return
	}
	chain, err := service.CreateRelayChain(strings.TrimSpace(req.RelayUUID), strings.TrimSpace(req.ExitUUID))
	if err != nil {
		sendJSON(w, "error", err.Error())
		return
	}
	sendJSON(w, "success", map[string]interface{}{"chain": chain})
}

func apiRelayChainRetry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := relayChainRequestID(w, r)
	if err != nil || id == "" {
		sendJSON(w, "error", "中转链 ID 无效")
		return
	}
	chain, err := service.RetryRelayChain(id)
	if err != nil {
		sendJSON(w, "error", err.Error())
		return
	}
	sendJSON(w, "success", map[string]interface{}{"chain": chain})
}

func apiRelayChainDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := relayChainRequestID(w, r)
	if err != nil || id == "" {
		sendJSON(w, "error", "中转链 ID 无效")
		return
	}
	if err := service.DeleteRelayChain(id); err != nil {
		sendJSON(w, "error", err.Error())
		return
	}
	sendJSON(w, "success", "删除命令已处理；离线 Agent 将在重连后继续清理")
}
