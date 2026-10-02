package service

import (
	"bytes"

	"nodectl/internal/database"

	"gopkg.in/yaml.v3"
)

// GenerateChainNodesYAML publishes only successful composite client entries.
// The Exit Agent's hidden inbound never appears in a user subscription.
func GenerateChainNodesYAML() (string, error) {
	var chains []database.RelayChain
	if err := database.DB.Where("enabled = ? AND status = ?", true, ChainActive).
		Order("relay_name ASC, exit_name ASC, id ASC").Find(&chains).Error; err != nil {
		return "", err
	}
	proxies := make([]*ClashNode, 0, len(chains))
	for _, chain := range chains {
		var relay, exit database.NodePool
		if database.DB.First(&relay, "uuid = ?", chain.RelayNodeUUID).Error != nil ||
			database.DB.First(&exit, "uuid = ?", chain.ExitNodeUUID).Error != nil ||
			relay.RoutingType != 1 || exit.RoutingType != 2 || relay.IsBlocked || exit.IsBlocked ||
			shouldExcludeNodeByTrafficThreshold(&relay) || shouldExcludeNodeByTrafficThreshold(&exit) {
			continue
		}
		proxies = append(proxies, &ClashNode{
			Name: chainDisplayName(chain), Type: "ss", Server: chain.RelayIP,
			Port: chain.RelayListenPort, Cipher: chain.RelayMethod,
			Password: chain.RelayPassword, UDP: true,
		})
	}
	if len(proxies) == 0 {
		proxies = append(proxies, &ClashNode{Name: "⚠️ 无中转链-自动直连", Type: "direct", UDP: true})
	}
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(ClashProvider{Proxies: proxies}); err != nil {
		return "", err
	}
	if err := encoder.Close(); err != nil {
		return "", err
	}
	return output.String(), nil
}
