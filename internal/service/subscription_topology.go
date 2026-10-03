package service

import "fmt"

type SubscriptionTopology string

const (
	TopologyChain  SubscriptionTopology = "chain"
	TopologySingle SubscriptionTopology = "single"
)

// Existing links keep their two-pool behavior. The single-provider variant
// uses only routing_type=2, matching the user's one-provider reference.
func ParseSubscriptionTopology(value string) (SubscriptionTopology, error) {
	switch value {
	case "", string(TopologyChain):
		return TopologyChain, nil
	case string(TopologySingle):
		return TopologySingle, nil
	default:
		return "", fmt.Errorf("topology 必须为 chain 或 single")
	}
}
