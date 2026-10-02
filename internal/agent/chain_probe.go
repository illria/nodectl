package agent

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"nodectl/internal/relaychain"
)

var chainProbeDial = net.DialTimeout

// chainApplyResult checks relay-to-exit reachability after the configuration has
// been applied. The TCP probe does not authenticate the Shadowsocks endpoint.
func chainApplyResult(chain relaychain.Config) CommandResult {
	if chain.Role == relaychain.RoleRelay {
		address := net.JoinHostPort(chain.ExitIP, strconv.Itoa(chain.ExitPort))
		conn, err := chainProbeDial("tcp", address, 5*time.Second)
		if err != nil || conn == nil {
			// The dial error may contain untrusted details; only report the endpoint.
			return CommandResult{Type: "result", Status: "error", Message: fmt.Sprintf("Exit endpoint unreachable: %s", address)}
		}
		_ = conn.Close()
	}
	return CommandResult{Type: "result", Status: "ok", Message: "中转链配置已应用"}
}
