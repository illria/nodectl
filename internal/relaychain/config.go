package relaychain

import (
	"encoding/base64"
	"fmt"
	"net"
	"regexp"
	"strings"
)

const Method = "2022-blake3-aes-128-gcm"

const (
	RoleRelay = "relay"
	RoleExit  = "exit"
)

var chainIDPattern = regexp.MustCompile(`^chain-[0-9a-f]{16}$`)

// Config is one Agent's part of a server-side Shadowsocks chain.
// ExitIP must be a literal address, so the relay never resolves the exit host.
type Config struct {
	ID           string `json:"id"`
	Role         string `json:"role"`
	ListenPort   int    `json:"listen_port"`
	Method       string `json:"method"`
	Password     string `json:"password"`
	ExitIP       string `json:"exit_ip,omitempty"`
	ExitPort     int    `json:"exit_port,omitempty"`
	ExitMethod   string `json:"exit_method,omitempty"`
	ExitPassword string `json:"exit_password,omitempty"`
}

func (c Config) TagSuffix() string { return strings.TrimPrefix(c.ID, "chain-") }

func (c Config) Validate() error {
	if !chainIDPattern.MatchString(c.ID) {
		return fmt.Errorf("invalid chain ID")
	}
	if c.Role != RoleRelay && c.Role != RoleExit {
		return fmt.Errorf("invalid chain role")
	}
	if c.ListenPort < 1 || c.ListenPort > 65535 {
		return fmt.Errorf("invalid chain listen port")
	}
	if err := validateKey(c.Method, c.Password); err != nil {
		return fmt.Errorf("invalid chain inbound: %w", err)
	}
	if c.Role == RoleRelay {
		if net.ParseIP(c.ExitIP) == nil {
			return fmt.Errorf("relay exit address must be an IP literal")
		}
		if c.ExitPort < 1 || c.ExitPort > 65535 {
			return fmt.Errorf("invalid exit port")
		}
		if err := validateKey(c.ExitMethod, c.ExitPassword); err != nil {
			return fmt.Errorf("invalid chain outbound: %w", err)
		}
	}
	return nil
}

func validateKey(method, password string) error {
	if method != Method {
		return fmt.Errorf("unsupported Shadowsocks method")
	}
	key, err := base64.StdEncoding.DecodeString(password)
	if err != nil || len(key) != 16 {
		return fmt.Errorf("Shadowsocks 2022 key must be 16 random bytes in base64")
	}
	return nil
}
