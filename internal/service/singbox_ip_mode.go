package service

import "fmt"

type SingBoxIPMode string

const (
	SingBoxIPv4Only  SingBoxIPMode = "ipv4"
	SingBoxDualStack SingBoxIPMode = "dual"
)

// Mobile clients often capture IPv6 in TUN on a Wi-Fi network without an IPv6
// default route. PreferIPv4 still returns AAAA answers; use IPv4Only by default.
// Keep dual-stack TUN capture so native IPv6 cannot bypass the VPN.
func ParseSingBoxIPMode(value, mode string) (SingBoxIPMode, error) {
	if value == "" {
		if mode == "" || mode == "mobile" {
			return SingBoxIPv4Only, nil
		}
		return SingBoxDualStack, nil
	}
	switch SingBoxIPMode(value) {
	case SingBoxIPv4Only, SingBoxDualStack:
		return SingBoxIPMode(value), nil
	default:
		return "", fmt.Errorf("ip 必须为 ipv4 或 dual")
	}
}
