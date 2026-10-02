package agent

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"nodectl/internal/relaychain"
)

type chainProbeTestConn struct {
	closed bool
}

func (c *chainProbeTestConn) Read([]byte) (int, error)        { return 0, io.EOF }
func (c *chainProbeTestConn) Write(p []byte) (int, error)     { return len(p), nil }
func (c *chainProbeTestConn) Close() error                    { c.closed = true; return nil }
func (c *chainProbeTestConn) LocalAddr() net.Addr             { return &net.TCPAddr{} }
func (c *chainProbeTestConn) RemoteAddr() net.Addr            { return &net.TCPAddr{} }
func (c *chainProbeTestConn) SetDeadline(time.Time) error     { return nil }
func (c *chainProbeTestConn) SetReadDeadline(time.Time) error { return nil }
func (c *chainProbeTestConn) SetWriteDeadline(time.Time) error {
	return nil
}

func TestChainApplyResultRelayProbeSuccess(t *testing.T) {
	previous := chainProbeDial
	t.Cleanup(func() { chainProbeDial = previous })
	for _, test := range []struct {
		name    string
		ip      string
		address string
	}{
		{name: "IPv4", ip: "203.0.113.10", address: "203.0.113.10:32001"},
		{name: "IPv6", ip: "2001:db8::10", address: "[2001:db8::10]:32001"},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn := &chainProbeTestConn{}
			calls := 0
			chainProbeDial = func(network, address string, timeout time.Duration) (net.Conn, error) {
				calls++
				if network != "tcp" || address != test.address || timeout != 5*time.Second {
					t.Fatalf("unexpected probe: network=%s address=%s timeout=%s", network, address, timeout)
				}
				return conn, nil
			}
			result := chainApplyResult(relaychain.Config{Role: relaychain.RoleRelay, ExitIP: test.ip, ExitPort: 32001})
			if result.Type != "result" || result.Status != "ok" {
				t.Fatalf("reachable exit must return ok: %+v", result)
			}
			if calls != 1 || !conn.closed {
				t.Fatalf("probe must dial once and close connection: calls=%d closed=%t", calls, conn.closed)
			}
		})
	}
}

func TestChainApplyResultRelayProbeFailure(t *testing.T) {
	previous := chainProbeDial
	t.Cleanup(func() { chainProbeDial = previous })
	const privateDetail = "private dial details"
	chainProbeDial = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return nil, errors.New(privateDetail)
	}
	result := chainApplyResult(relaychain.Config{Role: relaychain.RoleRelay, ExitIP: "203.0.113.10", ExitPort: 32001})
	if result.Type != "result" || result.Status != "error" {
		t.Fatalf("unreachable exit must return command error: %+v", result)
	}
	if result.Message != "Exit endpoint unreachable: 203.0.113.10:32001" {
		t.Fatalf("unexpected safe error message: %q", result.Message)
	}
	if strings.Contains(result.Message, privateDetail) {
		t.Fatalf("probe error leaked dial details: %q", result.Message)
	}
}

func TestChainApplyResultExitDoesNotProbe(t *testing.T) {
	previous := chainProbeDial
	t.Cleanup(func() { chainProbeDial = previous })
	chainProbeDial = func(string, string, time.Duration) (net.Conn, error) {
		t.Fatal("exit role must not probe another endpoint")
		return nil, nil
	}
	result := chainApplyResult(relaychain.Config{Role: relaychain.RoleExit})
	if result.Type != "result" || result.Status != "ok" {
		t.Fatalf("exit role must return ok without probe: %+v", result)
	}
}

func TestChainApplyResultNilProbeConnectionIsError(t *testing.T) {
	previous := chainProbeDial
	t.Cleanup(func() { chainProbeDial = previous })
	chainProbeDial = func(string, string, time.Duration) (net.Conn, error) { return nil, nil }
	result := chainApplyResult(relaychain.Config{Role: relaychain.RoleRelay, ExitIP: "203.0.113.10", ExitPort: 32001})
	if result.Status != "error" {
		t.Fatal("nil probe connection must not panic or acknowledge success")
	}
}
