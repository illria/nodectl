package service

import (
	"crypto/tls"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"nhooyr.io/websocket"
)

func TestAgentWSSecurityRequestDetection(t *testing.T) {
	for _, tc := range []struct {
		name, remoteAddr, forwardedProto, forwarded string
		tls, want                                   bool
	}{
		{name: "direct TLS", tls: true, want: true},
		{name: "TLS overrides plain proxy header", remoteAddr: "198.51.100.10:9090", tls: true, forwardedProto: "http", want: true},
		{name: "loopback HTTPS", remoteAddr: "127.0.0.1:7878", forwardedProto: "https", want: true},
		{name: "Docker bridge HTTPS", remoteAddr: "172.17.0.2:7878", forwardedProto: "https", want: true},
		{name: "private 172 range upper edge", remoteAddr: "172.31.255.254:7878", forwardedProto: "https", want: true},
		{name: "private WSS", remoteAddr: "192.168.1.2:7878", forwardedProto: "wss", want: true},
		{name: "private standard Forwarded HTTPS", remoteAddr: "10.0.0.2:7878", forwarded: "for=192.0.2.10;proto=https;host=panel.example", want: true},
		{name: "IPv6 ULA proxy HTTPS", remoteAddr: "[fd00::2]:7878", forwardedProto: "https", want: true},
		{name: "IPv6 loopback HTTPS", remoteAddr: "[::1]:7878", forwardedProto: "https", want: true},
		{name: "proxy case insensitive", forwardedProto: " HTTPS ", want: true},
		{name: "standard Forwarded HTTPS", forwarded: "for=192.0.2.10;proto=https;host=panel.example", want: true},
		{name: "quoted Forwarded protocol", forwarded: "for=192.0.2.10; Proto=\"HTTPS\"", want: true},
		{name: "public spoofed HTTPS", remoteAddr: "198.51.100.10:9090", forwardedProto: "https"},
		{name: "public spoofed Forwarded", remoteAddr: "198.51.100.10:9090", forwarded: "proto=https"},
		{name: "public spoofed WSS", remoteAddr: "198.51.100.10:9090", forwardedProto: "wss"},
		{name: "outside private 172 range", remoteAddr: "172.32.0.1:9090", forwardedProto: "https"},
		{name: "CGNAT is not trusted", remoteAddr: "100.64.0.1:9090", forwardedProto: "https"},
		{name: "public IPv6 is not trusted", remoteAddr: "[2001:db8::2]:9090", forwardedProto: "https"},
		{name: "unparseable peer", remoteAddr: "proxy.example:7878", forwardedProto: "https"},
		{name: "missing peer port", remoteAddr: "172.17.0.2", forwardedProto: "https"},
		{name: "plain WS"},
		{name: "proxy HTTP", forwardedProto: "http"},
		{name: "proxy WS", forwardedProto: "ws"},
		{name: "ambiguous proxy protocols", forwardedProto: "http, https"},
		{name: "conflicting forwarded headers", forwardedProto: "http", forwarded: "proto=https"},
		{name: "conflicting secure forwarded headers", forwardedProto: "https", forwarded: "proto=wss"},
		{name: "conflicting insecure forwarded headers", forwardedProto: "https", forwarded: "proto=http"},
		{name: "duplicate Forwarded proto", forwarded: "proto=https;proto=http"},
		{name: "standard Forwarded plain client hop", forwarded: "for=192.0.2.10;proto=http, for=192.0.2.20;proto=https"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://panel.example/api/callback/traffic/ws", nil)
			r.RemoteAddr = "127.0.0.1:7878"
			if tc.remoteAddr != "" {
				r.RemoteAddr = tc.remoteAddr
			}
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			}
			r.Header.Set("X-Forwarded-Proto", tc.forwardedProto)
			r.Header.Set("Forwarded", tc.forwarded)
			if got := isSecureAgentWSRequest(r); got != tc.want {
				t.Fatalf("secure=%v, want %v", got, tc.want)
			}
		})
	}
	r := httptest.NewRequest("GET", "http://panel.example/api/callback/traffic/ws", nil)
	r.RemoteAddr = "172.17.0.2:7878"
	r.Header.Add("X-Forwarded-Proto", "https")
	r.Header.Add("X-Forwarded-Proto", "http")
	if isSecureAgentWSRequest(r) {
		t.Fatal("multiple forwarded protocol headers were trusted")
	}
	public := httptest.NewRequest("GET", "http://panel.example/api/callback/traffic/ws", nil)
	public.RemoteAddr = "198.51.100.10:9090"
	public.Header.Set("X-Forwarded-For", "127.0.0.1")
	public.Header.Set("X-Forwarded-Proto", "https")
	if isSecureAgentWSRequest(public) {
		t.Fatal("spoofed X-Forwarded-For made a public immediate peer trusted")
	}
}

func TestAgentWSSecurityFollowsCurrentConnection(t *testing.T) {
	hub := &TrafficHub{}
	oldSecureConn, currentInsecureConn, newSecureConn := new(websocket.Conn), new(websocket.Conn), new(websocket.Conn)
	const installID = "relay000001"
	hub.registerAgentConnection(oldSecureConn, installID, true)
	if !hub.isNodeSecureWS(installID) {
		t.Fatal("secure connection was not registered")
	}
	if previous := hub.registerAgentConnection(currentInsecureConn, installID, false); previous != oldSecureConn {
		t.Fatal("replacement did not identify the old connection")
	}
	if hub.isNodeSecureWS(installID) {
		t.Fatal("insecure replacement inherited previous secure state")
	}
	if hub.unbindAgentConnectionIfCurrent(oldSecureConn, installID) || hub.agentConns[installID] != currentInsecureConn {
		t.Fatal("old disconnect removed current connection")
	}
	hub.registerAgentConnection(newSecureConn, installID, true)
	if hub.unbindAgentConnectionIfCurrent(currentInsecureConn, installID) || !hub.isNodeSecureWS(installID) {
		t.Fatal("old insecure disconnect removed new secure state")
	}
	if !hub.unbindAgentConnectionIfCurrent(newSecureConn, installID) {
		t.Fatal("current disconnect was not removed")
	}
	if hub.isNodeSecureWS(installID) || len(hub.agentConns) != 0 || len(hub.agentSecureWS) != 0 {
		t.Fatal("disconnect retained connection or security state")
	}
}

func TestAgentCommandSecretGate(t *testing.T) {
	for _, action := range []string{"chain-sync", "chain-apply"} {
		for _, state := range []string{"secure", "insecure", "offline", "stale secure flag"} {
			t.Run(action+"/"+state, func(t *testing.T) {
				hub := &TrafficHub{}
				conn := new(websocket.Conn)
				if state == "secure" || state == "insecure" {
					hub.registerAgentConnection(conn, "relay000001", state == "secure")
				}
				if state == "stale secure flag" {
					hub.agentSecureWS = map[string]bool{"relay000001": true}
				}
				dispatched := false
				err := hub.withAgentCommandConnection("relay000001", action, func(current *websocket.Conn) error {
					dispatched = true
					if current != conn {
						t.Fatal("dispatch used another connection")
					}
					return nil
				})
				if state == "secure" {
					if err != nil || !dispatched {
						t.Fatalf("secure command not dispatched: %v", err)
					}
				} else if !errors.Is(err, errRelayChainSecureWSRequired) || dispatched {
					t.Fatalf("secret dispatch was not blocked: error=%v dispatched=%v", err, dispatched)
				}
			})
		}
	}
	hub := &TrafficHub{}
	hub.registerAgentConnection(new(websocket.Conn), "relay000001", false)
	dispatched := false
	if err := hub.withAgentCommandConnection("relay000001", "chain-delete", func(*websocket.Conn) error {
		dispatched = true
		return nil
	}); err != nil || !dispatched {
		t.Fatalf("ID-only chain-delete must remain allowed on WS: %v", err)
	}
}

type secretMarshalSpy struct{ called *bool }

func (s secretMarshalSpy) MarshalJSON() ([]byte, error) {
	*s.called = true
	return []byte(`{"password":"synthetic-test-value"}`), nil
}

func TestAgentPublicCommandPathsRejectSecretsBeforeMarshaling(t *testing.T) {
	for _, action := range []string{"chain-sync", "chain-apply"} {
		for _, online := range []bool{false, true} {
			for _, async := range []bool{false, true} {
				hub := &TrafficHub{}
				if online {
					hub.registerAgentConnection(new(websocket.Conn), "relay000001", false)
				}
				marshaled := false
				payload := secretMarshalSpy{called: &marshaled}
				var err error
				if async {
					_, err = hub.fireCommandToNode("relay000001", action, payload)
				} else {
					_, err = hub.dispatchCommandToNode("relay000001", action, payload, time.Second)
				}
				if !errors.Is(err, errRelayChainSecureWSRequired) || err.Error() != "Agent secure WebSocket (WSS) required for relay chain" || marshaled {
					t.Fatalf("action=%s online=%v async=%v: error=%v marshaled=%v", action, online, async, err, marshaled)
				}
				if len(hub.cmdResults) != 0 || len(hub.cmdLogs) != 0 {
					t.Fatal("blocked command created a callback or log entry")
				}
			}
		}
	}
}

func TestAgentSecretDispatchConnectionAndSecurityAreAtomic(t *testing.T) {
	hub := &TrafficHub{}
	secureConn, insecureConn := new(websocket.Conn), new(websocket.Conn)
	hub.registerAgentConnection(secureConn, "relay000001", true)
	sending, releaseSend, sent := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		sent <- hub.withAgentCommandConnection("relay000001", "chain-sync", func(conn *websocket.Conn) error {
			if conn != secureConn {
				return errors.New("secret command selected an unexpected connection")
			}
			close(sending)
			<-releaseSend
			return nil
		})
	}()
	select {
	case <-sending:
	case <-time.After(time.Second):
		close(releaseSend)
		t.Fatal("secure dispatch did not start")
	}
	replaced := make(chan struct{})
	go func() {
		hub.registerAgentConnection(insecureConn, "relay000001", false)
		close(replaced)
	}()
	select {
	case <-replaced:
		close(releaseSend)
		t.Fatal("replacement changed connection during secret dispatch")
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseSend)
	select {
	case err := <-sent:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("secret dispatch did not finish")
	}
	select {
	case <-replaced:
	case <-time.After(time.Second):
		t.Fatal("replacement remained blocked after dispatch")
	}
	if hub.isNodeSecureWS("relay000001") || hub.agentConns["relay000001"] != insecureConn {
		t.Fatal("replacement did not install current insecure connection state")
	}
	if err := hub.withAgentCommandConnection("relay000001", "chain-apply", func(*websocket.Conn) error {
		t.Fatal("secret command used insecure replacement")
		return nil
	}); !errors.Is(err, errRelayChainSecureWSRequired) {
		t.Fatalf("insecure replacement secret command not blocked: %v", err)
	}
}
