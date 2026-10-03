package service

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func singBoxTestProfile(t *testing.T) *singBoxProfile {
	t.Helper()
	// Use the real rendered template, including regions and custom rules.
	data := renderClashTemplateForTest(t, ClashTemplateData{BaseURL: "https://panel.example", Token: "secret", ActiveModules: LoadClashModulesConfig().Modules, CustomProxies: []CustomProxyRule{{ID: "custom", Name: "Custom", Content: "example.com"}}, ProxiesInterval: "3600", RulesInterval: "300", PublicRulesInterval: "86400"})
	var p singBoxProfile
	if e := yaml.Unmarshal(data, &p); e != nil {
		t.Fatal(e)
	}
	p.Providers["CN_域"] = singBoxProvider{URL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.list", Behavior: "domain"}
	p.Providers["CN_IP"] = singBoxProvider{URL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.list", Behavior: "ipcidr"}
	return &p
}

func TestSingBoxVersions(t *testing.T) {
	for _, version := range []string{"", "1.8", "v1.14.2", "1.12.25"} {
		if _, e := SingBoxMinor(version); e != nil {
			t.Error(e)
		}
	}
	for _, version := range []string{"1.7", "1.15", "2.0", "1.14-alpha", "1.8.xyz", "1.14.2.3"} {
		if _, e := SingBoxMinor(version); e == nil {
			t.Errorf("accepted %s", version)
		}
	}
}

func TestSingBoxCompatibility(t *testing.T) {
	p := singBoxTestProfile(t)
	alter := 0
	nodes := []*ClashNode{
		{Name: "香港 VLESS", Type: "vless", Server: "proxy.example", Port: 443, UUID: "00000000-0000-4000-8000-000000000001", TLS: true, Network: "ws", WSOpts: map[string]interface{}{"path": "/ws", "headers": map[string]interface{}{"Host": "proxy.example"}}},
		{Name: "日本 VMess", Type: "vmess", Server: "192.0.2.1", Port: 443, UUID: "00000000-0000-4000-8000-000000000002", Cipher: "auto", AlterId: &alter, TLS: true, Network: "grpc", GRPCOpts: map[string]interface{}{"grpc-service-name": "proxy"}},
		{Name: "美国 Trojan", Type: "trojan", Server: "192.0.2.2", Port: 443, Password: "test"},
		{Name: "香港 SS", Type: "ss", Server: "192.0.2.3", Port: 443, Cipher: "aes-128-gcm", Password: "test"},
		{Name: "香港 Hy2", Type: "hysteria2", Server: "192.0.2.4", Port: 443, Password: "test", Obfs: "salamander", ObfsPassword: "test"},
		{Name: "香港 Hy1", Type: "hysteria", Server: "192.0.2.5", Port: 443, AuthStr: "test"},
		{Name: "香港 TUIC", Type: "tuic", Server: "192.0.2.6", Port: 443, UUID: "00000000-0000-4000-8000-000000000003", Password: "test", CongestionController: "bbr", UDPRelayMode: "native"},
		{Name: "香港 AnyTLS", Type: "anytls", Server: "proxy.example", Port: 443, Password: "test"},
		{Name: "香港 SOCKS", Type: "socks5", Server: "192.0.2.7", Port: 1080, Username: "user", Password: "test"},
		{Name: "香港 HTTP", Type: "http", Server: "192.0.2.8", Port: 8080, Username: "user", Password: "test"},
		{Name: "香港 HTTPUpgrade", Type: "vless", Server: "192.0.2.9", Port: 443, UUID: "00000000-0000-4000-8000-000000000004", TLS: true, Network: "ws", WSOpts: map[string]interface{}{"path": "/upgrade", "v2ray-http-upgrade": true, "headers": map[string]interface{}{"Host": "proxy.example"}}},
		{Name: "香港 HTTP transport", Type: "vmess", Server: "192.0.2.10", Port: 443, UUID: "00000000-0000-4000-8000-000000000005", Network: "http", HTTPOpts: map[string]interface{}{"path": []interface{}{"/"}, "headers": map[string]interface{}{"Host": []interface{}{"proxy.example"}}}},
		{Name: "香港 QUIC", Type: "vmess", Server: "192.0.2.11", Port: 443, UUID: "00000000-0000-4000-8000-000000000006", Network: "quic", TLS: true},
		{Name: "香港 Reality", Type: "vless", Server: "192.0.2.13", Port: 443, UUID: "00000000-0000-4000-8000-000000000007", TLS: true, ServerName: "www.example.com", Flow: "xtls-rprx-vision", ClientFingerprint: "chrome", RealityOpts: map[string]interface{}{"public-key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "short-id": "0123456789abcdef"}},
		{Name: "香港 SSR", Type: "ssr", Server: "192.0.2.12", Port: 443},
	}
	pools := map[string][]*ClashNode{"落地机场": nodes, "中转机场": {{Name: "中转", Type: "socks5", Server: "192.0.2.20", Port: 1080}}}
	for minor := 8; minor <= 14; minor++ {
		t.Run(fmt.Sprint(minor), func(t *testing.T) {
			data, warnings, e := buildSingBoxConfig(p, pools, "https://panel.example", "secret", minor, "full")
			if e != nil {
				t.Fatal(e)
			}
			if len(warnings) == 0 {
				t.Fatal("unsupported SSR was not reported")
			}
			var config map[string]interface{}
			if e = json.Unmarshal(data, &config); e != nil {
				t.Fatal(e)
			}
			encoded := string(data)
			if strings.Contains(encoded, `"action": "resolve"`) {
				t.Fatal("IP rules trigger DNS resolution")
			}
			if minor >= 12 && strings.Contains(encoded, `"address": "https://`) {
				t.Fatal("legacy DNS in modern config")
			}
			if minor >= 13 && (strings.Contains(encoded, `"type": "block"`) || strings.Contains(encoded, `"type": "dns"`)) {
				t.Fatal("removed special outbounds")
			}
			if minor < 12 && strings.Contains(encoded, `"type": "anytls"`) {
				t.Fatal("AnyTLS on old core")
			}
			if dir := os.Getenv("NODECTL_SINGBOX_FIXTURES"); dir != "" {
				if e = os.MkdirAll(dir, 0755); e != nil {
					t.Fatal(e)
				}
				// Core check should be independent of panel/network availability.
				route := config["route"].(map[string]interface{})
				for _, v := range route["rule_set"].([]interface{}) {
					set := v.(map[string]interface{})
					tag := set["tag"]
					for k := range set {
						delete(set, k)
					}
					set["tag"] = tag
					set["type"] = "local"
					set["format"] = "source"
					set["path"] = filepath.Join(dir, "rules.json")
				}
				source, e := convertSingBoxRuleSource([]byte("DOMAIN-SUFFIX,example.test\nIP-CIDR,203.0.113.0/24,no-resolve\nDST-PORT,3478"), "classical")
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(filepath.Join(dir, "rules.json"), source, 0600); e != nil {
					t.Fatal(e)
				}
				data, _ = json.MarshalIndent(config, "", "  ")
				if e = os.WriteFile(filepath.Join(dir, fmt.Sprintf("1.%d.json", minor)), data, 0600); e != nil {
					t.Fatal(e)
				}
			}
			fragment, _, e := buildSingBoxConfig(p, pools, "https://panel.example", "secret", minor, "outbounds")
			if e != nil {
				t.Fatal(e)
			}
			if strings.Contains(string(fragment), "dns-bootstrap") || strings.Contains(string(fragment), `"route"`) {
				t.Fatal("fragment references absent DNS/route")
			}
		})
	}
	if _, _, e := buildSingBoxConfig(p, map[string][]*ClashNode{}, "https://panel.example", "secret", 14, "full"); e == nil {
		t.Fatal("empty landing silently fell back to direct")
	}
}

func TestSingBoxRuleConversion(t *testing.T) {
	for _, input := range []struct{ behavior, text string }{{"domain", "+.example.com\n.example.net\nexact.test\n*.wild.test"}, {"ipcidr", "203.0.113.0/24\n2001:db8::/32"}, {"classical", "# upstream comment\npayload:\n - DOMAIN-SUFFIX,example.com\n - IP-CIDR,203.0.113.0/24,no-resolve\n - DST-PORT,1000-2000\n"}} {
		result, e := convertSingBoxRuleSource([]byte(input.text), input.behavior)
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(string(result), "resolve") {
			t.Fatal("rule set emits resolve action")
		}
	}
	for _, line := range []string{"AND,((DOMAIN,a),(IP-CIDR,1.1.1.1/32))", "IP-CIDR,invalid", "DST-PORT,99999", "DOMAIN,a,PROXY"} {
		if _, e := singBoxRule(line, "classical"); e == nil {
			t.Fatalf("silently accepted %s", line)
		}
	}
	rule, e := singBoxRule("+.example.com", "domain")
	if e != nil {
		t.Fatal(e)
	}
	if rule["domain_suffix"].([]string)[0] != ".example.com" || rule["domain"].([]string)[0] != "example.com" {
		t.Fatal("domain suffix semantics differ on old cores")
	}
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "::1", "::ffff:127.0.0.1", "169.254.169.254", "fc00::1", "0.0.0.0"} {
		if publicRuleAddress(netip.MustParseAddr(ip)) {
			t.Fatal("SSRF accepted", ip)
		}
	}
}

// Optional upstream samples are downloaded by the local compatibility check.
func TestSingBoxUpstreamRuleSamples(t *testing.T) {
	dir := os.Getenv("NODECTL_SINGBOX_RULE_SAMPLES")
	if dir == "" {
		t.Skip("no downloaded upstream samples")
	}
	for name, behavior := range map[string]string{"webrtc": "classical", "ads": "domain", "cn-domain": "domain", "cn-ip": "ipcidr", "google-domain": "domain", "google-ip": "ipcidr", "crypto": "domain"} {
		data, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil {
			t.Fatal(e)
		}
		result, e := convertSingBoxRuleSource(data, behavior)
		if e != nil {
			t.Fatalf("%s: %v", name, e)
		}
		if e = os.WriteFile(filepath.Join(dir, name+".json"), result, 0600); e != nil {
			t.Fatal(e)
		}
	}
}
