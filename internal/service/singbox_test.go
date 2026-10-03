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
	return singBoxTestProfileWithTopology(t, TopologyChain)
}

func singBoxTestProfileWithTopology(t *testing.T, topology SubscriptionTopology) *singBoxProfile {
	t.Helper()
	// Use the real rendered template, including regions and custom rules.
	data := renderClashTemplateForTest(t, ClashTemplateData{SingleProvider: topology == TopologySingle, BaseURL: "https://panel.example", Token: "secret", ActiveModules: LoadClashModulesConfig().Modules, CustomProxies: []CustomProxyRule{{ID: "custom", Name: "Custom", Content: "example.com"}}, ProxiesInterval: "3600", RulesInterval: "300", PublicRulesInterval: "86400"})
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

func TestSingBoxIPModes(t *testing.T) {
	for _, topology := range []SubscriptionTopology{TopologyChain, TopologySingle} {
		profile := singBoxTestProfileWithTopology(t, topology)
		pool, suffix := "落地机场", ""
		if topology == TopologySingle {
			pool, suffix = "provider1", "-single"
		}
		// DNS address selection must not discard explicit IPv6 node endpoints.
		pools := map[string][]*ClashNode{pool: {
			{Name: "香港 IPv4", Type: "socks5", Server: "192.0.2.1", Port: 1080},
			{Name: "香港 IPv6", Type: "socks5", Server: "2001:db8::1", Port: 1080},
		}}
		for minor := 8; minor <= 14; minor++ {
			for _, mode := range []string{"mobile", "full", "outbounds"} {
				for _, requested := range []SingBoxIPMode{"", SingBoxIPv4Only, SingBoxDualStack} {
					data, _, err := buildSingBoxConfigWithIPMode(profile, pools, "https://panel.example", "secret", minor, mode, topology, requested)
					if err != nil {
						t.Fatal(err)
					}
					var config map[string]interface{}
					if err = json.Unmarshal(data, &config); err != nil {
						t.Fatal(err)
					}
					if !strings.Contains(string(data), "2001:db8::1") {
						t.Fatal("IPv6 node endpoint removed")
					}
					if mode == "outbounds" {
						if len(config) != 1 {
							t.Fatal("fragment includes DNS settings")
						}
						continue
					}
					resolved, err := ParseSingBoxIPMode(string(requested), mode)
					if err != nil {
						t.Fatal(err)
					}
					strategy := "prefer_ipv4"
					if resolved == SingBoxIPv4Only {
						strategy = "ipv4_only"
					}
					if config["dns"].(map[string]interface{})["strategy"] != strategy {
						t.Fatal("wrong DNS address family", mode, requested)
					}
					if minor >= 12 && resolved == SingBoxIPv4Only {
						resolver := config["route"].(map[string]interface{})["default_domain_resolver"].(map[string]interface{})
						if resolver["server"] != "dns-bootstrap" || resolver["strategy"] != "ipv4_only" {
							t.Fatal("internal direct resolution still allows IPv6")
						}
					}
					if !strings.Contains(string(data), "fdfe:dcba:9876::1/126") {
						t.Fatal("IPv6 TUN capture removed")
					}
					if dir := os.Getenv("NODECTL_SINGBOX_FIXTURES"); dir != "" && mode == "mobile" && requested == SingBoxDualStack {
						if err = os.MkdirAll(dir, 0755); err != nil {
							t.Fatal(err)
						}
						if err = os.WriteFile(filepath.Join(dir, fmt.Sprintf("1.%d%s-dual-mobile.json", minor, suffix)), data, 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			if _, _, err := buildSingBoxConfigWithIPMode(profile, pools, "", "", minor, "mobile", topology, "invalid"); err == nil {
				t.Fatal("invalid IP mode accepted")
			}
		}
	}
}

func TestSingBoxDomesticPolicy(t *testing.T) {
	p := singBoxTestProfile(t)
	pools := map[string][]*ClashNode{"落地机场": {{Name: "香港", Type: "socks5", Server: "192.0.2.1", Port: 1080}}}
	for minor := 8; minor <= 14; minor++ {
		t.Run(fmt.Sprint(minor), func(t *testing.T) {
			data, _, err := buildSingBoxConfig(p, pools, "https://panel.example", "secret", minor, "mobile")
			if err != nil {
				t.Fatal(err)
			}
			var c struct {
				Outbounds []sbObject `json:"outbounds"`
				DNS       struct {
					Final            string     `json:"final"`
					Rules            []sbObject `json:"rules"`
					IndependentCache bool       `json:"independent_cache"`
				} `json:"dns"`
				Route struct {
					Rules []sbObject `json:"rules"`
				} `json:"route"`
			}
			if err = json.Unmarshal(data, &c); err != nil {
				t.Fatal(err)
			}
			for _, ob := range c.Outbounds {
				name := ob["tag"].(string)
				if singBoxDomesticGroup(name) && ob["default"] != "🇨🇳 大陆" {
					t.Fatalf("domestic app %s defaults to proxy", name)
				}
				if name == "Google" || name == "TikTok" || name == "Custom" {
					if ob["default"] != "总模式" {
						t.Fatalf("overseas/custom selector %s was changed", name)
					}
				}
			}
			if c.DNS.Final != "dns-remote" || (minor < 14 && !c.DNS.IndependentCache) {
				t.Fatal("overseas DNS fallback or independent cache missing")
			}
			indexes := map[string]int{}
			for i, r := range c.DNS.Rules {
				if m, ok := r["clash_mode"].(string); ok {
					indexes[m] = i
				}
				if sets, ok := r["rule_set"].([]interface{}); ok {
					if r["clash_mode"] != "Rule" || r["server"] != "dns-bootstrap" {
						t.Fatal("domestic DNS scope incorrect")
					}
					indexes["domestic"] = i
					foundCN := false
					for _, set := range sets {
						name := set.(string)
						if p.Providers[name].Behavior != "domain" {
							t.Fatal("non-domain rule can expose overseas queries", name)
						}
						if name == "CN_域" {
							foundCN = true
						} else if !singBoxDomesticGroup(strings.TrimSuffix(name, "_域")) {
							t.Fatal("overseas app uses direct DNS", name)
						}
					}
					if !foundCN {
						t.Fatal("domestic DNS depends on optional app selectors")
					}
				}
			}
			if _, ok := indexes["domestic"]; !ok || indexes["domestic"] >= indexes["Rule"] || indexes["domestic"] <= indexes["Global"] || indexes["domestic"] <= indexes["Direct"] {
				t.Fatal("mode overrides / domestic DNS / fallback order incorrect", indexes)
			}
			cnRules := 0
			for _, r := range c.Route.Rules {
				for _, name := range []string{"CN_域", "CN_IP"} {
					if sets, ok := r["rule_set"].([]interface{}); ok && len(sets) == 1 && sets[0] == name {
						cnRules++
						if r["outbound"] != "🇨🇳 大陆" {
							t.Fatal("domestic fallback not direct", name)
						}
					}
				}
			}
			if cnRules != 2 {
				t.Fatal("domestic routing needs no app-specific selector")
			}
		})
	}
	if dir := os.Getenv("NODECTL_SINGBOX_FIXTURES"); dir != "" {
		source, err := convertSingBoxRuleSource([]byte("DOMAIN-SUFFIX,domestic-module.test"), "classical")
		if err != nil {
			t.Fatal(err)
		}
		binary, err := CompileSingBoxRuleSet(source)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, "domestic-module.srs"), binary, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSingBoxCompatibility(t *testing.T) {
	p := singBoxTestProfile(t)
	singleProfile := singBoxTestProfileWithTopology(t, TopologySingle)
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
					set["format"] = "binary"
					set["path"] = filepath.Join(dir, "rules.srs")
				}
				source, e := convertSingBoxRuleSource([]byte("DOMAIN-SUFFIX,example.test\nIP-CIDR,203.0.113.0/24,no-resolve\nDST-PORT,3478"), "classical")
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(filepath.Join(dir, "rules.json"), source, 0600); e != nil {
					t.Fatal(e)
				}
				compiled, e := CompileSingBoxRuleSet(source)
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(filepath.Join(dir, "rules.srs"), compiled, 0600); e != nil {
					t.Fatal(e)
				}
				data, _ = json.MarshalIndent(config, "", "  ")
				if e = os.WriteFile(filepath.Join(dir, fmt.Sprintf("1.%d.json", minor)), data, 0600); e != nil {
					t.Fatal(e)
				}
			}
			mobile, _, e := buildSingBoxConfig(p, pools, "https://panel.example", "secret", minor, "mobile")
			if e != nil {
				t.Fatal(e)
			}
			var mobileConfig map[string]interface{}
			if e = json.Unmarshal(mobile, &mobileConfig); e != nil {
				t.Fatal(e)
			}
			inputs := mobileConfig["inbounds"].([]interface{})
			if len(inputs) != 1 || inputs[0].(map[string]interface{})["type"] != "tun" {
				t.Fatal("mobile lacks VPN TUN")
			}
			for _, mode := range []string{"Rule", "Global", "Direct"} {
				if !strings.Contains(string(mobile), `"clash_mode": "`+mode+`"`) {
					t.Fatal("missing native client mode", mode)
				}
			}
			if mobileConfig["experimental"].(map[string]interface{})["clash_api"].(map[string]interface{})["default_mode"] != "Rule" {
				t.Fatal("missing default Rule mode")
			}
			if strings.Contains(string(mobile), "external_controller") {
				t.Fatal("mobile opens desktop control port")
			}
			if dir := os.Getenv("NODECTL_SINGBOX_FIXTURES"); dir != "" {
				if e = os.WriteFile(filepath.Join(dir, fmt.Sprintf("1.%d-mobile.json", minor)), mobile, 0600); e != nil {
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
			for _, mode := range []string{"full", "mobile", "outbounds"} {
				single, _, err := buildSingBoxConfigWithTopology(singleProfile, map[string][]*ClashNode{"provider1": nodes, "中转机场": pools["中转机场"]}, "https://panel.example", "secret", minor, mode, TopologySingle)
				if err != nil {
					t.Fatal(err)
				}
				for _, forbidden := range []string{"中转策略", "中转关闭", "中转 · ", "192.0.2.20"} {
					if strings.Contains(string(single), forbidden) {
						t.Fatal("single provider exported relay", forbidden)
					}
				}
				var c map[string]any
				if err = json.Unmarshal(single, &c); err != nil {
					t.Fatal(err)
				}
				for _, value := range c["outbounds"].([]any) {
					ob := value.(map[string]any)
					if _, isNode := ob["server"]; isNode {
						if _, hasDetour := ob["detour"]; hasDetour {
							t.Fatal("single-pool node still chains through another outbound")
						}
					}
				}
				if mode == "outbounds" && len(c) != 1 {
					t.Fatal("single fragment includes runtime settings")
				}
				if dir := os.Getenv("NODECTL_SINGBOX_FIXTURES"); dir != "" && mode != "outbounds" {
					name := fmt.Sprintf("1.%d-single-mobile.json", minor)
					if mode == "full" {
						name = fmt.Sprintf("1.%d-single.json", minor)
						for _, value := range c["route"].(map[string]any)["rule_set"].([]any) {
							set := value.(map[string]any)
							tag := set["tag"]
							for key := range set {
								delete(set, key)
							}
							set["tag"], set["type"], set["format"], set["path"] = tag, "local", "binary", filepath.Join(dir, "rules.srs")
						}
						single, _ = json.MarshalIndent(c, "", "  ")
					}
					if err = os.WriteFile(filepath.Join(dir, name), single, 0600); err != nil {
						t.Fatal(err)
					}
				}
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
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "::1", "::ffff:127.0.0.1", "169.254.169.254", "100.100.100.200", "198.18.0.1", "fc00::1", "0.0.0.0"} {
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
		compiled, e := CompileSingBoxRuleSet(result)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, name+".srs"), compiled, 0600); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, name+".json"), result, 0600); e != nil {
			t.Fatal(e)
		}
	}
}

func TestSingBoxCompactionPreservesConditions(t *testing.T) {
	source, e := convertSingBoxRuleSource([]byte("DOMAIN,a.test\nDOMAIN,b.test\nIP-CIDR,203.0.113.0/24\nDST-PORT,3478"), "classical")
	if e != nil {
		t.Fatal(e)
	}
	var doc struct {
		Rules []sbObject `json:"rules"`
	}
	if e = json.Unmarshal(source, &doc); e != nil {
		t.Fatal(e)
	}
	if len(doc.Rules) != 3 {
		t.Fatal("different match classes merged into AND or domains not compacted")
	}
	binary, e := CompileSingBoxRuleSet(source)
	if e != nil {
		t.Fatal(e)
	}
	if string(binary[:4]) != "SRS\x01" {
		t.Fatal("binary format newer than oldest supported core")
	}
	if _, e = CompileSingBoxRuleSet([]byte(`{"version":1,"rules":[{"unsupported":true}]}`)); e == nil {
		t.Fatal("unknown field silently lost")
	}
}

func TestSingBoxLargeRuleFixture(t *testing.T) {
	path := os.Getenv("NODECTL_SINGBOX_LARGE_SOURCE")
	if path == "" {
		t.Skip("no large upstream source")
	}
	data, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	source, e := convertSingBoxRuleSource(data, "domain")
	if e != nil {
		t.Fatal(e)
	}
	var doc struct {
		Rules []sbObject `json:"rules"`
	}
	if e = json.Unmarshal(source, &doc); e != nil {
		t.Fatal(e)
	}
	if len(doc.Rules) > 3 {
		t.Fatal("large domains generated separate per-domain matchers")
	}
	compiled, e := CompileSingBoxRuleSet(source)
	if e != nil {
		t.Fatal(e)
	}
	dir := os.Getenv("NODECTL_SINGBOX_FIXTURES")
	if dir != "" {
		if e = os.WriteFile(filepath.Join(dir, "cn.srs"), compiled, 0600); e != nil {
			t.Fatal(e)
		}
	}
}
