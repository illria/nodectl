package service

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

type sbObject = map[string]interface{}

type singBoxProfile struct {
	Groups []struct {
		Name    string   `yaml:"name"`
		Type    string   `yaml:"type"`
		Proxies []string `yaml:"proxies"`
		Use     []string `yaml:"use"`
		Filter  string   `yaml:"filter"`
	} `yaml:"proxy-groups"`
	Providers map[string]singBoxProvider `yaml:"rule-providers"`
	Rules     []string                   `yaml:"rules"`
}
type singBoxProvider struct {
	URL      string `yaml:"url"`
	Behavior string `yaml:"behavior"`
	Format   string `yaml:"format"`
}

// Domestic app selectors default to direct, not the overseas catch-all selector.
// Keep this specific to sing-box; do not change the user's verified Clash template.
func singBoxDomesticGroup(name string) bool {
	switch name {
	case "小红书", "抖音", "BiliBili":
		return true
	}
	return false
}

// SingBoxMinor rejects untested future schemas rather than emitting a best-effort config.
func SingBoxMinor(version string) (int, error) {
	if version == "" {
		version = "1.14"
	}
	if !regexp.MustCompile(`^v?1\.(8|9|10|11|12|13|14)(\.\d+)?$`).MatchString(version) {
		return 0, fmt.Errorf("支持 sing-box 1.8～1.14，请填写内核版本（例如 1.12.25）")
	}
	parts := strings.Split(strings.TrimPrefix(version, "v"), ".")
	minor, _ := strconv.Atoi(parts[1])
	return minor, nil
}

func loadSingBoxProfile(baseURL, token string) (*singBoxProfile, error) {
	return loadSingBoxProfileWithTopology(baseURL, token, TopologyChain)
}

func loadSingBoxProfileWithTopology(baseURL, token string, topology SubscriptionTopology) (*singBoxProfile, error) {
	text, err := RenderClashConfigWithTopology("", "", baseURL, token, topology)
	if err != nil {
		return nil, err
	}
	var p singBoxProfile
	if err = yaml.Unmarshal([]byte(text), &p); err != nil {
		return nil, err
	}
	p.Providers["CN_域"] = singBoxProvider{URL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.list", Behavior: "domain"}
	p.Providers["CN_IP"] = singBoxProvider{URL: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.list", Behavior: "ipcidr"}
	return &p, nil
}

// GenerateSingBoxConfig shares node collection and routing policy with the Clash exporter.
func GenerateSingBoxConfig(baseURL, token, version, mode string, useFlag bool) ([]byte, []string, error) {
	return GenerateSingBoxConfigWithTopology(baseURL, token, version, mode, useFlag, TopologyChain)
}

func GenerateSingBoxConfigWithTopology(baseURL, token, version, mode string, useFlag bool, topology SubscriptionTopology) ([]byte, []string, error) {
	return GenerateSingBoxConfigWithIPMode(baseURL, token, version, mode, useFlag, topology, "")
}

func GenerateSingBoxConfigWithIPMode(baseURL, token, version, mode string, useFlag bool, topology SubscriptionTopology, ipMode SingBoxIPMode) ([]byte, []string, error) {
	if _, err := ParseSubscriptionTopology(string(topology)); err != nil {
		return nil, nil, err
	}
	minor, err := SingBoxMinor(version)
	if err != nil {
		return nil, nil, err
	}
	if mode == "" {
		mode = "mobile"
	}
	if mode != "full" && mode != "mobile" && mode != "outbounds" {
		return nil, nil, fmt.Errorf("mode 必须为 mobile、full 或 outbounds")
	}
	pools := map[string][]*ClashNode{}
	for _, pool := range []struct {
		name    string
		routing int
	}{{"中转机场", 1}, {"落地机场", 2}} {
		if topology == TopologySingle && pool.routing == 1 {
			continue
		}
		raw, e := GenerateRawNodesYAML(pool.routing, useFlag)
		if e != nil {
			return nil, nil, e
		}
		var provider ClashProvider
		if e = yaml.Unmarshal([]byte(raw), &provider); e != nil {
			return nil, nil, e
		}
		poolName := pool.name
		if topology == TopologySingle {
			poolName = "provider1"
		}
		pools[poolName] = provider.Proxies
	}
	p, err := loadSingBoxProfileWithTopology(baseURL, token, topology)
	if err != nil {
		return nil, nil, err
	}
	return buildSingBoxConfigWithIPMode(p, pools, baseURL, token, minor, mode, topology, ipMode)
}

func buildSingBoxConfig(p *singBoxProfile, pools map[string][]*ClashNode, baseURL, token string, minor int, mode string) ([]byte, []string, error) {
	return buildSingBoxConfigWithTopology(p, pools, baseURL, token, minor, mode, TopologyChain)
}

func buildSingBoxConfigWithTopology(p *singBoxProfile, pools map[string][]*ClashNode, baseURL, token string, minor int, mode string, topology SubscriptionTopology) ([]byte, []string, error) {
	return buildSingBoxConfigWithIPMode(p, pools, baseURL, token, minor, mode, topology, "")
}

func buildSingBoxConfigWithIPMode(p *singBoxProfile, pools map[string][]*ClashNode, baseURL, token string, minor int, mode string, topology SubscriptionTopology, ipMode SingBoxIPMode) ([]byte, []string, error) {
	ipMode, err := ParseSingBoxIPMode(string(ipMode), mode)
	if err != nil {
		return nil, nil, err
	}
	out := []sbObject{{"type": "direct", "tag": "🇨🇳 大陆"}}
	landingPool, bootstrapDetour := "落地机场", "中转关闭"
	poolNames := []string{"中转机场", "落地机场"}
	if topology == TopologySingle {
		landingPool, bootstrapDetour = "provider1", "🇨🇳 大陆"
		poolNames = []string{landingPool}
	} else {
		out = append(out, sbObject{"type": "direct", "tag": "中转关闭"})
	}
	reserved := map[string]bool{"🇨🇳 大陆": true, "中转关闭": true, "dns-out": true, "block": true}
	for _, g := range p.Groups {
		if reserved[g.Name] {
			return nil, nil, fmt.Errorf("策略组名称重复: %s", g.Name)
		}
		reserved[g.Name] = true
	}
	poolTags := map[string][]string{}
	originalNames := map[string]string{}
	var warnings []string
	for _, pool := range poolNames {
		nodes := append([]*ClashNode(nil), pools[pool]...)
		sort.SliceStable(nodes, func(i, j int) bool {
			return fmt.Sprintf("%s/%s/%s/%d", nodes[i].Name, nodes[i].Type, nodes[i].Server, nodes[i].Port) < fmt.Sprintf("%s/%s/%s/%d", nodes[j].Name, nodes[j].Type, nodes[j].Server, nodes[j].Port)
		})
		for _, n := range nodes {
			if n.Type == "direct" {
				continue
			}
			ob, e := singBoxOutbound(n, minor)
			if e != nil {
				warnings = append(warnings, fmt.Sprintf("%s: %s", n.Name, e))
				continue
			}
			prefix := "落地 · "
			if topology == TopologySingle {
				prefix = "节点 · "
			}
			if pool == "中转机场" {
				prefix = "中转 · "
			}
			tag := prefix + n.Name
			for suffix := 2; reserved[tag]; suffix++ {
				tag = fmt.Sprintf("%s%s (%d)", prefix, n.Name, suffix)
			}
			reserved[tag] = true
			ob["tag"] = tag
			if topology != TopologySingle && pool == landingPool {
				ob["detour"] = "💠 中转策略"
			}
			out = append(out, ob)
			poolTags[pool] = append(poolTags[pool], tag)
			originalNames[tag] = n.Name
		}
	}
	if len(poolTags[landingPool]) == 0 {
		return nil, warnings, fmt.Errorf("没有适用于 sing-box 1.%d 的落地节点，请配置落地节点或选择其他内核版本", minor)
	}
	// Determine available region groups from actual compatible nodes; no empty selectors.
	available := map[string]bool{"🇨🇳 大陆": true, "中转关闭": true}
	if topology == TopologySingle {
		delete(available, "中转关闭")
	}
	groupNodes := map[string][]string{}
	for _, g := range p.Groups {
		var filter *regexp.Regexp
		if g.Filter != "" {
			var e error
			filter, e = regexp.Compile(g.Filter)
			if e != nil {
				return nil, warnings, fmt.Errorf("策略组 %s 的筛选表达式无效", g.Name)
			}
		}
		for _, pool := range g.Use {
			for _, tag := range poolTags[pool] {
				if filter == nil || filter.MatchString(originalNames[tag]) {
					groupNodes[g.Name] = append(groupNodes[g.Name], tag)
				}
			}
		}
		available[g.Name] = g.Filter == "" || len(groupNodes[g.Name]) > 0
	}
	for _, g := range p.Groups {
		if !available[g.Name] {
			continue
		}
		tags := []string{}
		seen := map[string]bool{}
		for _, tag := range append(append([]string{}, g.Proxies...), groupNodes[g.Name]...) {
			if tag == "DIRECT" {
				tag = "🇨🇳 大陆"
			}
			if (available[tag] || originalNames[tag] != "") && !seen[tag] {
				tags = append(tags, tag)
				seen[tag] = true
			}
		}
		if len(tags) == 0 {
			return nil, warnings, fmt.Errorf("策略组 %s 没有可用选项", g.Name)
		}
		kind := "selector"
		if g.Type == "url-test" {
			kind = "urltest"
		}
		ob := sbObject{"type": kind, "tag": g.Name, "outbounds": tags}
		if kind == "urltest" {
			ob["url"] = "https://www.gstatic.com/generate_204"
			ob["interval"] = "5m"
			ob["tolerance"] = 50
		} else {
			ob["default"] = tags[0]
			if singBoxDomesticGroup(g.Name) && seen["🇨🇳 大陆"] {
				ob["default"] = "🇨🇳 大陆"
			}
		}
		out = append(out, ob)
	}
	if mode == "outbounds" {
		for _, ob := range out {
			delete(ob, "domain_resolver")
		}
		data, e := json.MarshalIndent(sbObject{"outbounds": out}, "", "  ")
		return data, warnings, e
	}
	if minor >= 12 && ipMode == SingBoxIPv4Only {
		// Native internal lookups can override the DNS default strategy. Match
		// node bootstrap resolution to the selected family explicitly.
		for _, ob := range out {
			if _, ok := ob["domain_resolver"]; ok {
				ob["domain_resolver"] = sbObject{"server": "dns-bootstrap", "strategy": "ipv4_only"}
			}
		}
	}
	if minor < 11 {
		out = append(out, sbObject{"type": "dns", "tag": "dns-out"}, sbObject{"type": "block", "tag": "block"})
	}
	rules := []sbObject{}
	dnsRule := sbObject{"port": []int{53}}
	if minor >= 11 {
		dnsRule["action"] = "hijack-dns"
	} else {
		dnsRule["outbound"] = "dns-out"
	}
	rules = append(rules, dnsRule)
	for _, m := range []struct{ name, target string }{{"Direct", "🇨🇳 大陆"}, {"Global", "总模式"}} {
		rule := sbObject{"clash_mode": m.name, "outbound": m.target}
		if minor >= 11 {
			rule["action"] = "route"
		}
		rules = append(rules, rule)
	}
	used := map[string]bool{}
	for _, line := range p.Rules {
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			return nil, warnings, fmt.Errorf("不支持的路由规则: %s", line)
		}
		if parts[0] == "MATCH" {
			continue
		}
		var match sbObject
		var e error
		targetIndex := 2
		switch parts[0] {
		case "RULE-SET":
			match = sbObject{"rule_set": []string{parts[1]}}
			used[parts[1]] = true
		case "GEOSITE", "GEOIP":
			if !strings.EqualFold(parts[1], "CN") {
				return nil, warnings, fmt.Errorf("不支持的地理规则: %s", line)
			}
			tag := "CN_域"
			if parts[0] == "GEOIP" {
				tag = "CN_IP"
			}
			match = sbObject{"rule_set": []string{tag}}
			used[tag] = true
		default:
			match, e = singBoxRule(strings.Join(parts[:2], ","), "classical")
			if e != nil {
				return nil, warnings, e
			}
		}
		if len(parts) <= targetIndex {
			return nil, warnings, fmt.Errorf("路由规则缺少策略: %s", line)
		}
		target := parts[targetIndex]
		if target == "REJECT" || target == "⛔️ 拒绝连接" {
			if minor >= 11 {
				match["action"] = "reject"
			} else {
				match["outbound"] = "block"
			}
		} else {
			if target == "DIRECT" {
				target = "🇨🇳 大陆"
			}
			if !available[target] {
				return nil, warnings, fmt.Errorf("规则引用不存在的策略组: %s", target)
			}
			match["outbound"] = target
			if minor >= 11 {
				match["action"] = "route"
			}
		}
		rules = append(rules, match)
	}
	names := []string{}
	for name := range used {
		names = append(names, name)
	}
	sort.Strings(names)
	sets := []sbObject{}
	for _, name := range names {
		provider, ok := p.Providers[name]
		if !ok {
			return nil, warnings, fmt.Errorf("规则集不存在: %s", name)
		}
		if _, e := singBoxSourceURL(provider); e != nil {
			return nil, warnings, fmt.Errorf("规则集 %s: %w", name, e)
		}
		sets = append(sets, sbObject{"type": "remote", "tag": name, "format": "binary", "url": strings.TrimRight(baseURL, "/") + "/sub/singbox/rules/" + url.PathEscape(name) + "?token=" + url.QueryEscape(token) + "&format=binary", "download_detour": "🇨🇳 大陆", "update_interval": "24h"})
	}
	route := sbObject{"rules": rules, "rule_set": sets, "final": "总模式", "auto_detect_interface": true}
	dns := sbObject{"final": "dns-remote", "strategy": "prefer_ipv4", "reverse_mapping": true}
	if ipMode == SingBoxIPv4Only {
		dns["strategy"] = "ipv4_only"
	}
	if minor < 14 {
		// Older cores share answers across servers by default. A Global answer
		// must not be reused after switching back to domestic Rule-mode DNS.
		dns["independent_cache"] = true
	}
	if minor >= 12 {
		dns["servers"] = []sbObject{{"type": "https", "tag": "dns-remote", "server": "1.1.1.1", "detour": "总模式"}, {"type": "https", "tag": "dns-bootstrap", "server": "223.5.5.5"}}
		route["default_domain_resolver"] = "dns-bootstrap"
		if ipMode == SingBoxIPv4Only {
			route["default_domain_resolver"] = sbObject{"server": "dns-bootstrap", "strategy": "ipv4_only"}
		}
	} else {
		dns["servers"] = []sbObject{{"tag": "dns-remote", "address": "https://1.1.1.1/dns-query", "detour": "总模式"}, {"tag": "dns-bootstrap", "address": "https://223.5.5.5/dns-query", "detour": bootstrapDetour}}
		dns["rules"] = []sbObject{{"outbound": "any", "server": "dns-bootstrap"}}
	}
	dnsRules, _ := dns["rules"].([]sbObject)
	if ipMode == SingBoxIPv4Only {
		// Older cores do not filter ipv6hint from HTTPS/SVCB responses. Clients
		// can use those hints even without AAAA answers. Fall back to A lookups.
		hintRule := sbObject{"query_type": []string{"AAAA", "HTTPS", "SVCB"}}
		if minor >= 12 {
			hintRule["action"], hintRule["rcode"] = "predefined", "NOERROR"
		} else {
			servers := dns["servers"].([]sbObject)
			dns["servers"] = append(servers, sbObject{"tag": "dns-ipv4-compat", "address": "rcode://success"})
			hintRule["server"] = "dns-ipv4-compat"
			if minor >= 11 {
				hintRule["action"] = "route"
			}
		}
		dnsRules = append([]sbObject{hintRule}, dnsRules...)
	}
	for _, m := range []struct{ name, server string }{{"Direct", "dns-bootstrap"}, {"Global", "dns-remote"}} {
		rule := sbObject{"clash_mode": m.name, "server": m.server}
		if minor >= 11 {
			rule["action"] = "route"
		}
		dnsRules = append(dnsRules, rule)
	}
	// Resolve domestic domains locally before the Rule-mode catch-all. GeoIP
	// alone is not sufficient: remote DNS can select an overseas CDN address.
	// Only domain-only providers may enter this allowlist; an IP/port/process
	// rule set must never accidentally expose unrelated overseas DNS queries.
	domesticSets := []string{}
	for _, name := range names {
		if name == "CN_域" || (p.Providers[name].Behavior == "domain" && strings.HasSuffix(name, "_域") && singBoxDomesticGroup(strings.TrimSuffix(name, "_域"))) {
			domesticSets = append(domesticSets, name)
		}
	}
	if len(domesticSets) > 0 {
		rule := sbObject{"clash_mode": "Rule", "rule_set": domesticSets, "server": "dns-bootstrap"}
		if minor >= 11 {
			rule["action"] = "route"
		}
		dnsRules = append(dnsRules, rule)
	}
	rule := sbObject{"clash_mode": "Rule", "server": "dns-remote"}
	if minor >= 11 {
		rule["action"] = "route"
	}
	dnsRules = append(dnsRules, rule)
	dns["rules"] = dnsRules
	tun := sbObject{"type": "tun", "tag": "tun-in", "auto_route": true, "strict_route": true}
	if minor >= 10 {
		tun["address"] = []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"}
	} else {
		tun["inet4_address"] = []string{"172.19.0.1/30"}
		tun["inet6_address"] = []string{"fdfe:dcba:9876::1/126"}
	}
	mixed := sbObject{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 7890}
	if minor < 11 {
		mixed["sniff"] = true
		tun["sniff"] = true
	} else {
		rules = append(rules[:1], append([]sbObject{{"action": "sniff"}}, rules[1:]...)...)
		route["rules"] = rules
	}
	config := sbObject{"log": sbObject{"level": "warn"}, "dns": dns, "inbounds": []sbObject{mixed, tun}, "outbounds": out, "route": route, "experimental": sbObject{"cache_file": sbObject{"enabled": true}, "clash_api": sbObject{"external_controller": "127.0.0.1:9090", "default_mode": "Rule"}}}
	if mode == "mobile" {
		config["inbounds"] = []sbObject{tun}
		config["experimental"] = sbObject{"cache_file": sbObject{"enabled": true}, "clash_api": sbObject{"default_mode": "Rule"}}
	}
	data, e := json.MarshalIndent(config, "", "  ")
	return data, warnings, e
}

func singBoxOutbound(n *ClashNode, minor int) (sbObject, error) {
	if n.Server == "" || n.Port < 1 || n.Port > 65535 {
		return nil, fmt.Errorf("服务器或端口无效")
	}
	if n.Type == "vmess" || n.Type == "vless" || n.Type == "tuic" {
		if _, err := uuid.Parse(n.UUID); err != nil {
			return nil, fmt.Errorf("UUID 无效")
		}
	}
	if len(n.RealityOpts) > 0 && !n.TLS {
		return nil, fmt.Errorf("Reality 需要 TLS")
	}
	o := sbObject{"type": n.Type, "server": n.Server, "server_port": n.Port}
	if n.Network == "quic" && !n.TLS {
		return nil, fmt.Errorf("QUIC 传输需要 TLS")
	}
	tlsRequired := n.TLS
	switch n.Type {
	case "ss":
		o["type"] = "shadowsocks"
		o["method"] = n.Cipher
		o["password"] = n.Password
		if n.Plugin != "" {
			if n.Plugin != "obfs" && n.Plugin != "obfs-local" && n.Plugin != "v2ray-plugin" {
				return nil, fmt.Errorf("不支持的 Shadowsocks 插件")
			}
			plugin := n.Plugin
			if plugin == "obfs" {
				plugin = "obfs-local"
			}
			o["plugin"] = plugin
			keys := []string{}
			for k := range n.PluginOpts {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			opts := []string{}
			for _, k := range keys {
				v := n.PluginOpts[k]
				optionKey := k
				if plugin == "obfs-local" {
					if k == "mode" {
						optionKey = "obfs"
					}
					if k == "host" {
						optionKey = "obfs-host"
					}
				}
				if v == true {
					opts = append(opts, optionKey)
				} else if v != false {
					opts = append(opts, optionKey+"="+fmt.Sprint(v))
				}
			}
			o["plugin_opts"] = strings.Join(opts, ";")
		}
	case "vmess":
		o["uuid"] = n.UUID
		o["security"] = n.Cipher
		if n.Cipher == "" {
			o["security"] = "auto"
		}
		if n.AlterId != nil {
			o["alter_id"] = *n.AlterId
		}
	case "vless":
		o["uuid"] = n.UUID
		if n.Flow != "" {
			o["flow"] = n.Flow
		}
	case "trojan":
		o["password"] = n.Password
		tlsRequired = true
	case "hysteria2":
		o["password"] = n.Password
		tlsRequired = true
		if n.Obfs != "" && n.Obfs != "none" {
			o["obfs"] = sbObject{"type": n.Obfs, "password": n.ObfsPassword}
		}
	case "hysteria":
		tlsRequired = true
		o["auth_str"] = n.AuthStr
		up, down := n.Up, n.Down
		if up <= 0 {
			up = 100
		}
		if down <= 0 {
			down = 100
		}
		o["up_mbps"] = up
		o["down_mbps"] = down
		if n.Obfs != "" {
			o["obfs"] = n.Obfs
		}
	case "tuic":
		tlsRequired = true
		o["uuid"] = n.UUID
		o["password"] = n.Password
		if n.CongestionController != "" {
			o["congestion_control"] = n.CongestionController
		}
		if n.UDPRelayMode != "" {
			o["udp_relay_mode"] = n.UDPRelayMode
		}
	case "anytls":
		if minor < 12 {
			return nil, fmt.Errorf("AnyTLS 需要 sing-box 1.12 或更新版本")
		}
		tlsRequired = true
		o["password"] = n.Password
	case "socks5":
		o["type"] = "socks"
		o["version"] = "5"
		if n.Username != "" {
			o["username"] = n.Username
			o["password"] = n.Password
		}
	case "http":
		if n.Username != "" {
			o["username"] = n.Username
			o["password"] = n.Password
		}
	default:
		return nil, fmt.Errorf("sing-box 不支持协议 %s", n.Type)
	}
	if n.PacketEncoding != "" && (n.Type == "vmess" || n.Type == "vless") {
		o["packet_encoding"] = n.PacketEncoding
	}
	if tlsRequired {
		t := sbObject{"enabled": true, "insecure": n.SkipCertVerify}
		sni := n.ServerName
		if sni == "" {
			sni = n.SNI
		}
		if sni != "" {
			t["server_name"] = sni
		}
		if len(n.ALPN) > 0 {
			t["alpn"] = n.ALPN
		}
		if n.ClientFingerprint != "" {
			t["utls"] = sbObject{"enabled": true, "fingerprint": n.ClientFingerprint}
		}
		if len(n.RealityOpts) > 0 {
			t["reality"] = sbObject{"enabled": true, "public_key": n.RealityOpts["public-key"], "short_id": n.RealityOpts["short-id"]}
		}
		o["tls"] = t
	}
	if n.Network != "" && n.Network != "tcp" {
		if n.Type != "vmess" && n.Type != "vless" && n.Type != "trojan" {
			return nil, fmt.Errorf("协议不支持该传输")
		}
		transport := sbObject{"type": n.Network}
		switch n.Network {
		case "ws":
			if n.WSOpts["v2ray-http-upgrade"] == true {
				transport["type"] = "httpupgrade"
			}
			if path, ok := n.WSOpts["path"]; ok {
				transport["path"] = path
			}
			if headers, ok := n.WSOpts["headers"]; ok {
				if transport["type"] == "httpupgrade" {
					switch h := headers.(type) {
					case map[string]interface{}:
						transport["host"] = h["Host"]
					case map[string]string:
						transport["host"] = h["Host"]
					}
				} else {
					transport["headers"] = headers
				}
			}
		case "grpc":
			transport["service_name"] = n.GRPCOpts["grpc-service-name"]
		case "http":
			if path, ok := n.HTTPOpts["path"]; ok {
				switch v := path.(type) {
				case []interface{}:
					if len(v) > 0 {
						transport["path"] = v[0]
					}
				case []string:
					if len(v) > 0 {
						transport["path"] = v[0]
					}
				default:
					transport["path"] = path
				}
			}
			if headers, ok := n.HTTPOpts["headers"].(map[string]interface{}); ok {
				if host, ok := headers["Host"]; ok {
					transport["host"] = host
				}
			}
		case "quic":
		default:
			return nil, fmt.Errorf("不支持的传输 %s", n.Network)
		}
		o["transport"] = transport
	}
	if minor >= 12 {
		if _, e := netip.ParseAddr(n.Server); e != nil {
			o["domain_resolver"] = "dns-bootstrap"
		}
	}
	return o, nil
}
