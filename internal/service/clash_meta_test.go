package service

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"text/template"

	"gopkg.in/yaml.v3"
)

type renderedClashConfig struct {
	Proxies []struct {
		Name string `yaml:"name"`
		Type string `yaml:"type"`
		UDP  bool   `yaml:"udp"`
	} `yaml:"proxies"`
	ProxyProviders map[string]struct {
		URL      string `yaml:"url"`
		Override struct {
			DialerProxy string `yaml:"dialer-proxy"`
			SkipProxy   bool   `yaml:"skip-proxy"`
		} `yaml:"override"`
	} `yaml:"proxy-providers"`
	ProxyGroups []struct {
		Name    string   `yaml:"name"`
		Type    string   `yaml:"type"`
		Icon    string   `yaml:"icon"`
		Proxies []string `yaml:"proxies"`
		Use     []string `yaml:"use"`
	} `yaml:"proxy-groups"`
	DNS struct {
		IPv6                  bool              `yaml:"ipv6"`
		EnhancedMode          string            `yaml:"enhanced-mode"`
		FakeIPRange           string            `yaml:"fake-ip-range"`
		DirectNameserver      []string          `yaml:"direct-nameserver"`
		ProxyServerNameserver []string          `yaml:"proxy-server-nameserver"`
		Nameserver            []string          `yaml:"nameserver"`
		NameserverPolicy      map[string]any    `yaml:"nameserver-policy"`
	} `yaml:"dns"`
	Rules []string `yaml:"rules"`
}

func TestRenderClashPolicyOrderAndReferences(t *testing.T) {
	data := ClashTemplateData{
		RelaySubURL:             "https://panel.example/sub/raw/1?token=x",
		ExitSubURL:              "https://panel.example/sub/raw/2?token=x",
		BaseURL:                 "https://panel.example",
		Token:                   "x",
		ActiveModules:           []ClashModuleDef{{Name: "Telegram", Icon: "https://example.test/telegram.svg"}, {Name: "加密货币", Icon: "💱"}},
		ProxiesInterval:         "3600",
		RulesInterval:           "300",
		PublicRulesInterval:     "86400",
	}
	tmpl, err := template.New("clash").Parse(ClashTemplateStr)
	if err != nil {
		t.Fatalf("parse template: %v", err)
	}
	var output bytes.Buffer
	if err := tmpl.Execute(&output, data); err != nil {
		t.Fatalf("render template: %v", err)
	}

	var config renderedClashConfig
	if err := yaml.Unmarshal(output.Bytes(), &config); err != nil {
		t.Fatalf("parse rendered YAML: %v", err)
	}
	if len(config.ProxyGroups) < 3 {
		t.Fatalf("only %d proxy groups rendered", len(config.ProxyGroups))
	}
	firstThree := []string{config.ProxyGroups[0].Name, config.ProxyGroups[1].Name, config.ProxyGroups[2].Name}
	wantFirstThree := []string{"总模式", "💠 中转策略", "手动选择"}
	for i, want := range wantFirstThree {
		if firstThree[i] != want {
			t.Fatalf("first groups = %v, want prefix %v", firstThree, wantFirstThree)
		}
	}

	if config.ProxyGroups[3].Name != "Telegram" || config.ProxyGroups[4].Name != "加密货币" {
		t.Fatalf("software groups were not placed before regions: %v %v", config.ProxyGroups[3].Name, config.ProxyGroups[4].Name)
	}
	if config.ProxyGroups[3].Proxies[0] != "总模式" || config.ProxyGroups[4].Proxies[0] != "总模式" {
		t.Fatal("software policy must list 总模式 first")
	}
	if config.ProxyGroups[4].Icon != "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/svg/bitcoin.svg" {
		t.Fatalf("Crypto icon = %q", config.ProxyGroups[4].Icon)
	}

	wantRegions := []string{
		"香港地区", "香港自动", "日本地区", "日本自动", "新加坡地区", "新加坡自动", "美国地区", "美国自动",
		"英国地区", "英国自动", "德国地区", "德国自动", "台湾地区", "台湾自动", "韩国地区", "韩国自动",
		"荷兰地区", "荷兰自动", "波兰地区", "波兰自动", "摩尔多瓦地区", "摩尔多瓦自动", "芬兰地区", "芬兰自动",
		"印度地区", "印度自动", "泰国地区", "泰国自动", "法国地区", "法国自动", "中国大陆地区", "中国大陆自动",
	}
	for i, want := range wantRegions {
		got := config.ProxyGroups[5+i].Name
		if got != want {
			t.Fatalf("region group %d = %q, want %q", i, got, want)
		}
	}

	groupByName := make(map[string]int, len(config.ProxyGroups))
	for i, group := range config.ProxyGroups {
		if _, exists := groupByName[group.Name]; exists {
			t.Fatalf("duplicate policy group %q", group.Name)
		}
		groupByName[group.Name] = i
		if group.Name == "默认代理" || group.Name == "自动选择" || group.Name == "💠 中转选择" {
			t.Fatalf("removed policy group is still present: %q", group.Name)
		}
	}
	if err := assertNoPolicyCycles(config.ProxyGroups, groupByName); err != nil {
		t.Fatal(err)
	}

	relay := config.ProxyGroups[1]
	if relay.Type != "select" || len(relay.Proxies) != 1 || relay.Proxies[0] != "中转关闭" || len(relay.Use) != 1 || relay.Use[0] != "中转机场" {
		t.Fatalf("unexpected relay policy: %#v", relay)
	}
	if config.ProxyProviders["落地机场"].Override.DialerProxy != "💠 中转策略" || config.ProxyProviders["落地机场"].Override.SkipProxy {
		t.Fatalf("unexpected landing provider override: %#v", config.ProxyProviders["落地机场"].Override)
	}
	if got := config.ProxyProviders["中转机场"].URL; got != data.RelaySubURL {
		t.Fatalf("中转机场 URL = %q, want %q", got, data.RelaySubURL)
	}
	if got := config.ProxyProviders["落地机场"].URL; got != data.ExitSubURL {
		t.Fatalf("落地机场 URL = %q, want %q", got, data.ExitSubURL)
	}
	if config.ProxyGroups[0].Use[0] != "落地机场" {
		t.Fatalf("总模式 does not expose landing nodes: %#v", config.ProxyGroups[0].Use)
	}
	manual := config.ProxyGroups[2]
	if len(manual.Proxies) != 0 || len(manual.Use) != 1 || manual.Use[0] != "落地机场" {
		t.Fatalf("手动选择 must default to landing provider, got %#v", manual)
	}
	var relayOffFound bool
	for _, proxy := range config.Proxies {
		if proxy.Name == "中转关闭" {
			relayOffFound = proxy.Type == "direct" && proxy.UDP
		}
	}
	if !relayOffFound {
		t.Fatal("中转关闭 direct proxy missing")
	}
	if len(config.Rules) == 0 {
		t.Fatal("no routing rules rendered")
	}
	if lastRule := config.Rules[len(config.Rules)-1]; lastRule != "MATCH,总模式" {
		t.Fatalf("last rule = %q, want MATCH,总模式", lastRule)
	}
	if strings.Contains(output.String(), "MATCH,默认代理") {
		t.Fatal("legacy default proxy MATCH rule is present")
	}

	if config.DNS.EnhancedMode != "fake-ip" || config.DNS.FakeIPRange != "198.18.0.1/16" {
		t.Fatalf("unexpected DNS fake-ip config: mode=%q range=%q", config.DNS.EnhancedMode, config.DNS.FakeIPRange)
	}
	if len(config.DNS.DirectNameserver) != 0 || len(config.DNS.NameserverPolicy) != 0 {
		t.Fatalf("client DNS must not use split/direct resolver paths: direct=%v policy=%v", config.DNS.DirectNameserver, config.DNS.NameserverPolicy)
	}
	if len(config.DNS.ProxyServerNameserver) == 0 {
		t.Fatal("proxy-server-nameserver bootstrap resolvers are required")
	}
	if len(config.DNS.Nameserver) != 2 {
		t.Fatalf("unexpected client nameserver count: %v", config.DNS.Nameserver)
	}
	for _, server := range config.DNS.Nameserver {
		if !strings.Contains(server, "#总模式") {
			t.Fatalf("client DNS server does not follow 总模式: %q", server)
		}
	}
	if _, exists := groupByName["DNS连接"]; exists {
		t.Fatal("legacy independent DNS连接 group must be removed")
	}
	var dotRuleFound bool
	for _, rule := range config.Rules {
		if rule == "DST-PORT,853,总模式" {
			dotRuleFound = true
		}
		if strings.Contains(rule, "DNS连接") {
			t.Fatalf("legacy DNS连接 rule still present: %q", rule)
		}
	}
	if !dotRuleFound {
		t.Fatal("DoT traffic must follow 总模式")
	}
}

func assertNoPolicyCycles(groups []struct {
	Name    string   `yaml:"name"`
	Type    string   `yaml:"type"`
	Icon    string   `yaml:"icon"`
	Proxies []string `yaml:"proxies"`
	Use     []string `yaml:"use"`
}, groupByName map[string]int) error {
	state := make([]uint8, len(groups))
	var visit func(int) error
	visit = func(index int) error {
		if state[index] == 1 {
			return fmt.Errorf("policy cycle reaches %q", groups[index].Name)
		}
		if state[index] == 2 {
			return nil
		}
		state[index] = 1
		for _, proxy := range groups[index].Proxies {
			if target, ok := groupByName[proxy]; ok {
				if err := visit(target); err != nil {
					return err
				}
			}
		}
		state[index] = 2
		return nil
	}
	for i := range groups {
		if err := visit(i); err != nil {
			return err
		}
	}
	return nil
}
