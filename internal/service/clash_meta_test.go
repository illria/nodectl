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
		URL      string         `yaml:"url"`
		Override map[string]any `yaml:"override"`
	} `yaml:"proxy-providers"`
	ProxyGroups []struct {
		Name    string   `yaml:"name"`
		Type    string   `yaml:"type"`
		Icon    string   `yaml:"icon"`
		Proxies []string `yaml:"proxies"`
		Use     []string `yaml:"use"`
	} `yaml:"proxy-groups"`
	Rules []string `yaml:"rules"`
}

func TestRenderClashPolicyOrderAndReferences(t *testing.T) {
	data := ClashTemplateData{
		ChainSubURL:         "https://panel.example/sub/chains?token=x",
		ExitSubURL:          "https://panel.example/sub/raw/2?token=x",
		BaseURL:             "https://panel.example",
		Token:               "x",
		ActiveModules:       []ClashModuleDef{{Name: "Telegram", Icon: "https://example.test/telegram.svg", IPURL: "https://example.test/telegram-ip.mrs"}, {Name: "加密货币", Icon: "💱"}, {Name: "阻断", Type: "reject", IPURL: "https://example.test/reject-ip.mrs"}},
		ProxiesInterval:     "3600",
		RulesInterval:       "300",
		PublicRulesInterval: "86400",
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

	var topLevel map[string]any
	if err := yaml.Unmarshal(output.Bytes(), &topLevel); err != nil {
		t.Fatalf("parse rendered YAML top-level keys: %v", err)
	}
	for _, forbidden := range []string{
		"mixed-port", "redir-port", "tproxy-port", "ipv6", "mode", "allow-lan",
		"disable-keep-alive", "geodata-mode", "geo-auto-update", "geo-update-interval",
		"geox-url", "experimental", "unified-delay", "tcp-concurrent", "log-level",
		"find-process-mode", "global-client-fingerprint", "profile", "sniffer", "tun", "dns",
		"proxy_groups", "rule-anchor",
	} {
		if _, ok := topLevel[forbidden]; ok {
			t.Fatalf("minimal subscription still overrides client runtime with top-level key %q", forbidden)
		}
	}
	if len(config.ProxyGroups) < 3 {
		t.Fatalf("only %d proxy groups rendered", len(config.ProxyGroups))
	}
	firstThree := []string{config.ProxyGroups[0].Name, config.ProxyGroups[1].Name, config.ProxyGroups[2].Name}
	wantFirstThree := []string{"总模式", "直连落地", "中转线路"}
	for i, want := range wantFirstThree {
		if firstThree[i] != want {
			t.Fatalf("first groups = %v, want prefix %v", firstThree, wantFirstThree)
		}
	}

	if config.ProxyGroups[3].Name != "手动选择" || config.ProxyGroups[4].Name != "Telegram" || config.ProxyGroups[5].Name != "加密货币" {
		t.Fatalf("unexpected group order: %v %v %v", config.ProxyGroups[3].Name, config.ProxyGroups[4].Name, config.ProxyGroups[5].Name)
	}
	if config.ProxyGroups[4].Proxies[0] != "总模式" || config.ProxyGroups[5].Proxies[0] != "总模式" {
		t.Fatal("software policy must list 总模式 first")
	}
	if config.ProxyGroups[5].Icon != "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/svg/bitcoin.svg" {
		t.Fatalf("Crypto icon = %q", config.ProxyGroups[5].Icon)
	}

	wantRegions := []string{
		"香港地区", "香港自动", "日本地区", "日本自动", "新加坡地区", "新加坡自动", "美国地区", "美国自动",
		"英国地区", "英国自动", "德国地区", "德国自动", "台湾地区", "台湾自动", "韩国地区", "韩国自动",
		"荷兰地区", "荷兰自动", "波兰地区", "波兰自动", "摩尔多瓦地区", "摩尔多瓦自动", "芬兰地区", "芬兰自动",
		"印度地区", "印度自动", "泰国地区", "泰国自动", "法国地区", "法国自动", "中国大陆地区", "中国大陆自动",
	}
	for i, want := range wantRegions {
		got := config.ProxyGroups[6+i].Name
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
		if group.Name == "默认代理" || group.Name == "自动选择" || group.Name == "💠 中转选择" || group.Name == "💠 中转策略" || group.Name == "中转关闭" {
			t.Fatalf("removed policy group is still present: %q", group.Name)
		}
	}
	if err := assertNoPolicyCycles(config.ProxyGroups, groupByName); err != nil {
		t.Fatal(err)
	}

	if direct := config.ProxyGroups[1]; direct.Type != "select" || len(direct.Use) != 1 || direct.Use[0] != "落地机场" {
		t.Fatalf("unexpected direct landing policy: %#v", direct)
	}
	if chain := config.ProxyGroups[2]; chain.Type != "select" || len(chain.Use) != 1 || chain.Use[0] != "中转链" {
		t.Fatalf("unexpected composite chain policy: %#v", chain)
	}
	if len(config.ProxyProviders) != 2 || len(config.ProxyProviders["落地机场"].Override) != 0 {
		t.Fatalf("unexpected providers: %#v", config.ProxyProviders)
	}
	if got := config.ProxyProviders["中转链"].URL; got != data.ChainSubURL {
		t.Fatalf("中转链 URL = %q, want %q", got, data.ChainSubURL)
	}
	if got := config.ProxyProviders["落地机场"].URL; got != data.ExitSubURL {
		t.Fatalf("落地机场 URL = %q, want %q", got, data.ExitSubURL)
	}
	manual := config.ProxyGroups[3]
	if len(manual.Proxies) != 0 || len(manual.Use) != 2 || manual.Use[0] != "落地机场" || manual.Use[1] != "中转链" {
		t.Fatalf("手动选择 must offer complete direct and composite nodes, got %#v", manual)
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
	for _, forbidden := range []string{"dialer-proxy", "type: relay", "💠 中转策略", "/sub/raw/1", "中转机场"} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("legacy client relay remains: %s", forbidden)
		}
	}
	for _, rule := range []string{"RULE-SET,Telegram_IP,Telegram,no-resolve", "RULE-SET,阻断_IP,REJECT,no-resolve"} {
		if !strings.Contains(output.String(), rule) {
			t.Fatalf("IP RuleSet missing no-resolve: %s", rule)
		}
	}

	if strings.Contains(output.String(), "\ntun:") || strings.Contains(output.String(), "\ndns:") {
		t.Fatal("generated subscription must not override client TUN/DNS settings")
	}
	for _, forbidden := range []string{"DNS_Hijack", "DoH_域", "DST-PORT,53,", "DST-PORT,853,"} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("legacy DNS override still present: %s", forbidden)
		}
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
