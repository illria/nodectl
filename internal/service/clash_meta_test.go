package service

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
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
	RuleProviders map[string]struct {
		Behavior string `yaml:"behavior"`
	} `yaml:"rule-providers"`
	Rules []string `yaml:"rules"`
}

func renderClashTemplateForTest(t *testing.T, data ClashTemplateData) []byte {
	t.Helper()
	tmpl, err := template.New("clash").Parse(ClashTemplateStr)
	if err != nil {
		t.Fatalf("parse template: %v", err)
	}
	var output bytes.Buffer
	if err := tmpl.Execute(&output, data); err != nil {
		t.Fatalf("render template: %v", err)
	}
	return output.Bytes()
}

func TestRenderClashSingleProviderMatchesReference(t *testing.T) {
	data, err := os.ReadFile("testdata/clash-single-provider-reference.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var reference, got map[string]any
	if err = yaml.Unmarshal(data, &reference); err != nil {
		t.Fatal(err)
	}
	modules := map[string]ClashModuleDef{}
	for _, m := range LoadClashModulesConfig().Modules {
		modules[m.Name] = m
	}
	active := []ClashModuleDef{}
	for _, g := range reference["proxy-groups"].([]any) {
		if m, ok := modules[g.(map[string]any)["name"].(string)]; ok {
			active = append(active, m)
		}
	}
	provider := reference["proxy-providers"].(map[string]any)["provider1"].(map[string]any)
	output := renderClashTemplateForTest(t, ClashTemplateData{SingleProvider: true, ExitSubURL: provider["url"].(string), BaseURL: "https://panel.example", Token: "reference-test-token", ActiveModules: active, ProxiesInterval: "3600", RulesInterval: "300", PublicRulesInterval: "86400"})
	if err = yaml.Unmarshal(output, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reference["proxy-providers"], got["proxy-providers"]) {
		t.Fatal("single provider differs from the user's reference")
	}
	// Cosmetic icons may evolve; all group names, order, options, provider use,
	// filters and URL-test intervals must match the uploaded single-pool file.
	for _, doc := range []map[string]any{reference, got} {
		for _, g := range doc["proxy-groups"].([]any) {
			delete(g.(map[string]any), "icon")
		}
	}
	if !reflect.DeepEqual(reference["proxy-groups"], got["proxy-groups"]) {
		t.Fatal("single-pool strategy groups differ from the user's reference")
	}
	for _, key := range []string{"proxies", "dns", "tun", "sniffer"} {
		if _, ok := got[key]; ok {
			t.Fatal("single-pool profile adds runtime/proxy overrides", key)
		}
	}
	for _, text := range []string{"中转机场", "中转策略", "中转关闭", "dialer-proxy"} {
		if strings.Contains(string(output), text) {
			t.Fatal("single-pool profile still contains relay configuration", text)
		}
	}
	// The uploaded file contains core rules; keep these in order and preserve
	// the configured software/custom rule sets in the generated subscription.
	rules := got["rules"].([]any)
	start := 0
	for _, want := range reference["rules"].([]any) {
		found := false
		for start < len(rules) {
			candidate := rules[start]
			start++
			if candidate == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatal("core routing rule missing or reordered", want)
		}
	}
}

// Keep the actual generated profile aligned with the user-verified reference,
// including group order, relay chaining, rule order and client-owned DNS/TUN.
func TestRenderClashMatchesNoResolveReference(t *testing.T) {
	referenceBytes, err := os.ReadFile("testdata/clash-no-resolve-reference.yaml")
	if err != nil {
		t.Fatalf("read reference: %v", err)
	}
	var reference renderedClashConfig
	var want map[string]any
	if err := yaml.Unmarshal(referenceBytes, &reference); err != nil {
		t.Fatalf("parse reference: %v", err)
	}
	if err := yaml.Unmarshal(referenceBytes, &want); err != nil {
		t.Fatalf("parse reference sections: %v", err)
	}
	moduleByName := make(map[string]ClashModuleDef)
	for _, module := range LoadClashModulesConfig().Modules {
		moduleByName[module.Name] = module
	}
	var activeModules []ClashModuleDef
	for _, group := range reference.ProxyGroups {
		if module, ok := moduleByName[group.Name]; ok {
			activeModules = append(activeModules, module)
		}
	}
	if len(activeModules) != 17 {
		t.Fatalf("reference modules = %d, want 17", len(activeModules))
	}
	data := ClashTemplateData{
		RelaySubURL:         reference.ProxyProviders["中转机场"].URL,
		ExitSubURL:          reference.ProxyProviders["落地机场"].URL,
		BaseURL:             "https://panel.example",
		Token:               "reference-test-token",
		ActiveModules:       activeModules,
		ProxiesInterval:     "3600",
		RulesInterval:       "300",
		PublicRulesInterval: "86400",
	}
	// v10 extends the reference's no-resolve protection to classical rule sets.
	for i, rule := range reference.Rules {
		parts := strings.Split(rule, ",")
		if parts[0] == "RULE-SET" && reference.RuleProviders[parts[1]].Behavior == "classical" {
			reference.Rules[i] = rule + ",no-resolve"
		}
	}
	wantRules := make([]any, len(reference.Rules))
	for i, rule := range reference.Rules {
		wantRules[i] = rule
	}
	want["rules"] = wantRules
	var got map[string]any
	if err := yaml.Unmarshal(renderClashTemplateForTest(t, data), &got); err != nil {
		t.Fatalf("parse generated profile: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("top-level sections = %d, want %d", len(got), len(want))
	}
	for section, expected := range want {
		if !reflect.DeepEqual(got[section], expected) {
			t.Errorf("generated %s differs from the user-verified reference", section)
		}
	}
}

func TestRenderClashRuleSetsDoNotResolveIPs(t *testing.T) {
	modules := LoadClashModulesConfig().Modules
	modules = append(modules,
		ClashModuleDef{Name: "External", URL: "https://rules.example/external.list"},
		ClashModuleDef{Name: "RejectExternal", Type: "reject", URL: "https://rules.example/reject.list", IPURL: "https://rules.example/reject.mrs"},
	)
	data := ClashTemplateData{
		RelaySubURL:         "https://panel.example/sub/raw/1?token=x",
		ExitSubURL:          "https://panel.example/sub/raw/2?token=x",
		BaseURL:             "https://panel.example",
		Token:               "x",
		ActiveModules:       modules,
		CustomProxies:       []CustomProxyRule{{ID: "custom", Name: "Custom", Content: "203.0.113.0/24\n2001:db8::/32\nexample.test"}},
		ProxiesInterval:     "3600",
		RulesInterval:       "300",
		PublicRulesInterval: "86400",
	}
	var config renderedClashConfig
	if err := yaml.Unmarshal(renderClashTemplateForTest(t, data), &config); err != nil {
		t.Fatalf("parse generated profile: %v", err)
	}
	seen := make(map[string]bool)
	for _, rule := range config.Rules {
		parts := strings.Split(rule, ",")
		if parts[0] != "RULE-SET" {
			continue
		}
		provider, ok := config.RuleProviders[parts[1]]
		if !ok {
			t.Fatalf("rule references unknown provider: %s", rule)
		}
		seen[parts[1]] = true
		if provider.Behavior == "ipcidr" || provider.Behavior == "classical" {
			if len(parts) != 4 || parts[3] != "no-resolve" {
				t.Errorf("IP-capable provider can trigger DNS resolution: %s", rule)
			}
		} else if len(parts) != 3 {
			t.Errorf("domain-only rule unexpectedly changed: %s", rule)
		}
	}
	for name := range config.RuleProviders {
		if !seen[name] {
			t.Errorf("rule provider has no routing reference: %s", name)
		}
	}
}

func TestRenderClashPolicyOrderAndReferences(t *testing.T) {
	data := ClashTemplateData{
		RelaySubURL:         "https://panel.example/sub/raw/1?token=x",
		ExitSubURL:          "https://panel.example/sub/raw/2?token=x",
		BaseURL:             "https://panel.example",
		Token:               "x",
		ActiveModules:       []ClashModuleDef{{Name: "Telegram", Icon: "https://example.test/telegram.svg"}, {Name: "加密货币", Icon: "💱"}},
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
