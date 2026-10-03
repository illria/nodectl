package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

func singBoxSourceURL(p singBoxProvider) (string, error) {
	u, e := url.Parse(p.URL)
	if e != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", fmt.Errorf("规则源必须是 HTTP(S) URL")
	}
	if p.Format == "mrs" {
		// These upstream repositories publish matching plaintext alongside MRS files.
		switch {
		case strings.Contains(u.Path, "/GitMetaio/rule/") || strings.Contains(u.Path, "/GitMetaio/rule@"):
			u.Path = strings.TrimSuffix(u.Path, ".mrs") + ".txt"
		case strings.Contains(u.Path, "/TG-Twilight/AWAvenue-Ads-Rule/"):
			u.Path = strings.TrimSuffix(u.Path, ".mrs") + ".yaml"
		case strings.Contains(u.Path, "/MetaCubeX/meta-rules-dat/") || strings.Contains(u.Path, "/MetaCubeX/meta-rules-dat@"):
			u.Path = strings.TrimSuffix(u.Path, ".mrs") + ".list"
		default:
			return "", fmt.Errorf("自定义 MRS 规则源没有已知文本镜像，请使用文本/YAML 规则源")
		}
	}
	return u.String(), nil
}

// singBoxRule creates headless source-v1 rules. IP matches never introduce a resolve action.
func singBoxRule(line, behavior string) (sbObject, error) {
	line = strings.TrimSpace(line)
	if behavior == "ipcidr" {
		if _, e := netip.ParsePrefix(line); e != nil {
			return nil, fmt.Errorf("无效 IP 规则")
		}
		return sbObject{"ip_cidr": []string{line}}, nil
	}
	if behavior == "domain" {
		if strings.HasPrefix(line, "+.") {
			d := strings.TrimPrefix(line, "+.")
			return sbObject{"domain": []string{d}, "domain_suffix": []string{"." + d}}, nil
		}
		if strings.HasPrefix(line, ".") {
			return sbObject{"domain_suffix": []string{line}}, nil
		}
		if strings.ContainsAny(line, "*?") {
			pattern := regexp.QuoteMeta(line)
			pattern = strings.ReplaceAll(pattern, `\*`, ".*")
			pattern = strings.ReplaceAll(pattern, `\?`, ".")
			return sbObject{"domain_regex": []string{"^" + pattern + "$"}}, nil
		}
		if strings.ContainsAny(line, ", /:") {
			return nil, fmt.Errorf("无效域名规则")
		}
		return sbObject{"domain": []string{line}}, nil
	}
	fields := strings.Split(line, ",")
	if len(fields) < 2 {
		return nil, fmt.Errorf("不支持的 classical 规则类型")
	}
	for _, extra := range fields[2:] {
		if extra != "no-resolve" {
			return nil, fmt.Errorf("不支持的 classical 规则附加字段")
		}
	}
	kind, value := strings.ToUpper(strings.TrimSpace(fields[0])), strings.TrimSpace(fields[1])
	if value == "" {
		return nil, fmt.Errorf("规则值不能为空")
	}
	key := ""
	switch kind {
	case "DOMAIN":
		key = "domain"
	case "DOMAIN-SUFFIX":
		return sbObject{"domain": []string{strings.TrimPrefix(value, ".")}, "domain_suffix": []string{"." + strings.TrimPrefix(value, ".")}}, nil
	case "DOMAIN-KEYWORD":
		key = "domain_keyword"
	case "DOMAIN-REGEX":
		if _, e := regexp.Compile(value); e != nil {
			return nil, fmt.Errorf("无效域名正则")
		}
		key = "domain_regex"
	case "IP-CIDR", "IP-CIDR6":
		key = "ip_cidr"
	case "SRC-IP-CIDR":
		key = "source_ip_cidr"
	case "PROCESS-NAME":
		key = "process_name"
	case "PROCESS-PATH":
		key = "process_path"
	case "NETWORK":
		if value != "tcp" && value != "udp" {
			return nil, fmt.Errorf("无效网络类型")
		}
		key = "network"
	case "DST-PORT", "SRC-PORT":
		key = "port"
		if kind == "SRC-PORT" {
			key = "source_port"
		}
		if strings.Contains(value, "-") {
			parts := strings.Split(value, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("无效端口范围")
			}
			a, e1 := strconv.Atoi(parts[0])
			b, e2 := strconv.Atoi(parts[1])
			if e1 != nil || e2 != nil || a < 1 || b > 65535 || a > b {
				return nil, fmt.Errorf("无效端口范围")
			}
			return sbObject{key + "_range": []string{parts[0] + ":" + parts[1]}}, nil
		}
		port, e := strconv.Atoi(value)
		if e != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("无效端口")
		}
		return sbObject{key: []int{port}}, nil
	default:
		return nil, fmt.Errorf("不支持的 classical 规则类型 %s", kind)
	}
	if key == "ip_cidr" || key == "source_ip_cidr" {
		if _, e := netip.ParsePrefix(value); e != nil {
			return nil, fmt.Errorf("无效 IP 规则")
		}
	}
	return sbObject{key: []string{value}}, nil
}

func convertSingBoxRuleSource(data []byte, behavior string) ([]byte, error) {
	if !strings.Contains(string(data), "\n") && len(data) > 16384 {
		return nil, fmt.Errorf("规则源不是文本列表")
	}
	lines := strings.Split(strings.TrimPrefix(string(data), "\ufeff"), "\n")
	if regexp.MustCompile(`(?m)^payload:\s*`).Match(data) {
		var doc struct {
			Payload []string `yaml:"payload"`
		}
		if e := yaml.Unmarshal(data, &doc); e != nil {
			return nil, fmt.Errorf("无效 YAML 规则源")
		}
		lines = doc.Payload
	}
	rules := []sbObject{}
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		rule, e := singBoxRule(line, behavior)
		if e != nil {
			return nil, fmt.Errorf("规则源第 %d 行: %w", i+1, e)
		}
		rules = append(rules, rule)
	}
	return json.Marshal(sbObject{"version": 1, "rules": rules})
}

var singBoxRuleCache = struct {
	sync.Mutex
	entries map[string]struct {
		data    []byte
		expires time.Time
	}
}{entries: make(map[string]struct {
	data    []byte
	expires time.Time
})}

func publicRuleAddress(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, prefix := range []string{"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"} {
		if netip.MustParsePrefix(prefix).Contains(addr) {
			return false
		}
	}
	return addr.IsValid() && !addr.IsPrivate() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() && !addr.IsLinkLocalMulticast() && !addr.IsMulticast() && !addr.IsUnspecified() && addr.IsGlobalUnicast()
}

// Resolve and validate the actual dial addresses, including redirects, to avoid SSRF.
func singBoxRuleHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, fmt.Errorf("规则源地址无效")
		}
		ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if e != nil {
			return nil, fmt.Errorf("规则源 DNS 解析失败")
		}
		for _, ip := range ips {
			if !publicRuleAddress(ip) {
				return nil, fmt.Errorf("规则源禁止访问内网地址")
			}
		}
		for _, ip := range ips {
			conn, e := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if e == nil {
				return conn, nil
			}
		}
		return nil, fmt.Errorf("规则源连接失败")
	}}
	return &http.Client{Transport: transport, Timeout: 25 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("规则源重定向过多")
		}
		if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
			return fmt.Errorf("规则源协议无效")
		}
		return nil
	}}
}

func GenerateSingBoxRuleSet(ctx context.Context, name, baseURL, token string) ([]byte, error) {
	p, e := loadSingBoxProfile(baseURL, token)
	if e != nil {
		return nil, e
	}
	provider, ok := p.Providers[name]
	if !ok {
		return nil, fmt.Errorf("规则集不存在")
	}
	if name == "我的直连规则" {
		return convertSingBoxRuleSource([]byte(ParseCustomRules(GetCustomDirectRules())), "classical")
	}
	for _, custom := range GetCustomProxyRulesForClash() {
		if name == custom.Name+"_自定义分流" {
			return convertSingBoxRuleSource([]byte(ParseCustomRules(custom.Content)), "classical")
		}
	}
	source, e := singBoxSourceURL(provider)
	if e != nil {
		return nil, e
	}
	key := provider.Behavior + "|" + source
	singBoxRuleCache.Lock()
	cached, exists := singBoxRuleCache.entries[key]
	singBoxRuleCache.Unlock()
	if exists && time.Now().Before(cached.expires) {
		return cached.data, nil
	}
	client := singBoxRuleHTTPClient()
	defer client.CloseIdleConnections()
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if e != nil {
		return nil, fmt.Errorf("规则源地址无效")
	}
	resp, e := client.Do(req)
	if e != nil {
		return nil, fmt.Errorf("下载规则源失败")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("规则源返回 HTTP %d", resp.StatusCode)
	}
	const max = 16 << 20
	data, e := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if e != nil || len(data) > max {
		return nil, fmt.Errorf("规则源读取失败或超过 16MB")
	}
	result, e := convertSingBoxRuleSource(data, provider.Behavior)
	if e != nil {
		return nil, e
	}
	singBoxRuleCache.Lock()
	if len(singBoxRuleCache.entries) >= 16 {
		clear(singBoxRuleCache.entries)
	}
	singBoxRuleCache.entries[key] = struct {
		data    []byte
		expires time.Time
	}{result, time.Now().Add(5 * time.Minute)}
	singBoxRuleCache.Unlock()
	return result, nil
}
