package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
	"nodectl/internal/database"
	"nodectl/internal/logger"
)

func TestSingleSubscriptionSourcesAndFormats(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "single.db")), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.AutoMigrate(&database.SysConfig{}, &database.NodePool{}, &database.AirportNode{}, &database.CustomNode{}); err != nil {
		t.Fatal(err)
	}
	oldDB, oldLog := database.DB, logger.Log
	database.DB, logger.Log = db, slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Cleanup(func() { database.DB, logger.Log = oldDB, oldLog })
	for _, config := range []database.SysConfig{
		{Key: "sub_token", Value: "test&token"},
		{Key: "panel_url", Value: "https://panel.example"},
		{Key: "pref_use_emoji_flag", Value: "false"},
		{Key: "clash_custom_direct_raw", Value: "direct.example"},
		{Key: "clash_custom_proxy_rules", Value: `[{"id":"custom","name":"Custom","content":"proxy.example"}]`},
	} {
		if err = db.Create(&config).Error; err != nil {
			t.Fatal(err)
		}
	}
	link := func(ip string) string {
		return "vless://00000000-0000-4000-8000-000000000001@" + ip + ":443?security=tls#HK"
	}
	for i, node := range []database.NodePool{
		{Name: "HK managed relay", RoutingType: 1, IPV4: "192.0.2.11"},
		{Name: "HK managed exit", RoutingType: 2, IPV4: "192.0.2.12"},
		{Name: "blocked", RoutingType: 2, IPV4: "192.0.2.13", IsBlocked: true},
		{Name: "protocol disabled", RoutingType: 2, IPV4: "192.0.2.14", DisabledLinks: []string{"vless"}},
	} {
		node.UUID, node.InstallID = fmt.Sprintf("managed-%d", i), fmt.Sprintf("install-%d", i)
		node.Links, node.LinkIPModes = map[string]string{"vless": link(node.IPV4)}, map[string]int{"vless": 1}
		if err = db.Create(&node).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, node := range []database.AirportNode{
		{ID: "airport-relay", SubID: "airport", Name: "HK airport relay", RoutingType: 1, Link: link("192.0.2.21")},
		{ID: "airport-exit", SubID: "airport", Name: "HK airport exit", RoutingType: 2, Link: link("192.0.2.22")},
		{ID: "airport-disabled", SubID: "airport", Name: "airport disabled", RoutingType: 0, Link: link("192.0.2.23")},
	} {
		if err = db.Create(&node).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, node := range []database.CustomNode{
		{ID: "custom-relay", Name: "HK custom relay", RoutingType: 1, Link: link("192.0.2.31")},
		{ID: "custom-exit", Name: "HK custom exit", RoutingType: 2, Link: link("192.0.2.32")},
		{ID: "custom-disabled", Name: "custom disabled", RoutingType: 1, Link: link("192.0.2.33")},
	} {
		if err = db.Create(&node).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err = db.Model(&database.CustomNode{}).Where("id = ?", "custom-disabled").Update("routing_type", 0).Error; err != nil {
		t.Fatal(err)
	}
	request := func(handler http.HandlerFunc, path string, status int) *httptest.ResponseRecorder {
		t.Helper()
		response := httptest.NewRecorder()
		handler(response, httptest.NewRequest(http.MethodGet, "https://panel.example"+path, nil))
		if response.Code != status {
			t.Fatalf("%s: status %d, want %d: %s", path, response.Code, status, response.Body.String())
		}
		return response
	}
	exits := []string{"192.0.2.12", "192.0.2.22", "192.0.2.32"}
	all := []string{"192.0.2.11", "192.0.2.12", "192.0.2.21", "192.0.2.22", "192.0.2.31", "192.0.2.32"}
	checkServers := func(got, want []string) {
		t.Helper()
		sort.Strings(got)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("exported servers = %v, want %v", got, want)
		}
	}
	query := "?token=test%26token&topology=single"
	for _, variant := range []struct {
		query   string
		servers []string
	}{{query, exits}, {"?token=test%26token", all}} {
		response := request(apiSubV2ray, "/sub/v2ray"+variant.query, 200)
		decoded, err := base64.StdEncoding.DecodeString(response.Body.String())
		if err != nil {
			t.Fatal(err)
		}
		var servers []string
		for _, line := range strings.Split(strings.TrimSpace(string(decoded)), "\n") {
			u, err := url.Parse(line)
			if err != nil || u.Scheme != "vless" {
				t.Fatalf("invalid node link: %q", line)
			}
			servers = append(servers, u.Hostname())
		}
		checkServers(servers, variant.servers)
	}
	response := request(apiSubClash, "/sub/clash"+query, 200)
	var clash map[string]interface{}
	if err = yaml.Unmarshal(response.Body.Bytes(), &clash); err != nil {
		t.Fatal(err)
	}
	providers := clash["proxy-providers"].(map[string]interface{})
	if len(providers) != 1 {
		t.Fatal("single profile has multiple providers", providers)
	}
	provider := providers["provider1"].(map[string]interface{})
	if provider["url"] != "https://panel.example/sub/raw/2?token=test%26token" || provider["override"] != nil {
		t.Fatal("landing provider URL or chaining incorrect", provider)
	}
	for _, forbidden := range []string{"中转策略", "中转关闭", "dialer-proxy"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatal("single Clash profile contains", forbidden)
		}
	}
	for _, rule := range []string{"RULE-SET,我的直连规则,DIRECT,no-resolve", "RULE-SET,Custom_自定义分流,Custom,no-resolve"} {
		if !strings.Contains(response.Body.String(), rule) {
			t.Fatal("custom rule lost", rule)
		}
	}
	var raw struct {
		Proxies []struct {
			Server string `yaml:"server"`
			Detour string `yaml:"dialer-proxy"`
		} `yaml:"proxies"`
	}
	if err = yaml.Unmarshal(request(apiSubRaw, "/sub/raw/2?token=test%26token", 200).Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	var rawServers []string
	for _, node := range raw.Proxies {
		if node.Detour != "" {
			t.Fatal("raw node has chaining", node)
		}
		rawServers = append(rawServers, node.Server)
	}
	checkServers(rawServers, exits)
	for _, version := range []string{"1.8", "1.9", "1.10", "1.11", "1.12", "1.13", "1.14"} {
		for _, mode := range []string{"mobile", "full", "outbounds"} {
			response = request(apiSubSingBox, "/sub/singbox"+query+"&version="+version+"&mode="+mode, 200)
			var config struct {
				Outbounds []map[string]interface{} `json:"outbounds"`
			}
			if err = json.Unmarshal(response.Body.Bytes(), &config); err != nil {
				t.Fatal(err)
			}
			var servers []string
			for _, outbound := range config.Outbounds {
				if server, ok := outbound["server"].(string); ok {
					servers = append(servers, server)
					if outbound["detour"] != nil {
						t.Fatal("single node still chained", outbound)
					}
				}
			}
			checkServers(servers, exits)
			if strings.Contains(response.Body.String(), "中转") {
				t.Fatal("single sing-box contains relay")
			}
		}
	}
	for _, endpoint := range []struct {
		path    string
		handler http.HandlerFunc
	}{
		{"/sub/clash", apiSubClash}, {"/sub/singbox", apiSubSingBox}, {"/sub/v2ray", apiSubV2ray},
	} {
		response = request(endpoint.handler, endpoint.path+query, 200)
		if response.Header().Get("X-NodeCTL-Topology") != "single" || !strings.Contains(response.Header().Get("Cache-Control"), "no-store") {
			t.Fatal("missing topology/cache headers", endpoint.path, response.Header())
		}
		request(endpoint.handler, endpoint.path+"?token=test%26token&topology=invalid", 400)
		request(endpoint.handler, endpoint.path+"?token=wrong&topology=single", 403)
	}
}
