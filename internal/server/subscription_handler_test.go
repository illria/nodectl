package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"nodectl/internal/database"
	"nodectl/internal/logger"
	"nodectl/internal/version"

	"github.com/glebarez/sqlite"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func TestClashSubscriptionRoutesRelayAndExitProviders(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "subscription.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	if err := db.AutoMigrate(&database.SysConfig{}, &database.NodePool{}, &database.AirportNode{}, &database.CustomNode{}); err != nil {
		t.Fatalf("migrate test database: %v", err)
	}
	oldDB, oldLog := database.DB, logger.Log
	database.DB = db
	logger.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Cleanup(func() {
		database.DB = oldDB
		logger.Log = oldLog
	})
	for _, config := range []database.SysConfig{
		{Key: "sub_token", Value: "secret"},
		{Key: "panel_url", Value: "https://panel.example"},
		{Key: "clash_active_modules", Value: "Telegram,Google,External"},
		{Key: "clash_custom_direct_raw", Value: "203.0.113.0/24\n2001:db8::/32\ndirect.example.test"},
		{Key: "clash_custom_proxy_rules", Value: `[{"id":"custom","name":"Custom","content":"198.51.100.0/24\nproxy.example.test"}]`},
		{Key: "clash_custom_modules", Value: `[{"name":"External","url":"https://rules.example/external.list"}]`},
	} {
		if err := db.Create(&config).Error; err != nil {
			t.Fatalf("insert test config %s: %v", config.Key, err)
		}
	}

	recorder := httptest.NewRecorder()
	apiSubClash(recorder, httptest.NewRequest(http.MethodGet, "https://panel.example/sub/clash?token=secret", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("Clash subscription status = %d: %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") {
		t.Fatalf("Clash subscription can be cached: %q", got)
	}
	if got := recorder.Header().Get("X-NodeCTL-Version"); got != version.Version {
		t.Fatalf("subscription version = %q, want %q", got, version.Version)
	}
	var config struct {
		ProxyProviders map[string]struct {
			URL string `yaml:"url"`
		} `yaml:"proxy-providers"`
		Rules []string `yaml:"rules"`
	}
	if err := yaml.Unmarshal(recorder.Body.Bytes(), &config); err != nil {
		t.Fatalf("parse Clash subscription: %v", err)
	}
	if got, want := config.ProxyProviders["中转机场"].URL, "https://panel.example/sub/raw/1?token=secret"; got != want {
		t.Fatalf("relay provider URL = %q, want %q", got, want)
	}
	if got, want := config.ProxyProviders["落地机场"].URL, "https://panel.example/sub/raw/2?token=secret"; got != want {
		t.Fatalf("exit provider URL = %q, want %q", got, want)
	}
	for _, want := range []string{
		"RULE-SET,我的直连规则,DIRECT,no-resolve",
		"RULE-SET,WebRTC_端/域,REJECT,no-resolve",
		"RULE-SET,Custom_自定义分流,Custom,no-resolve",
		"RULE-SET,External_用户自定义,External,no-resolve",
		"RULE-SET,Telegram_IP,Telegram,no-resolve",
		"RULE-SET,Google_IP,Google,no-resolve",
		"GEOIP,CN,DIRECT,no-resolve",
	} {
		found := false
		for _, rule := range config.Rules {
			found = found || rule == want
		}
		if !found {
			t.Errorf("subscription is missing DNS-safe routing rule %q", want)
		}
	}
	var topLevel map[string]any
	if err := yaml.Unmarshal(recorder.Body.Bytes(), &topLevel); err != nil {
		t.Fatalf("parse subscription sections: %v", err)
	}
	for _, key := range []string{"dns", "tun", "sniffer", "ipv6"} {
		if _, ok := topLevel[key]; ok {
			t.Errorf("subscription overrides client setting %q", key)
		}
	}
	for _, tc := range []struct {
		path string
		want string
	}{
		{path: "/sub/rules/direct", want: "IP-CIDR,203.0.113.0/24\nIP-CIDR6,2001:db8::/32\nDOMAIN-SUFFIX,direct.example.test"},
		{path: "/sub/rules/proxy/custom", want: "IP-CIDR,198.51.100.0/24\nDOMAIN-SUFFIX,proxy.example.test"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			apiSubRuleList(response, httptest.NewRequest(http.MethodGet, "https://panel.example"+tc.path+"?token=secret", nil))
			if response.Code != http.StatusOK || response.Body.String() != tc.want {
				t.Fatalf("rule-list response = %d %q, want %q", response.Code, response.Body.String(), tc.want)
			}
		})
	}

	for _, tc := range []struct {
		path string
		name string
	}{
		{path: "/sub/raw/1", name: "⚠️ 无中转-自动直连"},
		{path: "/sub/raw/2", name: "⚠️ 无落地-自动直连"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			apiSubRaw(recorder, httptest.NewRequest(http.MethodGet, "https://panel.example"+tc.path+"?token=secret", nil))
			if recorder.Code != http.StatusOK {
				t.Fatalf("raw subscription status = %d: %s", recorder.Code, recorder.Body.String())
			}
			var provider struct {
				Proxies []struct {
					Name string `yaml:"name"`
					Type string `yaml:"type"`
				} `yaml:"proxies"`
			}
			if err := yaml.Unmarshal(recorder.Body.Bytes(), &provider); err != nil {
				t.Fatalf("parse raw provider: %v", err)
			}
			if len(provider.Proxies) != 1 || provider.Proxies[0].Name != tc.name || provider.Proxies[0].Type != "direct" {
				t.Fatalf("unexpected empty provider fallback: %#v", provider.Proxies)
			}
		})
	}
}
