package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"nodectl/internal/database"
	"nodectl/internal/logger"
	"nodectl/internal/relaychain"

	"github.com/glebarez/sqlite"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func TestClashSubscriptionUsesCompositeAndDirectProviders(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "subscription.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	if err := db.AutoMigrate(&database.SysConfig{}, &database.NodePool{}, &database.AirportNode{}, &database.CustomNode{}, &database.RelayChain{}); err != nil {
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
		{Key: "clash_active_modules", Value: "Telegram"},
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
	var config struct {
		ProxyProviders map[string]struct {
			URL string `yaml:"url"`
		} `yaml:"proxy-providers"`
	}
	if err := yaml.Unmarshal(recorder.Body.Bytes(), &config); err != nil {
		t.Fatalf("parse Clash subscription: %v", err)
	}
	if len(config.ProxyProviders) != 2 {
		t.Fatalf("provider count = %d, want 2", len(config.ProxyProviders))
	}
	if got, want := config.ProxyProviders["中转链"].URL, "https://panel.example/sub/chains?token=secret"; got != want {
		t.Fatalf("chain provider URL = %q, want %q", got, want)
	}
	if got, want := config.ProxyProviders["落地机场"].URL, "https://panel.example/sub/raw/2?token=secret"; got != want {
		t.Fatalf("exit provider URL = %q, want %q", got, want)
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
	chainRecorder := httptest.NewRecorder()
	apiSubChains(chainRecorder, httptest.NewRequest(http.MethodGet, "https://panel.example/sub/chains?token=secret", nil))
	if chainRecorder.Code != http.StatusOK {
		t.Fatalf("chain subscription status = %d: %s", chainRecorder.Code, chainRecorder.Body.String())
	}
	var empty struct {
		Proxies []struct {
			Name string `yaml:"name"`
			Type string `yaml:"type"`
		} `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(chainRecorder.Body.Bytes(), &empty); err != nil || len(empty.Proxies) != 1 || empty.Proxies[0].Type != "direct" {
		t.Fatalf("chain fallback = %#v, parse error = %v", empty.Proxies, err)
	}

	for _, node := range []database.NodePool{
		{UUID: "relay-node", Name: "Relay", RoutingType: 1, InstallID: "relay-install"},
		{UUID: "exit-node", Name: "Exit", RoutingType: 2, InstallID: "exit-install"},
	} {
		if err := db.Create(&node).Error; err != nil {
			t.Fatalf("create node: %v", err)
		}
	}
	chain := database.RelayChain{
		ID: "chain-0123456789abcdef", RelayNodeUUID: "relay-node", ExitNodeUUID: "exit-node",
		RelayName: "Relay", ExitName: "Exit", RelayIP: "198.51.100.10", Enabled: true, Status: "active",
		RelayListenPort: 31000, RelayMethod: relaychain.Method, RelayPassword: "AAAAAAAAAAAAAAAAAAAAAA==",
		ExitListenPort: 32000, ExitMethod: relaychain.Method, ExitPassword: "BBBBBBBBBBBBBBBBBBBBBB==",
	}
	if err := db.Create(&chain).Error; err != nil {
		t.Fatalf("create chain: %v", err)
	}
	chainRecorder = httptest.NewRecorder()
	apiSubChains(chainRecorder, httptest.NewRequest(http.MethodGet, "https://panel.example/sub/chains?token=secret", nil))
	var provider struct {
		Proxies []struct {
			Name, Type, Server, Cipher, Password string
			Port                                 int
			UDP                                  bool
		} `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(chainRecorder.Body.Bytes(), &provider); err != nil {
		t.Fatalf("parse chain provider: %v", err)
	}
	if len(provider.Proxies) != 1 || provider.Proxies[0].Type != "ss" ||
		provider.Proxies[0].Server != chain.RelayIP || provider.Proxies[0].Port != chain.RelayListenPort ||
		provider.Proxies[0].Password != chain.RelayPassword || !provider.Proxies[0].UDP {
		t.Fatalf("unexpected composite proxy: %#v", provider.Proxies)
	}
	if provider.Proxies[0].Port == chain.ExitListenPort || provider.Proxies[0].Password == chain.ExitPassword {
		t.Fatal("hidden Exit inbound leaked into composite provider")
	}
}
