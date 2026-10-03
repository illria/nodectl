package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
	"nodectl/internal/database"
	"nodectl/internal/logger"
)

func TestSingBoxSubscriptionAndRules(t *testing.T) {
	db, e := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "singbox.db")), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if e != nil {
		t.Fatal(e)
	}
	if e = db.AutoMigrate(&database.SysConfig{}, &database.NodePool{}, &database.AirportNode{}, &database.CustomNode{}); e != nil {
		t.Fatal(e)
	}
	oldDB, oldLog := database.DB, logger.Log
	database.DB = db
	logger.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Cleanup(func() { database.DB = oldDB; logger.Log = oldLog })
	for _, cfg := range []database.SysConfig{{Key: "sub_token", Value: "secret"}, {Key: "panel_url", Value: "https://panel.example"}, {Key: "clash_custom_direct_raw", Value: "direct.example\n203.0.113.0/24"}, {Key: "clash_custom_proxy_rules", Value: `[{"id":"custom","name":"Custom","content":"proxy.example"}]`}} {
		if e = db.Create(&cfg).Error; e != nil {
			t.Fatal(e)
		}
	}
	for _, node := range []database.CustomNode{{Name: "香港落地", Link: "vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls#HK", RoutingType: 2}, {Name: "中转", Link: "socks5://192.0.2.2:1080#Relay", RoutingType: 1}, {Name: "AnyTLS", Link: "anytls://test@192.0.2.3:443#AnyTLS", RoutingType: 2}} {
		if e = db.Create(&node).Error; e != nil {
			t.Fatal(e)
		}
	}
	for _, version := range []string{"1.8", "1.9", "1.10", "1.11", "1.12", "1.13", "1.14"} {
		w := httptest.NewRecorder()
		apiSubSingBox(w, httptest.NewRequest(http.MethodGet, "https://panel.example/sub/singbox?token=secret&version="+version, nil))
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", version, w.Code, w.Body.String())
		}
		var config map[string]interface{}
		if e = json.Unmarshal(w.Body.Bytes(), &config); e != nil {
			t.Fatal(e)
		}
		if !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
			t.Fatal("subscription cached")
		}
		for _, out := range config["outbounds"].([]interface{}) {
			o := out.(map[string]interface{})
			if strings.HasPrefix(o["tag"].(string), "落地 · ") && o["detour"] != "💠 中转策略" {
				t.Fatal("missing relay chaining")
			}
		}
	}
	for _, path := range []string{"/sub/singbox?token=wrong", "/sub/singbox?token=secret&version=1.15", "/sub/singbox?token=secret&mode=bad"} {
		w := httptest.NewRecorder()
		apiSubSingBox(w, httptest.NewRequest("GET", "https://panel.example"+path, nil))
		if w.Code == 200 {
			t.Fatal("invalid input accepted", path)
		}
	}
	for _, topology := range []string{"chain", "single"} {
		for _, mode := range []string{"", "mobile", "full"} {
			for _, ip := range []string{"", "ipv4", "dual", "invalid"} {
				w := httptest.NewRecorder()
				apiSubSingBox(w, httptest.NewRequest("GET", "https://panel.example/sub/singbox?token=secret&topology="+topology+"&mode="+mode+"&ip="+ip, nil))
				if ip == "invalid" {
					if w.Code != 400 {
						t.Fatal("invalid IP mode accepted", w.Code)
					}
					continue
				}
				if w.Code != 200 {
					t.Fatal(w.Code, w.Body.String())
				}
				var config struct {
					DNS struct {
						Strategy string `json:"strategy"`
					} `json:"dns"`
				}
				if e = json.Unmarshal(w.Body.Bytes(), &config); e != nil {
					t.Fatal(e)
				}
				resolved := ip
				if resolved == "" {
					resolved = "ipv4"
					if mode == "full" {
						resolved = "dual"
					}
				}
				strategy := "prefer_ipv4"
				if resolved == "ipv4" {
					strategy = "ipv4_only"
				}
				if config.DNS.Strategy != strategy || w.Header().Get("X-NodeCTL-IP-Mode") != resolved {
					t.Fatal("IP mode not applied", mode, ip)
				}
			}
		}
	}
	w := httptest.NewRecorder()
	apiSubSingBox(w, httptest.NewRequest("GET", "https://panel.example/sub/singbox?token=secret&version=1.8&inspect=1", nil))
	if !strings.Contains(w.Body.String(), "AnyTLS") {
		t.Fatal("skip warning missing", w.Body.String())
	}
	for _, name := range []string{"我的直连规则", "Custom_自定义分流"} {
		w := httptest.NewRecorder()
		apiSubSingBoxRules(w, httptest.NewRequest("GET", "https://panel.example/sub/singbox/rules/"+name+"?token=secret", nil))
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var doc map[string]interface{}
		if e = json.Unmarshal(w.Body.Bytes(), &doc); e != nil {
			t.Fatal(e)
		}
		if doc["version"] != float64(1) {
			t.Fatal("source format version incompatible")
		}
	}
	w = httptest.NewRecorder()
	apiSubSingBoxRules(w, httptest.NewRequest("GET", "https://panel.example/sub/singbox/rules/我的直连规则?token=secret&format=binary", nil))
	if w.Code != 200 || !strings.HasPrefix(w.Body.String(), "SRS\x01") {
		t.Fatal("binary rule endpoint failed", w.Code)
	}
	w = httptest.NewRecorder()
	apiSubSingBoxRules(w, httptest.NewRequest("GET", "https://panel.example/sub/singbox/rules/unknown?token=secret", nil))
	if w.Code == 200 {
		t.Fatal("unknown ruleset accepted")
	}
}
