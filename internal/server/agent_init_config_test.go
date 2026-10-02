package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"nodectl/internal/database"
	"nodectl/internal/logger"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func TestAgentInitConfigContainsOnlyInitializationMetadata(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "agent-init.db")), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&database.SysConfig{}, &database.NodePool{}, &database.RelayChain{}); err != nil {
		t.Fatal(err)
	}
	oldDB, oldLog := database.DB, logger.Log
	database.DB, logger.Log = db, slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Cleanup(func() { database.DB, logger.Log = oldDB, oldLog })
	node := database.NodePool{UUID: "relay", InstallID: "relay000001", Links: map[string]string{"ss": "synthetic-link"}, LinkPorts: map[string]int{"ss": 31000}}
	if err := db.Create(&node).Error; err != nil {
		t.Fatal(err)
	}
	panel := database.SysConfig{Key: "panel_url", Value: "https://panel.example"}
	if err := db.Create(&panel).Error; err != nil {
		t.Fatal(err)
	}
	chain := database.RelayChain{ID: "chain-0123456789abcdef", RelayInstallID: node.InstallID, ExitInstallID: "exit0000001", Status: "active", Enabled: true,
		RelayPassword: "synthetic-relay-secret", ExitPassword: "synthetic-exit-secret", CompositeLink: "synthetic-private-composite"}
	if err := db.Create(&chain).Error; err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	apiAgentInitConfig(recorder, httptest.NewRequest(http.MethodGet, "/api/agent/init-config?install_id="+node.InstallID, nil))
	var response struct {
		Status string                     `json:"status"`
		Data   map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusOK || response.Status != "success" {
		t.Fatalf("init-config failed: status=%d API=%s", recorder.Code, response.Status)
	}
	var keys []string
	for key := range response.Data {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if !reflect.DeepEqual(keys, []string{"panel_url", "ports", "protocols", "sni", "ws_url"}) {
		t.Fatalf("unexpected init-config fields: %v", keys)
	}
	for _, forbidden := range []string{"chains", "password", chain.RelayPassword, chain.ExitPassword, chain.CompositeLink} {
		if strings.Contains(recorder.Body.String(), forbidden) {
			t.Fatalf("HTTP init-config contains forbidden field/value: %s", forbidden)
		}
	}
}
