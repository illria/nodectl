package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nodectl/internal/database"
	"nodectl/internal/version"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setAgentDownloadPanelVersion(t *testing.T, panelVersion string) {
	t.Helper()
	previous := version.Version
	version.Version = panelVersion
	t.Cleanup(func() { version.Version = previous })
}

func seedAgentDownloadAsset(t *testing.T, tag, arch, assetURL string) {
	t.Helper()
	key := "illria/nodectl|" + tag + "|nodectl-agent-linux-" + arch + "-"
	agentAssetCache.Lock()
	previousURL, hadURL := agentAssetCache.data[key]
	previousExpiry, hadExpiry := agentAssetCache.expiry[key]
	agentAssetCache.data[key] = assetURL
	agentAssetCache.expiry[key] = time.Now().Add(time.Hour)
	agentAssetCache.Unlock()
	t.Cleanup(func() {
		agentAssetCache.Lock()
		defer agentAssetCache.Unlock()
		if hadURL {
			agentAssetCache.data[key] = previousURL
		} else {
			delete(agentAssetCache.data, key)
		}
		if hadExpiry {
			agentAssetCache.expiry[key] = previousExpiry
		} else {
			delete(agentAssetCache.expiry, key)
		}
	})
}

func TestRCPanelServesStagingAgentsFromLocalImage(t *testing.T) {
	setAgentDownloadPanelVersion(t, "v0.4.76-custom.9-rc")
	dir := t.TempDir()
	t.Setenv("NODECTL_STAGING_AGENT_DIR", dir)
	for _, arch := range []string{"amd64", "arm64"} {
		filename := "nodectl-agent-linux-" + arch + "-v0.2.78-rc"
		if err := os.WriteFile(filepath.Join(dir, filename), []byte("synthetic-rc-agent-"+arch), 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/api/public/download/agent?arch="+arch+"&channel=stable", nil)
			apiDownloadAgent(response, request)
			filename := "nodectl-agent-linux-" + arch + "-v0.2.78-rc"
			if response.Code != http.StatusOK || response.Body.String() != "synthetic-rc-agent-"+arch ||
				response.Header().Get("Content-Type") != "application/octet-stream" ||
				response.Header().Get("Content-Disposition") != "attachment; filename=\""+filename+"\"" ||
				response.Header().Get("Location") != "" {
				t.Fatal("RC panel did not serve the matching local Agent binary")
			}
		})
	}
}

func TestRCPanelMissingAgentCannotFallbackToRelease(t *testing.T) {
	setAgentDownloadPanelVersion(t, "v0.4.76-custom.9-rc")
	t.Setenv("NODECTL_STAGING_AGENT_DIR", t.TempDir())
	// A cached Release URL makes an accidental fallthrough return 302 immediately.
	seedAgentDownloadAsset(t, version.Version, "amd64", "https://example.invalid/stable-agent")
	response := httptest.NewRecorder()
	apiDownloadAgent(response, httptest.NewRequest(http.MethodGet, "/api/public/download/agent?arch=amd64&channel=stable", nil))
	if response.Code != http.StatusInternalServerError ||
		!strings.Contains(response.Body.String(), "staging agent artifact unavailable") ||
		response.Header().Get("Location") != "" {
		t.Fatal("missing RC artifact fell back to a Release Agent")
	}
}

func TestRCPanelRejectsUnlistedAndTraversalArchitectures(t *testing.T) {
	setAgentDownloadPanelVersion(t, "v0.4.76-custom.9-rc")
	t.Setenv("NODECTL_STAGING_AGENT_DIR", t.TempDir())
	for _, arch := range []string{"../../etc/passwd", "/etc/passwd", "armv7", "386"} {
		t.Run(arch, func(t *testing.T) {
			response := httptest.NewRecorder()
			apiDownloadAgent(response, httptest.NewRequest(http.MethodGet, "/api/public/download/agent?arch="+arch+"&channel=stable", nil))
			if response.Code != http.StatusBadRequest || response.Header().Get("Location") != "" {
				t.Fatal("RC panel accepted an unlisted or traversal architecture")
			}
		})
	}
}

func TestNonRCPanelKeepsGitHubReleaseDelivery(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "agent-download.db")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&database.SysConfig{}); err != nil {
		t.Fatal(err)
	}
	previousDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = previousDB })
	dir := t.TempDir()
	t.Setenv("NODECTL_STAGING_AGENT_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "nodectl-agent-linux-amd64-v0.2.78-rc"), []byte("wrong-local-agent"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, panelVersion := range []string{"v0.4.76-custom.8", "v0.4.76-custom.9", "v0.4.77", "v0.4.77-alpha"} {
		t.Run(panelVersion, func(t *testing.T) {
			setAgentDownloadPanelVersion(t, panelVersion)
			assetURL := "https://example.invalid/releases/download/" + panelVersion + "/nodectl-agent-linux-amd64-v0.2.78"
			seedAgentDownloadAsset(t, panelVersion, "amd64", assetURL)
			response := httptest.NewRecorder()
			apiDownloadAgent(response, httptest.NewRequest(http.MethodGet, "/api/public/download/agent?arch=amd64", nil))
			if response.Code != http.StatusFound || response.Header().Get("Location") != assetURL ||
				strings.Contains(response.Body.String(), "wrong-local-agent") {
				t.Fatal("non-RC panel stopped using the GitHub Release asset path")
			}
		})
	}
}

func TestRCInstallScriptKeepsStableChannelForLocalAgentEndpoint(t *testing.T) {
	setAgentDownloadPanelVersion(t, "v0.4.76-custom.9-rc")
	script := generateMinimalInstallScript("relay000001", "https://panel.example", false)
	if !strings.Contains(script, "CHANNEL=\"stable\"") ||
		!strings.Contains(script, `local DOWNLOAD_URL="${PANEL_URL}/api/public/download/agent?arch=${ARCH}&channel=${CHANNEL}"`) ||
		!strings.Contains(script, `curl -fsSL "$DOWNLOAD_URL" -o "$AGENT_BIN"`) {
		t.Fatal("RC install script no longer downloads through the panel endpoint")
	}
}
