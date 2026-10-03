package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"nodectl/internal/database"
	"nodectl/internal/service"
	"nodectl/internal/version"
)

func apiSubSingBox(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", 405)
		return
	}
	if !verifySubToken(r) {
		http.Error(w, "Invalid Token", 403)
		return
	}
	coreVersion, mode := r.URL.Query().Get("version"), r.URL.Query().Get("mode")
	topology, err := service.ParseSubscriptionTopology(r.URL.Query().Get("topology"))
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if _, err := service.SingBoxMinor(coreVersion); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if mode != "" && mode != "mobile" && mode != "full" && mode != "outbounds" {
		http.Error(w, "mode 必须为 mobile、full 或 outbounds", 400)
		return
	}
	var flag, name database.SysConfig
	database.DB.Where("key = ?", "pref_use_emoji_flag").First(&flag)
	database.DB.Where("key = ?", "sub_custom_name").First(&name)
	if name.Value == "" {
		name.Value = "NodeCTL"
	}
	data, warnings, err := service.GenerateSingBoxConfigWithTopology(getBaseURL(r), r.URL.Query().Get("token"), coreVersion, mode, flag.Value != "false", topology)
	if err != nil {
		http.Error(w, err.Error(), 422)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("X-NodeCTL-Version", version.Version)
	w.Header().Set("X-NodeCTL-Topology", string(topology))
	w.Header().Set("X-NodeCTL-Skipped-Nodes", strconv.Itoa(len(warnings)))
	w.Header().Set("profile-title", name.Value)
	if info := service.GetSubscriptionUserinfo(); info != "" {
		w.Header().Set("Subscription-Userinfo", info)
	}
	if r.URL.Query().Get("inspect") == "1" {
		json.NewEncoder(w).Encode(map[string]interface{}{"skipped_nodes": warnings})
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename*=utf-8''%s.json`, url.QueryEscape(name.Value)))
	w.Write(data)
}

func apiSubSingBoxRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", 405)
		return
	}
	if !verifySubToken(r) {
		http.Error(w, "Invalid Token", 403)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/sub/singbox/rules/")
	data, err := service.GenerateSingBoxRuleSet(r.Context(), name, getBaseURL(r), r.URL.Query().Get("token"))
	if err != nil {
		http.Error(w, err.Error(), 422)
		return
	}
	format := r.URL.Query().Get("format")
	if format != "" && format != "source" && format != "binary" {
		http.Error(w, "format 必须为 source 或 binary", 400)
		return
	}
	if format == "binary" {
		data, err = service.CompileSingBoxRuleSet(data)
		if err != nil {
			http.Error(w, "规则集编译失败", 422)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
	} else {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Write(data)
}
