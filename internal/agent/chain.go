package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"time"

	"nodectl/internal/relaychain"
)

func (rt *Runtime) executeChainApply(cmd ServerCommand, reply func(CommandResult)) {
	var chain relaychain.Config
	if err := json.Unmarshal(cmd.Payload, &chain); err != nil {
		reply(CommandResult{Type: "result", Status: "error", Message: "无效中转链配置"})
		return
	}
	if err := chain.Validate(); err != nil {
		reply(CommandResult{Type: "result", Status: "error", Message: err.Error()})
		return
	}
	cm := rt.ensureSingboxManager().GetConfigManager()
	next := append([]relaychain.Config(nil), cm.Chains...)
	found := false
	for i := range next {
		if next[i].ID == chain.ID {
			next[i] = chain
			found = true
			break
		}
	}
	if !found {
		next = append(next, chain)
	}
	if err := rt.applyChainSet(next); err != nil {
		reply(CommandResult{Type: "result", Status: "error", Message: err.Error()})
		return
	}
	reply(CommandResult{Type: "result", Status: "ok", Message: "中转链配置已应用"})
}

func (rt *Runtime) executeChainDelete(cmd ServerCommand, reply func(CommandResult)) {
	var payload struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(cmd.Payload, &payload); err != nil || payload.ID == "" {
		reply(CommandResult{Type: "result", Status: "error", Message: "无效中转链 ID"})
		return
	}
	cm := rt.ensureSingboxManager().GetConfigManager()
	next := make([]relaychain.Config, 0, len(cm.Chains))
	for _, chain := range cm.Chains {
		if chain.ID != payload.ID {
			next = append(next, chain)
		}
	}
	if err := rt.applyChainSet(next); err != nil {
		reply(CommandResult{Type: "result", Status: "error", Message: err.Error()})
		return
	}
	reply(CommandResult{Type: "result", Status: "ok", Message: "中转链配置已删除"})
}

// applyChainSet saves the exact chain set before restarting sing-box. On a failed
// restart it restores the prior cache and config, then attempts to restore service.
// The caller holds rt.configMu.
func (rt *Runtime) applyChainSet(chains []relaychain.Config) error {
	mgr := rt.ensureSingboxManager()
	cm := mgr.GetConfigManager()
	previous := append([]relaychain.Config(nil), cm.Chains...)
	if len(previous) == len(chains) && (len(chains) == 0 || reflect.DeepEqual(previous, chains)) && mgr.IsRunning() {
		return nil
	}
	ctx := context.Background()
	if err := mgr.GetInstaller().EnsureInstalled(ctx); err != nil {
		return fmt.Errorf("sing-box 安装失败: %w", err)
	}
	if err := cm.ReplaceChains(chains); err != nil {
		return fmt.Errorf("保存中转链失败: %w", err)
	}
	if err := cm.GenerateAndSave(); err != nil {
		_ = cm.ReplaceChains(previous)
		return fmt.Errorf("生成中转链配置失败: %w", err)
	}
	mgr.ForceKill()
	if err := mgr.StartAndVerify(ctx, 3*time.Second); err != nil {
		_ = cm.ReplaceChains(previous)
		_ = cm.GenerateAndSave()
		mgr.ForceKill()
		if restoreErr := mgr.StartAndVerify(ctx, 3*time.Second); restoreErr != nil {
			log.Printf("[Agent] 恢复原有 sing-box 配置失败: %v", restoreErr)
		}
		return fmt.Errorf("启动中转链失败: %w", err)
	}
	return nil
}

func (rt *Runtime) refreshChainsFromPanel(ctx context.Context) {
	chains, err := rt.fetchPanelChains(ctx)
	if err != nil {
		log.Printf("[Agent] 重连后获取中转链失败，保留本地缓存: %v", err)
		return
	}
	rt.configMu.Lock()
	defer rt.configMu.Unlock()
	if err := rt.applyChainSet(chains); err != nil {
		log.Printf("[Agent] 重连后恢复中转链失败: %v", err)
	}
}
