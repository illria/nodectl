package service

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"nodectl/internal/database"
	"nodectl/internal/logger"
)

const (
	airportAutoUpdateEnabledKey  = "airport_auto_update_enabled"
	airportAutoUpdateIntervalKey = "airport_auto_update_interval_minutes"
	defaultAirportAutoUpdateMins = 360
	maxAirportAutoUpdateMins     = 10080
)

var airportSubscriptionAutoUpdateOnce sync.Once

// StartAirportSubscriptionAutoUpdate starts the serialized subscription sync loop once.
func StartAirportSubscriptionAutoUpdate() {
	airportSubscriptionAutoUpdateOnce.Do(func() {
		go func() {
			time.Sleep(time.Minute)
			runAirportSubscriptionAutoUpdate()

			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				runAirportSubscriptionAutoUpdate()
			}
		}()
	})
}

func runAirportSubscriptionAutoUpdate() {
	if database.DB == nil {
		logger.Log.Warn("机场订阅自动同步跳过：数据库未初始化")
		return
	}
	if !isSysConfigEnabled(airportAutoUpdateEnabledKey) {
		return
	}

	intervalMinutes := airportSubscriptionAutoUpdateInterval()
	interval := time.Duration(intervalMinutes) * time.Minute
	var subs []database.AirportSub
	if err := database.DB.Find(&subs).Error; err != nil {
		logger.Log.Error("读取机场订阅列表失败", "error", err)
		return
	}

	now := time.Now()
	due := make([]database.AirportSub, 0, len(subs))
	for _, sub := range subs {
		if sub.UpdatedAt.IsZero() || now.Sub(sub.UpdatedAt) >= interval {
			due = append(due, sub)
		}
	}

	logger.Log.Info("开始自动同步机场订阅", "due", len(due), "interval_minutes", intervalMinutes)
	success, failed := 0, 0
	for i, sub := range due {
		if err := SyncAirportSubscription(sub.ID); err != nil {
			failed++
			logger.Log.Error("机场订阅自动同步失败", "id", sub.ID, "name", sub.Name, "error", err)
		} else {
			success++
			logger.Log.Info("机场订阅自动同步成功", "id", sub.ID, "name", sub.Name)
		}
		if i < len(due)-1 {
			time.Sleep(3 * time.Second)
		}
	}
	logger.Log.Info("机场订阅自动同步完成", "success", success, "failed", failed)
}

func airportSubscriptionAutoUpdateInterval() int {
	minutes, err := strconv.Atoi(strings.TrimSpace(getSysConfigValue(airportAutoUpdateIntervalKey)))
	if err != nil || minutes < 1 || minutes > maxAirportAutoUpdateMins {
		return defaultAirportAutoUpdateMins
	}
	return minutes
}
