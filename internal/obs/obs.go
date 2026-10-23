// Package obs 提供结构化日志与构建信息，保证所有日志只写 stdout/stderr。
// 这一点与容器的 read_only 根文件系统配合：进程不落任何本地文件，容器才敢只读运行。
package obs

import (
	"log/slog"
	"os"
	"strings"
)

// NewLogger 返回 JSON 结构化 logger（生产可被 docker logs / Loki 直接采集）。
func NewLogger(level string) *slog.Logger {
	var lv slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		lv = slog.LevelDebug
	case "warn", "warning":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lv}))
}
