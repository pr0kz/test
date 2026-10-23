// Command server 是 Banner 指纹识别服务端。
//
// 关键设计：
//   - 规则来自 go:embed（默认）或 -rules-dir（外部覆盖），启动即编译，编译失败直接退出；
//   - -healthcheck 子模式：向自身 /health 发一次请求并按结果退出 0/1。
//     之所以内置而不是用 curl，是因为运行镜像是 scratch —— 里面没有任何 shell 或 HTTP 客户端。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"bannerfp/internal/api"
	"bannerfp/internal/engine"
	"bannerfp/internal/obs"
	"bannerfp/rules"
)

// version 由 -ldflags "-X main.version=..." 注入。
var version = "dev"

func main() {
	var (
		addr        = flag.String("addr", env("BFP_ADDR", ":8080"), "listen address, e.g. :8080")
		rulesDir    = flag.String("rules-dir", env("BFP_RULES_DIR", ""), "load rules from this directory instead of the embedded ruleset")
		logLevel    = flag.String("log-level", env("BFP_LOG_LEVEL", "info"), "log level: debug|info|warn|error")
		maxItems    = flag.Int("max-items", envInt("BFP_MAX_ITEMS", api.DefaultMaxItems), "max scan items accepted per request")
		healthcheck = flag.Bool("healthcheck", false, "probe own /health endpoint and exit 0 (healthy) or 1 (unhealthy)")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	logger := obs.NewLogger(*logLevel)
	if *healthcheck {
		if err := probeHealth(*addr); err != nil {
			fmt.Fprintf(os.Stderr, "healthcheck failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("healthy")
		return
	}

	if err := run(logger, *addr, *rulesDir, *maxItems); err != nil {
		logger.Error("server exited with error", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger, addr, rulesDir string, maxItems int) error {
	rs, source, err := loadRules(rulesDir)
	if err != nil {
		return fmt.Errorf("load rules: %w", err)
	}
	eng, err := engine.New(rs)
	if err != nil {
		return fmt.Errorf("compile rules: %w", err)
	}

	srv := api.New(api.Config{
		Engine:       eng,
		Version:      version,
		MaxItems:     maxItems,
		MaxBodyBytes: api.DefaultMaxBodyBytes,
		Logger:       logger,
		Started:      time.Now(),
	})

	httpSrv := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	logger.Info("banner fingerprint server started",
		"version", version,
		"addr", ln.Addr().String(),
		"rules_source", source,
		"rules_version", rs.Version,
		"probes", rs.ProbeCount(),
		"os_hints", rs.OSHintCount(),
		"max_items", maxItems,
	)

	errCh := make(chan error, 1)
	go func() {
		if serveErr := httpSrv.Serve(ln); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-stop:
		logger.Info("shutdown signal received, draining", "signal", sig.String())
	case serveErr := <-errCh:
		return serveErr
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	logger.Info("server stopped cleanly")
	return nil
}

func loadRules(dir string) (*rules.RuleSet, string, error) {
	if dir == "" {
		rs, err := rules.LoadBuiltin()
		return rs, "embedded", err
	}
	rs, err := rules.LoadDir(dir)
	return rs, dir, err
}

// probeHealth 供容器 healthcheck 使用：纯 Go 实现，不依赖 curl/wget/shell。
func probeHealth(addr string) error {
	url := healthURL(addr)
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}
	return nil
}

func healthURL(addr string) string {
	if strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://") {
		return strings.TrimRight(addr, "/") + "/health"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host, port = "", "8080"
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		host = "127.0.0.1"
	}
	return fmt.Sprintf("http://%s/health", net.JoinHostPort(host, port))
}

func env(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	v := env(key, "")
	if v == "" {
		return fallback
	}
	var n int
	if _, err := fmt.Sscanf(strings.TrimSpace(v), "%d", &n); err != nil {
		return fallback
	}
	return n
}
