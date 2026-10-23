// Command client 是独立的客户端程序：读取本地 JSON 文件 → 调服务端 /fingerprint → 展示结果。
//
// 它是部署里唯一的"业务调用方"，也用于人工自测：既不共享 server 的代码路径（除契约 model），
// 也不依赖 server 的规则，因此可以独立镜像、以非 root 只读方式跑一个一次性 Job。
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"bannerfp/internal/banner"
	"bannerfp/internal/model"
	"bannerfp/internal/report"
)

func main() {
	var (
		input   = flag.String("input", env("BFP_INPUT", "input.json"), "path to the JSON file with scan items")
		server  = flag.String("server", env("BFP_SERVER", "http://127.0.0.1:8080"), "server base URL")
		timeout = flag.Duration("timeout", 30*time.Second, "per-request timeout")
		batch   = flag.Int("batch", 500, "how many items to send per request")
		retries = flag.Int("retries", 3, "retry count for retryable failures (5xx / network)")
		asJSON  = flag.Bool("json", false, "print machine-readable JSON instead of a table")
		out     = flag.String("out", "", "also write results to this file (stdout only by default)")
		verbose = flag.Bool("verbose", true, "print progress lines")
	)
	flag.Parse()

	if err := run(*input, *server, *timeout, *batch, *retries, *asJSON, *out, *verbose); err != nil {
		fmt.Fprintf(os.Stderr, "client: %v\n", err)
		os.Exit(1)
	}
}

func run(inputPath, server string, timeout time.Duration, batchSize, retries int, asJSON bool, outPath string, verbose bool) error {
	if batchSize <= 0 {
		batchSize = 500
	}
	raw, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("read input file: %w", err)
	}
	items, err := model.DecodeInputs(raw)
	if err != nil {
		return fmt.Errorf("parse input file %s: %w", inputPath, err)
	}
	if len(items) == 0 {
		return fmt.Errorf("input file %s contains no scan items", inputPath)
	}
	if verbose {
		fmt.Printf("loaded %d scan item(s) from %s\nsending to %s/fingerprint in batches of %d\n\n",
			len(items), inputPath, strings.TrimRight(server, "/"), batchSize)
	}

	client := &http.Client{Timeout: timeout}
	endpoint := strings.TrimRight(server, "/") + "/fingerprint"

	results := make([]model.Result, 0, len(items))
	for start := 0; start < len(items); start += batchSize {
		end := start + batchSize
		if end > len(items) {
			end = len(items)
		}
		chunk := items[start:end]
		chunkResults, err := postBatch(client, endpoint, chunk, retries)
		if err != nil {
			return fmt.Errorf("fingerprint batch [%d:%d]: %w", start, end, err)
		}
		if len(chunkResults) != len(chunk) {
			return fmt.Errorf("server returned %d result(s) for %d item(s)", len(chunkResults), len(chunk))
		}
		results = append(results, chunkResults...)
		if verbose {
			fmt.Printf("  batch [%d:%d] ok (%d result(s))\n", start, end, len(chunkResults))
		}
	}
	if verbose {
		fmt.Println()
	}

	var payload string
	if asJSON {
		payload, err = report.JSON(results)
		if err != nil {
			return err
		}
	} else {
		payload = report.Table(results, items) + "\n" + report.Summary(results)
	}
	fmt.Print(payload)

	if outPath != "" {
		if err := os.WriteFile(outPath, []byte(payload), 0o644); err != nil {
			return fmt.Errorf("write output file: %w", err)
		}
		if verbose {
			fmt.Printf("\nresults written to %s\n", outPath)
		}
	}
	return nil
}

func postBatch(client *http.Client, endpoint string, items []model.ScanInput, retries int) ([]model.Result, error) {
	body, err := json.Marshal(items)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	delay := 250 * time.Millisecond
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			time.Sleep(delay)
			delay *= 2
		}
		results, retryable, err := doPost(client, endpoint, body)
		if err == nil {
			return results, nil
		}
		lastErr = err
		if !retryable {
			break
		}
	}
	return nil, lastErr
}

func doPost(client *http.Client, endpoint string, body []byte) ([]model.Result, bool, error) {
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, true, fmt.Errorf("post %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, true, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		retryable := resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests
		return nil, retryable, fmt.Errorf("server returned %d: %s", resp.StatusCode, bodySnippet(payload))
	}
	var results []model.Result
	if err := json.Unmarshal(payload, &results); err != nil {
		return nil, false, fmt.Errorf("decode response: %w (body: %s)", err, bodySnippet(payload))
	}
	return results, false, nil
}

func bodySnippet(b []byte) string {
	return banner.Snippet(strings.TrimSpace(string(b)), 200)
}

func env(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return v
	}
	return fallback
}

var _ = errors.New
