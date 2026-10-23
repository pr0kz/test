package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"bannerfp/internal/api"
	"bannerfp/internal/engine"
	"bannerfp/internal/model"
	"bannerfp/rules"
)

func newHandler(t *testing.T) http.Handler {
	t.Helper()
	rs, err := rules.LoadBuiltin()
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	eng, err := engine.New(rs)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	return api.New(api.Config{Engine: eng, Version: "test", Started: time.Now()}).Handler()
}

func do(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestFingerprintBatch(t *testing.T) {
	h := newHandler(t)
	body := `[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
	          {"ip":"1.2.3.23","port":12345,"banner":"QUIT\r\n"},
	          {"ip":"1.2.3.7","port":3306,"banner":"J\x00\x00\x00\n8.0.32\x00"}]`
	rec := do(t, h, http.MethodPost, "/fingerprint", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var results []model.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}
	// 顺序必须与输入严格一致
	if results[0].Protocol != "SSH" || results[0].Product != "OpenSSH" || results[0].Version != "8.9p1" {
		t.Fatalf("unexpected result[0]: %+v", results[0])
	}
	if results[1].Protocol != model.ProtocolUnknown {
		t.Fatalf("unexpected result[1]: %+v", results[1])
	}
	if results[2].Protocol != "MySQL" || results[2].Version != "8.0.32" {
		t.Fatalf("unexpected result[2]: %+v", results[2])
	}
}

// TestFingerprintBadItemsDoNotFailBatch 单条脏数据只影响自己。
func TestFingerprintBadItemsDoNotFailBatch(t *testing.T) {
	h := newHandler(t)
	body := `[{"ip":"1.1.1.1"},{"banner":"SSH-2.0-x","port":"22"},{"ip":"1.1.1.3","port":80,"banner":""}]`
	rec := do(t, h, http.MethodPost, "/fingerprint", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var results []model.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}
	for _, r := range results {
		if r.Protocol == "" {
			t.Fatalf("protocol must never be empty string: %+v", r)
		}
	}
}

func TestFingerprintRejectsBadBody(t *testing.T) {
	h := newHandler(t)
	rec := do(t, h, http.MethodPost, "/fingerprint", `not json at all`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	var payload map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if payload["error"] == "" {
		t.Fatalf("error body missing error code: %v", payload)
	}
}

func TestFingerprintBatchLimit(t *testing.T) {
	rs, err := rules.LoadBuiltin()
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	eng, err := engine.New(rs)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	h := api.New(api.Config{Engine: eng, Version: "test", MaxItems: 1}).Handler()
	rec := do(t, h, http.MethodPost, "/fingerprint",
		`[{"ip":"1.1.1.1","port":22,"banner":"SSH-2.0-x"},{"ip":"1.1.1.2","port":22,"banner":"SSH-2.0-y"}]`)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}

func TestHealthAndVersion(t *testing.T) {
	h := newHandler(t)
	for _, path := range []string{"/health", "/version"} {
		rec := do(t, h, http.MethodGet, path, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d", path, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Fatalf("%s content-type = %q", path, ct)
		}
	}
	var health map[string]any
	rec := do(t, h, http.MethodGet, "/health", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &health); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if health["status"] != "ok" {
		t.Fatalf("health status = %v", health["status"])
	}
	if probes, ok := health["probes"].(float64); !ok || probes <= 0 {
		t.Fatalf("health should report loaded probes, got %v", health["probes"])
	}
}

func TestUnknownRouteAndMethod(t *testing.T) {
	h := newHandler(t)
	if rec := do(t, h, http.MethodGet, "/nope", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown path status = %d, want 404", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/fingerprint", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("wrong method status = %d, want 405", rec.Code)
	}
}
