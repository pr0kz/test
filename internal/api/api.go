// Package api 是 HTTP 接入层：路由、请求校验、错误语义、panic 兜底与访问日志。
//
// 契约（详见 README『HTTP 接口』）：
//
//	POST /fingerprint  批量识别，返回与输入等长、同序的结果数组
//	GET  /health       健康检查（compose healthcheck 打的就是这里）
//	GET  /version      构建版本与规则版本
//
// 设计要点：单条脏数据只影响自己（回落 unknown），绝不让整批 5xx；
// 传输/结构层面的问题才用 4xx 明确拒绝。
package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"bannerfp/internal/engine"
	"bannerfp/internal/model"
	"bannerfp/internal/pipeline"
)

// 请求体与批量规模上限，防止单个请求打爆内存/CPU。
const (
	DefaultMaxItems     = 20000
	DefaultMaxBodyBytes = 32 << 20
)

// Config 是接入层的全部外部依赖，注入式构造便于测试。
type Config struct {
	Engine       *engine.Engine
	Version      string
	MaxItems     int
	MaxBodyBytes int64
	Logger       *slog.Logger
	Started      time.Time
}

// Server 持有 handler 状态。
type Server struct {
	cfg        Config
	totalReqs  atomic.Uint64
	totalItems atomic.Uint64
	unknown    atomic.Uint64
}

// New 构造接入层。
func New(cfg Config) *Server {
	if cfg.MaxItems <= 0 {
		cfg.MaxItems = DefaultMaxItems
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Started.IsZero() {
		cfg.Started = time.Now()
	}
	return &Server{cfg: cfg}
}

// Handler 返回带中间件的完整路由。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /fingerprint", s.handleFingerprint)
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /version", s.handleVersion)
	mux.HandleFunc("/", s.handleNotFound)
	return s.recoverer(s.accessLog(mux))
}

// ---- handlers ----

func (s *Server) handleFingerprint(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
	body := make([]byte, 0)
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Body.Read(buf)
		body = append(body, buf[:n]...)
		if err != nil {
			break
		}
	}

	items, err := model.DecodeInputs(body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if ok := asMaxBytes(err, &tooLarge); ok {
			s.writeError(w, http.StatusRequestEntityTooLarge, "body_too_large",
				"request body exceeds "+strconv.FormatInt(s.cfg.MaxBodyBytes, 10)+" bytes")
			return
		}
		s.writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	if len(items) > s.cfg.MaxItems {
		s.writeError(w, http.StatusRequestEntityTooLarge, "batch_too_large",
			"batch size "+strconv.Itoa(len(items))+" exceeds limit "+strconv.Itoa(s.cfg.MaxItems))
		return
	}

	started := time.Now()
	results := pipeline.Run(s.cfg.Engine, items)

	s.totalReqs.Add(1)
	s.totalItems.Add(uint64(len(results)))
	for _, res := range results {
		if res.Protocol == model.ProtocolUnknown {
			s.unknown.Add(1)
		}
	}
	s.cfg.Logger.Debug("fingerprint batch processed",
		"items", len(results),
		"duration_ms", time.Since(started).Milliseconds(),
		"request_id", requestID(r),
	)
	s.writeJSON(w, http.StatusOK, results)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	rs := s.cfg.Engine.RuleSet()
	s.writeJSON(w, http.StatusOK, map[string]any{
		"status":         "ok",
		"service":        "banner-fingerprint",
		"version":        s.cfg.Version,
		"rules_version":  rs.Version,
		"probes":         rs.ProbeCount(),
		"os_hints":       rs.OSHintCount(),
		"uptime_seconds": int64(time.Since(s.cfg.Started).Seconds()),
		"stats": map[string]any{
			"requests": s.totalReqs.Load(),
			"items":    s.totalItems.Load(),
			"unknown":  s.unknown.Load(),
		},
	})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	rs := s.cfg.Engine.RuleSet()
	s.writeJSON(w, http.StatusOK, map[string]any{
		"version":       s.cfg.Version,
		"rules_version": rs.Version,
		"rule_files":    rs.SourceFiles(),
		"probes":        rs.ProbeCount(),
	})
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	// ServeMux 的兜底路由会吞掉"路径存在但方法不对"的请求，这里显式还原 405 语义。
	if allow := allowedMethods(r.URL.Path); allow != "" && !strings.Contains(allow, r.Method) {
		w.Header().Set("Allow", allow)
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed",
			r.Method+" is not allowed on "+r.URL.Path+"; allowed: "+allow)
		return
	}
	s.writeError(w, http.StatusNotFound, "not_found",
		"unknown path "+r.Method+" "+r.URL.Path+"; try POST /fingerprint or GET /health")
}

func allowedMethods(path string) string {
	switch path {
	case "/fingerprint":
		return "POST"
	case "/health", "/version":
		return "GET"
	}
	return ""
}

// ---- middleware ----

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		if sw.status == 0 {
			sw.status = http.StatusOK
		}
		s.cfg.Logger.Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"bytes", sw.bytes,
			"duration_ms", time.Since(started).Milliseconds(),
			"remote", r.RemoteAddr,
			"request_id", requestID(r),
		)
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.cfg.Logger.Error("panic recovered", "panic", rec, "path", r.URL.Path, "request_id", requestID(r))
				s.writeError(w, http.StatusInternalServerError, "internal_error", "unexpected server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// ---- helpers ----

func (s *Server) writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		s.cfg.Logger.Error("encode response failed", "err", err)
	}
}

func (s *Server) writeError(w http.ResponseWriter, status int, code, detail string) {
	s.writeJSON(w, status, map[string]string{"error": code, "detail": detail})
}

func requestID(r *http.Request) string {
	if id := r.Header.Get("X-Request-ID"); id != "" {
		return strings.TrimSpace(id)
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "-"
	}
	return hex.EncodeToString(b[:])
}

func asMaxBytes(err error, target **http.MaxBytesError) bool {
	for err != nil {
		if e, ok := err.(*http.MaxBytesError); ok {
			*target = e
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
