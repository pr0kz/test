package engine_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"bannerfp/internal/engine"
	"bannerfp/internal/model"
	"bannerfp/rules"
)

type expectedItem struct {
	IP            string  `json:"ip"`
	Port          int     `json:"port"`
	Protocol      string  `json:"protocol"`
	Product       string  `json:"product"`
	Version       string  `json:"version"`
	OSHint        string  `json:"os_hint"`
	ConfidenceMin float64 `json:"confidence_min"`
}

func newEngine(t *testing.T) *engine.Engine {
	t.Helper()
	rs, err := rules.LoadBuiltin()
	if err != nil {
		t.Fatalf("load builtin rules: %v", err)
	}
	eng, err := engine.New(rs)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	return eng
}

// TestGoldenExamples 用 examples/ 里的自测数据做端到端回归。
func TestGoldenExamples(t *testing.T) {
	eng := newEngine(t)

	inputRaw, err := os.ReadFile(filepath.Join("..", "..", "examples", "input.json"))
	if err != nil {
		t.Fatalf("read input: %v", err)
	}
	inputs, err := model.DecodeInputs(inputRaw)
	if err != nil {
		t.Fatalf("decode input: %v", err)
	}

	expectRaw, err := os.ReadFile(filepath.Join("..", "..", "examples", "expected.json"))
	if err != nil {
		t.Fatalf("read expected: %v", err)
	}
	var expected struct {
		Items []expectedItem `json:"items"`
	}
	if err := json.Unmarshal(expectRaw, &expected); err != nil {
		t.Fatalf("decode expected: %v", err)
	}
	if len(inputs) != len(expected.Items) {
		t.Fatalf("input has %d items but expected has %d", len(inputs), len(expected.Items))
	}

	for i, in := range inputs {
		want := expected.Items[i]
		got := eng.Identify(in)
		if got.Protocol != want.Protocol {
			t.Errorf("%s:%d protocol = %q, want %q", in.IP, in.Port, got.Protocol, want.Protocol)
		}
		if got.Product != want.Product {
			t.Errorf("%s:%d product = %q, want %q", in.IP, in.Port, got.Product, want.Product)
		}
		if got.Version != want.Version {
			t.Errorf("%s:%d version = %q, want %q", in.IP, in.Port, got.Version, want.Version)
		}
		if got.OSHint != want.OSHint {
			t.Errorf("%s:%d os_hint = %q, want %q", in.IP, in.Port, got.OSHint, want.OSHint)
		}
		if got.Confidence < want.ConfidenceMin {
			t.Errorf("%s:%d confidence = %.2f, want >= %.2f", in.IP, in.Port, got.Confidence, want.ConfidenceMin)
		}
		if got.Confidence < 0 || got.Confidence > 1 {
			t.Errorf("%s:%d confidence %.2f out of [0,1]", in.IP, in.Port, got.Confidence)
		}
	}
}

// TestBannerEncodings 验证同一份 banner 的三种投递形态都能识别。
func TestBannerEncodings(t *testing.T) {
	eng := newEngine(t)
	cases := []struct {
		name   string
		banner string
	}{
		{"真实字节", "J\x00\x00\x00\n8.0.32\x00"},
		{"字面量转义", `J\x00\x00\x00\n8.0.32\x00`},
		{"unicode 转义", "J\u0000\u0000\u0000\u000a8.0.32\u0000"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := eng.Identify(model.ScanInput{IP: "1.1.1.1", Port: 3306, Banner: c.banner})
			if got.Protocol != "MySQL" || got.Version != "8.0.32" {
				t.Fatalf("got %+v, want MySQL/8.0.32", got)
			}
		})
	}
}

// TestNeverPanicsAndAlwaysReturnsOneResult 保证脏输入只降级、不崩溃。
func TestNeverPanicsAndAlwaysReturnsOneResult(t *testing.T) {
	eng := newEngine(t)
	cases := []string{
		"", " ", "\x00", "quit\r\n", "220 ", "+OK", "SSH-", "HTTP/1.1",
		"\xff\xfb\x18\xff\xfd\x03", "\x16\x03", string(make([]byte, 1000)),
	}
	for _, banner := range cases {
		got := eng.Identify(model.ScanInput{IP: "9.9.9.9", Port: 0, Banner: banner})
		if got.Protocol == "" {
			t.Fatalf("banner %q produced empty protocol; unknown is expected instead", banner)
		}
		if got.IP != "9.9.9.9" {
			t.Fatalf("ip not passthrough: %+v", got)
		}
		if got.Confidence < 0 || got.Confidence > 1 {
			t.Fatalf("banner %q confidence %f out of range", banner, got.Confidence)
		}
	}
}

// TestUnknownIsNotAnError 确认"认不出"是合法结果而不是错误路径。
func TestUnknownIsNotAnError(t *testing.T) {
	eng := newEngine(t)
	got := eng.Identify(model.ScanInput{IP: "2.2.2.2", Port: 12345, Banner: "QUIT\r\n"})
	if got.Protocol != model.ProtocolUnknown {
		t.Fatalf("protocol = %q, want %q", got.Protocol, model.ProtocolUnknown)
	}
	if got.Confidence > 0.2 {
		t.Fatalf("unknown confidence = %f, want low", got.Confidence)
	}
}

// TestPortIsNotEvidence 确认端口不会用于否决证据（443 明文 HTTP / 9999 TLS）。
func TestPortIsNotEvidence(t *testing.T) {
	eng := newEngine(t)
	got := eng.Identify(model.ScanInput{IP: "3.3.3.3", Port: 443, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"})
	if got.Protocol != "HTTP" || got.Product != "nginx" {
		t.Fatalf("got %+v, want HTTP/nginx", got)
	}
	got = eng.Identify(model.ScanInput{IP: "3.3.3.4", Port: 80, Banner: "\x16\x03\x01\x00\xa5\x01\x00\x00\xa1"})
	if got.Protocol != "TLS" {
		t.Fatalf("got %+v, want TLS on port 80", got)
	}
}
