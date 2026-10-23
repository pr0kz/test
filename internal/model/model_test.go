package model

import (
	"testing"
)

// TestDecodeInputsShapes 覆盖数组 / 包装对象 / 单对象 / NDJSON 四种投递形态。
func TestDecodeInputsShapes(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		{"数组", `[{"ip":"1.1.1.1","port":22,"banner":"SSH-2.0-x"},{"ip":"1.1.1.2","port":80,"banner":"HTTP/1.1 200 OK"}]`, 2},
		{"items 包装", `{"items":[{"ip":"1.1.1.1","port":22,"banner":"x"}]}`, 1},
		{"单对象", `{"ip":"1.1.1.1","port":22,"banner":"x"}`, 1},
		{"NDJSON", "{\"ip\":\"1.1.1.1\",\"port\":22,\"banner\":\"a\"}\n{\"ip\":\"1.1.1.2\",\"port\":23,\"banner\":\"b\"}\n", 2},
		{"空数组", `[]`, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			items, err := DecodeInputs([]byte(c.body))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(items) != c.want {
				t.Fatalf("got %d items, want %d", len(items), c.want)
			}
		})
	}
}

// TestDecodeInputsTolerantFields 字段别名、字符串端口、base64 banner 都要能吃下。
func TestDecodeInputsTolerantFields(t *testing.T) {
	body := `[{"host":"1.1.1.1","port":"3306","banner_b64":"SgAAAAo4LjAuMzIA"},{"address":"1.1.1.2","port":80}]`
	items, err := DecodeInputs([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("got %d items", len(items))
	}
	if items[0].IP != "1.1.1.1" || items[0].Port != 3306 {
		t.Fatalf("alias/string port not handled: %+v", items[0])
	}
	if items[0].Banner != "J\x00\x00\x00\n8.0.32\x00" {
		t.Fatalf("base64 banner not decoded: %q", items[0].Banner)
	}
	if items[1].IP != "1.1.1.2" || items[1].Banner != "" {
		t.Fatalf("missing banner should stay empty: %+v", items[1])
	}
}

// TestSanitizeInvalidJSONEscapes 采集器输出的非严格 JSON（\x00 转义）必须能被修复。
func TestSanitizeInvalidJSONEscapes(t *testing.T) {
	body := `[{"ip":"1.2.3.7","port":3306,"banner":"J\x00\x00\x00\n8.0.32\x00"}]`
	items, err := DecodeInputs([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// \x00 以字面量形式保留，由 banner 归一化层还原成单个字节；
	// \n 是合法 JSON 转义，直接还原成换行。
	want := `J\x00\x00\x00` + "\n" + `8.0.32\x00`
	if items[0].Banner != want {
		t.Fatalf("banner = %q, want %q", items[0].Banner, want)
	}
}

// TestSanitizeValidJSONUntouched 合法 JSON 不应被改动。
func TestSanitizeValidJSONUntouched(t *testing.T) {
	body := []byte(`[{"ip":"1.1.1.1","banner":"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"}]`)
	got := sanitizeJSON(body)
	if string(got) != string(body) {
		t.Fatalf("sanitizer modified valid JSON:\n in=%s\nout=%s", body, got)
	}
}

func TestDecodeInputsErrors(t *testing.T) {
	for _, body := range []string{``, `   `, `hello`, `[{"ip":}]`} {
		if _, err := DecodeInputs([]byte(body)); err == nil {
			t.Fatalf("body %q should fail", body)
		}
	}
}
