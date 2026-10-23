package banner

import (
	"bytes"
	"testing"
)

func TestDecodeUnescapesLiteralSequences(t *testing.T) {
	v := Decode(`J\x00\x00\x00\n8.0.32\x00`)
	want := []byte{'J', 0, 0, 0, '\n', '8', '.', '0', '.', '3', '2', 0}
	if !bytes.Equal(v.Raw, want) {
		t.Fatalf("raw = %q, want %q", v.Raw, want)
	}
	if !v.Escaped || !v.Binary {
		t.Fatalf("expected Escaped and Binary flags, got %+v", v)
	}
}

// \u00a5 必须还原成单字节 0xa5，而不是 UTF-8 的两字节。
func TestDecodeUnicodeSingleByte(t *testing.T) {
	v := Decode(`\u00a5\u0016`)
	if !bytes.Equal(v.Raw, []byte{0xa5, 0x16}) {
		t.Fatalf("raw = % x, want a5 16", v.Raw)
	}
}

func TestDecodeKeepsPlainText(t *testing.T) {
	v := Decode("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0")
	if v.Escaped || v.Binary {
		t.Fatalf("plain HTTP banner flagged as escaped/binary: %+v", v)
	}
	if v.FirstLine != "http/1.1 200 ok" {
		t.Fatalf("first line = %q", v.FirstLine)
	}
	if !bytes.Contains(v.Lower, []byte("server: nginx/1.24.0")) {
		t.Fatalf("lower view = %q", v.Lower)
	}
}

// 非法 UTF-8 必须逐字节保留（不能用 strings.ToLower）。
func TestDecodePreservesHighBytes(t *testing.T) {
	raw := string([]byte{0xff, 0xfd, 0x18, 0xfe, 0x00})
	v := Decode(raw)
	if !bytes.Equal(v.Raw, []byte{0xff, 0xfd, 0x18, 0xfe, 0x00}) {
		t.Fatalf("raw = % x", v.Raw)
	}
}

func TestDecodeTruncates(t *testing.T) {
	big := make([]byte, MaxBytes+1024)
	for i := range big {
		big[i] = 'a'
	}
	v := Decode(string(big))
	if v.Len() != MaxBytes || !v.Truncated {
		t.Fatalf("len = %d, truncated = %v", v.Len(), v.Truncated)
	}
}

func TestSnippetEscapesControlBytes(t *testing.T) {
	got := Snippet("ab\x00\r\ncd", 20)
	want := `ab\x00\r\ncd`
	if got != want {
		t.Fatalf("snippet = %q, want %q", got, want)
	}
}
