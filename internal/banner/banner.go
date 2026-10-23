// Package banner 负责把"任意形态的 banner"归一化成可稳定匹配的字节序列。
//
// 这是整套识别的地基，也是这类系统最容易翻车的地方：同一份 MySQL 握手包可能以三种形态出现。
//
//	真实字节       0x4a 0x00 0x00 0x00 0x0a "8.0.32" 0x00
//	JSON \u 转义   "\u0000\u0000\u0000\u000a8.0.32\u0000"（json.Unmarshal 后与上一行等价）
//	字面量转义     "J\\x00\\x00\\x00\\n8.0.32\\x00"（采集器把不可打印字节 escape 成了文本）
//
// 如果不做归一化，第三种形态永远识别不出 MySQL。因此 Decode 统一还原 escapes，
// 并且额外提供 ASCII 小写视图（不能直接用 strings.ToLower：它会把非法 UTF-8 字节替换成 U+FFFD，
// 破坏二进制 banner）。
package banner

import (
	"bytes"
	"strings"
	"unicode/utf8"
)

// MaxBytes 是单条 banner 参与匹配的上限，超出部分截断。
// 64KB 足够覆盖任何已知协议的首包，同时把最坏耗时钳死在常量级。
const MaxBytes = 64 * 1024

const firstLineLimit = 256

// View 是一条 banner 的多视图表示，供不同匹配器按需取用。
type View struct {
	// Raw 是归一化后的原始字节（已解码转义、已截断），二进制安全的正则匹配用它。
	Raw []byte
	// Lower 是 Raw 的 ASCII 小写副本，前缀/子串匹配用它。
	Lower []byte
	// Text 是 string(Lower)，便于 contains 类规则书写。
	Text string
	// FirstLine 是首行（小写、最多 256 字节），协议欢迎行匹配用它。
	FirstLine string
	// Binary 标记是否含有不可打印/高位字节。
	Binary bool
	// Truncated 标记是否发生过截断。
	Truncated bool
	// Escaped 标记是否发生过字面量转义还原。
	Escaped bool
}

// Len 返回参与匹配的字节数。
func (v View) Len() int { return len(v.Raw) }

// Decode 归一化 banner。永不 panic，永不返回 nil Raw（空输入返回零长度切片）。
func Decode(raw string) View {
	decoded, escaped := unescapeLiteral(raw)
	truncated := false
	if len(decoded) > MaxBytes {
		decoded = decoded[:MaxBytes]
		truncated = true
	}
	if decoded == nil {
		decoded = []byte{}
	}
	lower := make([]byte, len(decoded))
	for i, c := range decoded {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		lower[i] = c
	}
	return View{
		Raw:       decoded,
		Lower:     lower,
		Text:      string(lower),
		FirstLine: firstLine(lower),
		Binary:    looksBinary(decoded),
		Truncated: truncated,
		Escaped:   escaped,
	}
}

func firstLine(lower []byte) string {
	end := len(lower)
	if i := bytes.IndexAny(lower, "\r\n"); i >= 0 && i < end {
		end = i
	}
	if end > firstLineLimit {
		end = firstLineLimit
	}
	return string(lower[:end])
}

func looksBinary(b []byte) bool {
	for _, c := range b {
		if c >= 0x7f {
			return true
		}
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			return true
		}
	}
	return false
}

// unescapeLiteral 还原文本形态的转义序列：\xNN、\uNNNN、\n、\r、\t、\0、\\、\"。
// 只有确实存在合法转义时才改写，普通文本原样返回。
func unescapeLiteral(s string) (out []byte, changed bool) {
	if !strings.ContainsRune(s, '\\') {
		return []byte(s), false
	}
	out = make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			out = append(out, c)
			continue
		}
		switch s[i+1] {
		case 'x', 'X':
			if i+3 < len(s) {
				if hi, ok1 := hexVal(s[i+2]); ok1 {
					if lo, ok2 := hexVal(s[i+3]); ok2 {
						out = append(out, hi<<4|lo)
						i += 3
						changed = true
						continue
					}
				}
			}
		case 'u':
			if i+5 < len(s) {
				// \u00NN 是采集器转义单个字节的常见写法（JSON 本身不合法，但真实数据里到处都是）。
				// 直接还原成单字节，避免 \u00a5 被编码成 UTF-8 的两个字节而破坏二进制 banner。
				if s[i+2] == '0' && s[i+3] == '0' {
					if hi, ok1 := hexVal(s[i+4]); ok1 {
						if lo, ok2 := hexVal(s[i+5]); ok2 {
							out = append(out, hi<<4|lo)
							i += 5
							changed = true
							continue
						}
					}
				}
				var r rune
				ok := true
				for j := 0; j < 4; j++ {
					h, valid := hexVal(s[i+2+j])
					if !valid {
						ok = false
						break
					}
					r = r<<4 | rune(h)
				}
				if ok {
					out = utf8.AppendRune(out, r)
					i += 5
					changed = true
					continue
				}
			}
		case 'n':
			out = append(out, '\n')
			i++
			changed = true
			continue
		case 'r':
			out = append(out, '\r')
			i++
			changed = true
			continue
		case 't':
			out = append(out, '\t')
			i++
			changed = true
			continue
		case '0':
			out = append(out, 0x00)
			i++
			changed = true
			continue
		case '\\', '"', '\'':
			out = append(out, s[i+1])
			i++
			changed = true
			continue
		}
		out = append(out, c)
	}
	return out, changed
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// Snippet 把 banner 渲染成一行可读摘要，用于 client 展示与日志。
func Snippet(raw string, max int) string {
	if max <= 0 {
		max = 60
	}
	var sb strings.Builder
	count := 0
	for i := 0; i < len(raw); i++ {
		if count >= max {
			sb.WriteString("...")
			break
		}
		c := raw[i]
		switch {
		case c == '\r':
			sb.WriteString("\\r")
		case c == '\n':
			sb.WriteString("\\n")
		case c == '\t':
			sb.WriteString("\\t")
		case c < 0x20 || c >= 0x7f:
			sb.WriteString("\\x")
			const hexdigits = "0123456789abcdef"
			sb.WriteByte(hexdigits[c>>4])
			sb.WriteByte(hexdigits[c&0x0f])
		default:
			sb.WriteByte(c)
		}
		count++
	}
	return sb.String()
}
