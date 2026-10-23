// Package model 定义系统的输入/输出契约。
//
// 这里是 JSON 字段名的唯一来源：HTTP 接口、client 输出、规则测试都复用同一套结构，
// 避免出现"接口返回 xxx、client 打印 yyy"的漂移。
package model

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ScanInput 是一条网络扫描原始数据。
//
// 字段特意不使用 json tag，而用自定义 UnmarshalJSON 兼容多种真实世界形态：
//   - 标准形态：{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-..."}
//   - port 为字符串："port":"22"
//   - 二进制 banner 以 base64 传递：{"ip":"..","port":3306,"banner_b64":"SgAA..."}
//   - 字段别名：host/address/target、data/raw/response
//
// 识别结果必须"进 N 条出 N 条"，因此输入解析永不对单条数据报错，只做最大努力的字段对齐。
type ScanInput struct {
	IP     string
	Port   int
	Banner string
}

// Result 是单条指纹识别结果，字段顺序即 JSON 输出顺序。
//
// 约定：识别不出产品/版本/OS 时返回空字符串而不是 null，协议一律回落 "unknown"。
type Result struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

// ProtocolUnknown 是兜底协议值，绝不返回空串，避免下游把"未识别"与"字段缺失"混淆。
const ProtocolUnknown = "unknown"

var (
	ipKeys     = []string{"ip", "host", "address", "host_ip", "target", "addr"}
	portKeys   = []string{"port", "port_number", "portnum"}
	bannerKeys = []string{"banner", "data", "service_banner", "raw", "response", "payload", "body"}
	b64Keys    = []string{"banner_b64", "banner_base64", "bannerB64"}
)

// UnmarshalJSON 实现宽进的数据适配。
func (s *ScanInput) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		// 非对象（例如数组里的裸字符串）：当作只有 banner 的条目。
		var str string
		if errStr := json.Unmarshal(data, &str); errStr == nil {
			*s = ScanInput{Banner: str}
			return nil
		}
		return fmt.Errorf("scan item must be a JSON object: %w", err)
	}
	*s = ScanInput{
		IP:   firstString(raw, ipKeys...),
		Port: firstPort(raw, portKeys...),
	}
	for _, k := range b64Keys {
		if v, ok := raw[k]; ok {
			var encoded string
			if json.Unmarshal(v, &encoded) == nil && encoded != "" {
				if decoded, err := decodeBase64Loose(encoded); err == nil {
					s.Banner = string(decoded)
					return nil
				}
			}
		}
	}
	s.Banner = firstString(raw, bannerKeys...)
	return nil
}

// MarshalJSON 让 ScanInput 也能被 client / 测试直接序列化。
func (s ScanInput) MarshalJSON() ([]byte, error) {
	type alias struct {
		IP     string `json:"ip"`
		Port   int    `json:"port"`
		Banner string `json:"banner"`
	}
	return json.Marshal(alias{IP: s.IP, Port: s.Port, Banner: s.Banner})
}

func firstString(raw map[string]json.RawMessage, keys ...string) string {
	for _, k := range keys {
		v, ok := raw[k]
		if !ok {
			continue
		}
		var s string
		if err := json.Unmarshal(v, &s); err == nil {
			return strings.TrimSpace(s)
		}
		var n json.Number
		if err := json.Unmarshal(v, &n); err == nil {
			return n.String()
		}
	}
	return ""
}

func firstPort(raw map[string]json.RawMessage, keys ...string) int {
	for _, k := range keys {
		v, ok := raw[k]
		if !ok {
			continue
		}
		var f float64
		if err := json.Unmarshal(v, &f); err == nil {
			return int(f)
		}
		var s string
		if err := json.Unmarshal(v, &s); err == nil {
			if p, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
				return p
			}
		}
	}
	return 0
}

func decodeBase64Loose(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("invalid base64")
}

// DecodeInputs 解析一批输入，容忍三种常见投递形态：
//   - JSON 数组            [ {...}, {...} ]
//   - JSON 包装对象        {"items":[...]} / {"banners":[...]} / {"data":[...]} / {"targets":[...]}
//   - NDJSON / 单个对象    每行一个 {...}
//
// 解析前会先做一次 JSON 修复（sanitizeJSON）：扫描器把二进制 banner escape 成
// "J\x00\x00\x00\n8.0.32\x00" 这种非法 JSON 是行业常态（题目给的自测数据就是这种形态）。
// 只要能取出条目就不会因为个别字段缺失而失败；整批根本无法解析时才返回 error。
func DecodeInputs(body []byte) ([]ScanInput, error) {
	trimmed := bytes.TrimSpace(sanitizeJSON(body))
	if len(trimmed) == 0 {
		return nil, errors.New("empty request body: expected a JSON array of scan items")
	}
	switch trimmed[0] {
	case '[':
		var items []ScanInput
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return nil, fmt.Errorf("invalid JSON array of scan items: %w", err)
		}
		return items, nil
	case '{':
		if items, ok := decodeWrapperOrSingle(trimmed); ok {
			return items, nil
		}
		return decodeLines(trimmed)
	default:
		return decodeLines(trimmed)
	}
}

func decodeWrapperOrSingle(trimmed []byte) ([]ScanInput, bool) {
	var wrapper struct {
		Items   []ScanInput `json:"items"`
		Banners []ScanInput `json:"banners"`
		Data    []ScanInput `json:"data"`
		Targets []ScanInput `json:"targets"`
	}
	if err := json.Unmarshal(trimmed, &wrapper); err == nil {
		switch {
		case len(wrapper.Items) > 0:
			return wrapper.Items, true
		case len(wrapper.Banners) > 0:
			return wrapper.Banners, true
		case len(wrapper.Data) > 0:
			return wrapper.Data, true
		case len(wrapper.Targets) > 0:
			return wrapper.Targets, true
		}
	}
	var single ScanInput
	if err := json.Unmarshal(trimmed, &single); err != nil {
		return nil, false
	}
	if single.IP == "" && single.Banner == "" {
		return nil, false
	}
	return []ScanInput{single}, true
}

func decodeLines(trimmed []byte) ([]ScanInput, error) {
	var items []ScanInput
	for i, line := range bytes.Split(trimmed, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if line[0] != '{' {
			return nil, fmt.Errorf("line %d: expected a JSON object, got %q", i+1, truncate(line, 32))
		}
		var item ScanInput
		if err := json.Unmarshal(line, &item); err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		items = append(items, item)
	}
	if len(items) == 0 {
		return nil, errors.New("no scan items found in body: expected a JSON array of scan items")
	}
	return items, nil
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}

// sanitizeJSON 修复"看起来像 JSON 但严格来说不是"的输入：
//
//	\xNN        非标准转义 → 改写成字面量 \\xNN，交由 banner 归一化层还原成单个字节
//	裸控制字符  字符串内的 0x00-0x1f → 改写成 \\u00NN
//	非法转义    \q 之类 → 改写成字面量 \\q
//
// 对合法 JSON 是完全的空操作，因此可以安全地无条件调用。
func sanitizeJSON(in []byte) []byte {
	if !hasRepairableEscape(in) {
		return in
	}
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, len(in)+32)
	inString := false
	for i := 0; i < len(in); i++ {
		c := in[i]
		if !inString {
			if c == '"' {
				inString = true
			}
			out = append(out, c)
			continue
		}
		switch c {
		case '"':
			inString = false
			out = append(out, c)
		case '\\':
			if i+1 >= len(in) {
				out = append(out, c)
				continue
			}
			n := in[i+1]
			switch n {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't', 'u':
				out = append(out, c, n)
				i++
			case 'x', 'X':
				if i+3 < len(in) && isHexByte(in[i+2]) && isHexByte(in[i+3]) {
					out = append(out, '\\', '\\', 'x', in[i+2], in[i+3])
					i += 3
				} else {
					out = append(out, '\\', '\\')
				}
			default:
				out = append(out, '\\', '\\', n)
				i++
			}
		default:
			if c < 0x20 {
				out = append(out, '\\', '\\', 'u', '0', '0', hexdigits[c>>4], hexdigits[c&0x0f])
			} else {
				out = append(out, c)
			}
		}
	}
	return out
}

// hasRepairableEscape 用一次快速扫描判断是否需要修复，避免大 body 上的无谓复制。
func hasRepairableEscape(in []byte) bool {
	inString := false
	for i := 0; i < len(in); i++ {
		c := in[i]
		if !inString {
			if c == '"' {
				inString = true
			}
			continue
		}
		switch {
		case c == '"':
			inString = false
		case c == '\\':
			if i+1 >= len(in) {
				return false
			}
			n := in[i+1]
			switch n {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				i++
			case 'u':
				i++
			case 'x', 'X':
				return true
			default:
				return true
			}
		case c < 0x20:
			return true
		}
	}
	return false
}

func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
