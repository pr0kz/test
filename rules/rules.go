// Package rules 定义"识别规则"的数据模型与加载方式。
//
// 设计原则：规则 = 数据，代码 = 解释器。
// 新增一种协议/产品只需要改 rules/*.json，不需要改任何 Go 代码、不需要重新训练任何模型。
// 规则文件通过 go:embed 编进二进制（镜像可只读运行、无外部依赖），
// 同时支持 -rules-dir 指向外部目录做热替换（CI 里改规则不必重新出镜像）。
package rules

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strings"
)

//go:embed *.json
var builtinFS embed.FS

// Match 描述一个最小匹配断言。
//
//	prefix    不区分大小写的字节前缀
//	contains  不区分大小写的字节子串
//	regex     RE2 正则，作用于原始字节（二进制安全，支持 \x00 这类转义）
//	hex       十六进制字节串，offset>=0 时要求出现在该偏移，offset<0(默认) 时任意位置出现
type Match struct {
	Type   string `json:"type"`
	Value  string `json:"value"`
	Offset *int   `json:"offset,omitempty"`
}

// ProductRule 在协议已确定的前提下抽取产品名与版本号。
//
// Product 支持模板：字面量（"nginx"）或正则捕获组引用（"$1"、"${1}"）。
// Version 同理，未命中捕获组时输出空串。
// Weight 是该产品证据的置信度增量，显式写 0 表示"命名了产品但不加分"。
type ProductRule struct {
	Regex   string   `json:"regex"`
	Product string   `json:"product"`
	Version string   `json:"version,omitempty"`
	Weight  *float64 `json:"weight,omitempty"`
	OS      string   `json:"os,omitempty"`
}

// Probe 是一个协议识别单元：证据集合 + 基础置信度 + 端口先验 + 产品规则。
//
//   - All  全部必须命中
//   - Any  至少命中一条
//   - None 一条都不能命中（用于负样本抑制，例如 FTP 的 220 要排除 SMTP 的 220）
//
// Ports 只用于"加分"，永远不用于否决：真实环境里 443 说 HTTP、8443 说 nginx、
// 9999 说 TLS 都是常态，端口与协议的错配不能作为否定证据。
type Probe struct {
	ID             string        `json:"id"`
	Protocol       string        `json:"protocol"`
	Description    string        `json:"description,omitempty"`
	All            []Match       `json:"all,omitempty"`
	Any            []Match       `json:"any,omitempty"`
	None           []Match       `json:"none,omitempty"`
	BaseConfidence float64       `json:"base_confidence"`
	Ports          []int         `json:"ports,omitempty"`
	DefaultProduct string        `json:"default_product,omitempty"`
	Products       []ProductRule `json:"products,omitempty"`
}

// OSHint 是 OS 词表条目，按书写顺序匹配，先命中者优先（因此要"具体 → 笼统"排列）。
type OSHint struct {
	Contains []string `json:"contains"`
	OS       string   `json:"os"`
}

// RuleSet 是一个完整规则集，可由多个 JSON 文件合并而成。
type RuleSet struct {
	Version     string   `json:"version"`
	Description string   `json:"description,omitempty"`
	OSHints     []OSHint `json:"os_hints,omitempty"`
	Probes      []Probe  `json:"probes,omitempty"`
	Sources     []string `json:"-"`
}

// LoadBuiltin 加载编进二进制的规则。
func LoadBuiltin() (*RuleSet, error) {
	return loadFS(builtinFS, "builtin")
}

// LoadDir 从磁盘目录加载规则，用于规则热替换 / 评估时替换规则集。
func LoadDir(dir string) (*RuleSet, error) {
	return loadFS(os.DirFS(dir), dir)
}

func loadFS(fsys fs.FS, label string) (*RuleSet, error) {
	entries, err := fs.Glob(fsys, "*.json")
	if err != nil {
		return nil, fmt.Errorf("scan rules in %s: %w", label, err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no *.json rule files found in %s", label)
	}
	sort.Strings(entries)

	merged := &RuleSet{}
	for _, name := range entries {
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("read rule file %s: %w", name, err)
		}
		var part RuleSet
		if err := json.Unmarshal(data, &part); err != nil {
			return nil, fmt.Errorf("parse rule file %s: %w", name, err)
		}
		if part.Version == "" {
			return nil, fmt.Errorf("rule file %s: missing version", name)
		}
		if merged.Version == "" {
			merged.Version = part.Version
		} else if merged.Version != part.Version {
			return nil, fmt.Errorf("rule file %s: version %q conflicts with %q", name, part.Version, merged.Version)
		}
		merged.OSHints = append(merged.OSHints, part.OSHints...)
		merged.Probes = append(merged.Probes, part.Probes...)
		merged.Sources = append(merged.Sources, label+"/"+name)
	}
	if err := merged.Validate(); err != nil {
		return nil, err
	}
	return merged, nil
}

// Validate 在启动期做 fail-fast 校验：宁可起不来，也不要带着坏规则对外服务。
func (r *RuleSet) Validate() error {
	if r.Version == "" {
		return fmt.Errorf("ruleset: missing version")
	}
	if len(r.Probes) == 0 {
		return fmt.Errorf("ruleset %s: no probes defined", r.Version)
	}
	seen := make(map[string]bool, len(r.Probes))
	for i, p := range r.Probes {
		if p.ID == "" {
			return fmt.Errorf("probe #%d: missing id", i)
		}
		if seen[p.ID] {
			return fmt.Errorf("probe %q: duplicate id", p.ID)
		}
		seen[p.ID] = true
		if p.Protocol == "" {
			return fmt.Errorf("probe %q: missing protocol", p.ID)
		}
		if len(p.All) == 0 && len(p.Any) == 0 {
			return fmt.Errorf("probe %q: needs at least one of all/any", p.ID)
		}
		if p.BaseConfidence <= 0 || p.BaseConfidence > 1 {
			return fmt.Errorf("probe %q: base_confidence %v must be in (0,1]", p.ID, p.BaseConfidence)
		}
		for j, m := range append(append(append([]Match{}, p.All...), p.Any...), p.None...) {
			if err := validateMatch(m); err != nil {
				return fmt.Errorf("probe %q match #%d: %w", p.ID, j, err)
			}
		}
		for j, pr := range p.Products {
			if pr.Product == "" {
				return fmt.Errorf("probe %q product #%d: missing product", p.ID, j)
			}
			if pr.Regex == "" {
				return fmt.Errorf("probe %q product #%d: missing regex", p.ID, j)
			}
			if _, err := regexp.Compile(pr.Regex); err != nil {
				return fmt.Errorf("probe %q product #%d: invalid regex: %w", p.ID, j, err)
			}
			if pr.Weight != nil && (*pr.Weight < 0 || *pr.Weight > 0.5) {
				return fmt.Errorf("probe %q product #%d: weight %v out of range [0,0.5]", p.ID, j, *pr.Weight)
			}
		}
	}
	for i, h := range r.OSHints {
		if h.OS == "" || len(h.Contains) == 0 {
			return fmt.Errorf("os_hint #%d: needs os and contains", i)
		}
	}
	return nil
}

func validateMatch(m Match) error {
	switch strings.ToLower(m.Type) {
	case "prefix", "contains":
		if m.Value == "" {
			return fmt.Errorf("%s match needs a value", m.Type)
		}
	case "regex":
		if m.Value == "" {
			return fmt.Errorf("regex match needs a value")
		}
		if _, err := regexp.Compile(m.Value); err != nil {
			return fmt.Errorf("invalid regex %q: %w", m.Value, err)
		}
	case "hex":
		if _, err := ParseHex(m.Value); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown match type %q (want prefix|contains|regex|hex)", m.Type)
	}
	return nil
}

// ParseHex 解析 "160301" / "16 03 01" / "16:03:01" 形式的十六进制字节串。
func ParseHex(s string) ([]byte, error) {
	cleaned := strings.Map(func(r rune) rune {
		switch r {
		case ' ', ':', '-', '_':
			return -1
		}
		return r
	}, s)
	cleaned = strings.TrimPrefix(strings.TrimPrefix(cleaned, "0x"), "0X")
	if cleaned == "" {
		return nil, fmt.Errorf("empty hex value")
	}
	if len(cleaned)%2 != 0 {
		return nil, fmt.Errorf("hex value %q has odd length", s)
	}
	out := make([]byte, len(cleaned)/2)
	for i := 0; i < len(out); i++ {
		hi, lo := cleaned[i*2], cleaned[i*2+1]
		h, ok1 := hexNibble(hi)
		l, ok2 := hexNibble(lo)
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("hex value %q contains non-hex characters", s)
		}
		out[i] = h<<4 | l
	}
	return out, nil
}

func hexNibble(c byte) (byte, bool) {
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

// ProbeCount / OSHintCount / SourceFiles 供 /health 展示，方便"一眼确认规则真的加载了"。
func (r *RuleSet) ProbeCount() int       { return len(r.Probes) }
func (r *RuleSet) OSHintCount() int      { return len(r.OSHints) }
func (r *RuleSet) SourceFiles() []string { return append([]string(nil), r.Sources...) }
func (r *RuleSet) Sum() string {
	return fmt.Sprintf("version=%s probes=%d os_hints=%d", r.Version, len(r.Probes), len(r.OSHints))
}
