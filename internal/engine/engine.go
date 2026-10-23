// Package engine 是规则解释器：把 rules.RuleSet 编译成可执行的匹配器，并给出一条 banner 的指纹。
//
// 打分模型（详见 README『置信度模型』）：
//
//	confidence = clamp(base(协议证据强度)
//	                 + product_weight(命中的产品规则，默认 0.12)
//	                 + 0.05(版本号命中)
//	                 + 0.05(OS 线索命中)
//	                 + 0.05(端口与协议先验一致), 0, 0.99)
//
// 端口只在"一致"时加分，绝不在"不一致"时扣分：443 明文 HTTP、8443 nginx、9999 TLS
// 这些真实数据证明端口不是否定证据。
package engine

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"

	"bannerfp/internal/banner"
	"bannerfp/internal/model"
	"bannerfp/rules"
)

const (
	weightVersion        = 0.05
	weightOS             = 0.05
	weightPort           = 0.05
	defaultProductWeight = 0.12
	maxConfidence        = 0.99
	unknownConfidence    = 0.10
	// minMatchConfidence 是"接受某个协议判定"的下限，低于它宁可回落 unknown 也不猜。
	minMatchConfidence = 0.40
)

// Engine 是并发安全的（只读编译产物），可在多个 goroutine 间共享。
type Engine struct {
	rs      *rules.RuleSet
	probes  []*compiledProbe
	osHints []rules.OSHint
}

type compiledMatch struct {
	typ     string
	literal []byte
	re      *regexp.Regexp
	hex     []byte
	offset  int
}

type compiledProduct struct {
	re      *regexp.Regexp
	product string
	version string
	weight  float64
	os      string
}

type compiledProbe struct {
	probe    *rules.Probe
	all      []compiledMatch
	any      []compiledMatch
	none     []compiledMatch
	products []compiledProduct
	ports    map[int]struct{}
}

// New 编译规则集。任何编译错误都在启动期暴露（fail fast），不带病对外服务。
func New(rs *rules.RuleSet) (*Engine, error) {
	if rs == nil {
		return nil, errors.New("engine: nil ruleset")
	}
	e := &Engine{rs: rs, osHints: rs.OSHints}
	for i := range rs.Probes {
		cp, err := compileProbe(&rs.Probes[i])
		if err != nil {
			return nil, err
		}
		e.probes = append(e.probes, cp)
	}
	if len(e.probes) == 0 {
		return nil, errors.New("engine: no probes compiled")
	}
	return e, nil
}

// RuleSet 返回底层的规则集（只读），供 /health 汇报。
func (e *Engine) RuleSet() *rules.RuleSet { return e.rs }

// ProbeCount 返回编译后的协议识别单元数量。
func (e *Engine) ProbeCount() int { return len(e.probes) }

func compileProbe(p *rules.Probe) (*compiledProbe, error) {
	cp := &compiledProbe{probe: p, ports: make(map[int]struct{}, len(p.Ports))}
	for _, port := range p.Ports {
		cp.ports[port] = struct{}{}
	}
	var err error
	if cp.all, err = compileMatches(p.ID, "all", p.All); err != nil {
		return nil, err
	}
	if cp.any, err = compileMatches(p.ID, "any", p.Any); err != nil {
		return nil, err
	}
	if cp.none, err = compileMatches(p.ID, "none", p.None); err != nil {
		return nil, err
	}
	for i := range p.Products {
		pr := &p.Products[i]
		re, err := regexp.Compile(pr.Regex)
		if err != nil {
			return nil, fmt.Errorf("probe %q product #%d: invalid regex: %w", p.ID, i, err)
		}
		weight := defaultProductWeight
		if pr.Weight != nil {
			weight = *pr.Weight
		}
		cp.products = append(cp.products, compiledProduct{
			re: re, product: pr.Product, version: pr.Version, weight: weight, os: pr.OS,
		})
	}
	return cp, nil
}

func compileMatches(probeID, group string, in []rules.Match) ([]compiledMatch, error) {
	out := make([]compiledMatch, 0, len(in))
	for i, m := range in {
		cm := compiledMatch{offset: -1}
		if m.Offset != nil {
			cm.offset = *m.Offset
		}
		switch strings.ToLower(m.Type) {
		case "prefix":
			cm.typ = "prefix"
			cm.literal = bytes.ToLower([]byte(m.Value))
		case "contains":
			cm.typ = "contains"
			cm.literal = bytes.ToLower([]byte(m.Value))
		case "regex":
			re, err := regexp.Compile(m.Value)
			if err != nil {
				return nil, fmt.Errorf("probe %q %s #%d: invalid regex: %w", probeID, group, i, err)
			}
			cm.typ = "regex"
			cm.re = re
		case "hex":
			hb, err := rules.ParseHex(m.Value)
			if err != nil {
				return nil, fmt.Errorf("probe %q %s #%d: %w", probeID, group, i, err)
			}
			cm.typ = "hex"
			cm.hex = hb
		default:
			return nil, fmt.Errorf("probe %q %s #%d: unknown match type %q", probeID, group, i, m.Type)
		}
		out = append(out, cm)
	}
	return out, nil
}

func (m compiledMatch) matches(v banner.View) bool {
	switch m.typ {
	case "prefix":
		return bytes.HasPrefix(v.Lower, m.literal)
	case "contains":
		return bytes.Contains(v.Lower, m.literal)
	case "regex":
		return m.re.Match(v.Raw)
	case "hex":
		if m.offset >= 0 {
			if m.offset+len(m.hex) > len(v.Raw) {
				return false
			}
			return bytes.Equal(v.Raw[m.offset:m.offset+len(m.hex)], m.hex)
		}
		return bytes.Contains(v.Raw, m.hex)
	}
	return false
}

func (cp *compiledProbe) matches(v banner.View) bool {
	if len(cp.all) == 0 && len(cp.any) == 0 {
		return false
	}
	for _, m := range cp.none {
		if m.matches(v) {
			return false
		}
	}
	for _, m := range cp.all {
		if !m.matches(v) {
			return false
		}
	}
	if len(cp.any) > 0 {
		hit := false
		for _, m := range cp.any {
			if m.matches(v) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

// extract 返回第一个命中的产品规则（规则文件里的书写顺序 = 特异性顺序）。
func (cp *compiledProbe) extract(v banner.View) (*compiledProduct, string) {
	for i := range cp.products {
		pr := &cp.products[i]
		if !pr.re.Match(v.Raw) {
			continue
		}
		return pr, expand(pr.version, pr.re, v.Raw)
	}
	return nil, ""
}

func (e *Engine) detectOS(v banner.View) string {
	for _, h := range e.osHints {
		for _, needle := range h.Contains {
			if bytes.Contains(v.Lower, []byte(strings.ToLower(needle))) {
				return h.OS
			}
		}
	}
	return ""
}

// expand 渲染 $1 / ${1} / ${name} 模板；无捕获时返回空串。
func expand(tmpl string, re *regexp.Regexp, src []byte) string {
	if tmpl == "" || !strings.Contains(tmpl, "$") {
		return tmpl
	}
	idx := re.FindSubmatchIndex(src)
	if idx == nil {
		return ""
	}
	return string(re.ExpandString(nil, tmpl, string(src), idx))
}

// Identify 是核心入口：单条 banner → 指纹。任何输入都不返回 error，认不出回落 unknown。
func (e *Engine) Identify(in model.ScanInput) model.Result {
	res := model.Result{IP: in.IP, Port: in.Port, Protocol: model.ProtocolUnknown}
	if in.Banner == "" {
		return res
	}
	v := banner.Decode(in.Banner)
	if v.Len() == 0 {
		return res
	}
	res.Confidence = unknownConfidence

	var (
		bestScore   float64
		bestProbe   *compiledProbe
		bestProduct *compiledProduct
		bestVersion string
		bestOS      string
	)
	for _, cp := range e.probes {
		if !cp.matches(v) {
			continue
		}
		product, version := cp.extract(v)
		if product == nil && cp.probe.DefaultProduct != "" {
			// 协议自身就是产品（典型如 Redis：协议与产品同名），但没有可加的置信度。
			product = &compiledProduct{product: cp.probe.DefaultProduct, weight: 0}
		}
		score := cp.probe.BaseConfidence
		osHint := ""
		if product != nil {
			score += product.weight
			osHint = product.os
		}
		if version != "" {
			score += weightVersion
		}
		if osHint == "" {
			osHint = e.detectOS(v)
		}
		if osHint != "" {
			score += weightOS
		}
		if _, ok := cp.ports[in.Port]; ok {
			score += weightPort
		}
		// 严格大于：同分时保留规则文件中更靠前的 probe（作者按特异性排序）。
		if score > bestScore {
			bestScore, bestProbe, bestProduct, bestVersion, bestOS = score, cp, product, version, osHint
		}
	}
	if bestProbe == nil || bestScore < minMatchConfidence {
		return res
	}

	res.Protocol = bestProbe.probe.Protocol
	if bestProduct != nil {
		res.Product = cleanProduct(bestProduct.product, bestProduct.re, v.Raw)
	}
	res.Version = cleanVersion(bestVersion)
	res.OSHint = bestOS
	res.Confidence = round2(math.Min(bestScore, maxConfidence))
	return res
}

func cleanProduct(tmpl string, re *regexp.Regexp, src []byte) string {
	out := tmpl
	if re != nil {
		out = expand(tmpl, re, src)
	}
	out = strings.Join(strings.Fields(out), " ")
	return strings.Trim(out, " \t\r\n-_:,;/()[]")
}

func cleanVersion(v string) string {
	v = strings.Join(strings.Fields(v), " ")
	return strings.Trim(v, " \t\r\n-_:+,;/()[]")
}

func round2(f float64) float64 {
	return math.Round(f*100) / 100
}
