// Package report 把识别结果渲染成人能读的表格与机器能读的 JSON。
// 与 client 的 I/O 解耦，便于单测。
package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"bannerfp/internal/banner"
	"bannerfp/internal/model"
)

type row struct {
	cells []string
}

// Table 渲染对齐表格：ip:port / 协议 / 产品 / 版本 / OS / 置信度 / banner 摘要。
// inputs 可以为 nil，此时省略 banner 摘要列。
func Table(results []model.Result, inputs []model.ScanInput) string {
	withSnippet := len(inputs) == len(results) && len(inputs) > 0
	header := []string{"#", "IP", "PORT", "PROTOCOL", "PRODUCT", "VERSION", "OS_HINT", "CONF"}
	if withSnippet {
		header = append(header, "BANNER")
	}

	rows := make([]row, 0, len(results)+1)
	rows = append(rows, row{cells: header})
	for i, res := range results {
		cells := []string{
			fmt.Sprintf("%d", i+1),
			res.IP,
			fmt.Sprintf("%d", res.Port),
			res.Protocol,
			res.Product,
			res.Version,
			res.OSHint,
			fmt.Sprintf("%.2f", res.Confidence),
		}
		if withSnippet {
			cells = append(cells, banner.Snippet(inputs[i].Banner, 44))
		}
		rows = append(rows, row{cells: cells})
	}

	widths := make([]int, len(header))
	for _, r := range rows {
		for i, c := range r.cells {
			if w := displayWidth(c); w > widths[i] {
				widths[i] = w
			}
		}
	}

	var sb strings.Builder
	for _, r := range rows {
		for i, c := range r.cells {
			pad := widths[i] - displayWidth(c)
			sb.WriteString(c)
			if i < len(r.cells)-1 {
				sb.WriteString(strings.Repeat(" ", pad+2))
			}
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// Summary 输出总数/未识别数/平均置信度/各协议计数。
func Summary(results []model.Result) string {
	if len(results) == 0 {
		return "no results\n"
	}
	counts := map[string]int{}
	var sum float64
	unknown := 0
	for _, r := range results {
		counts[r.Protocol]++
		sum += r.Confidence
		if r.Protocol == model.ProtocolUnknown {
			unknown++
		}
	}
	protocols := make([]string, 0, len(counts))
	for p := range counts {
		protocols = append(protocols, p)
	}
	sort.Slice(protocols, func(i, j int) bool {
		if counts[protocols[i]] != counts[protocols[j]] {
			return counts[protocols[i]] > counts[protocols[j]]
		}
		return protocols[i] < protocols[j]
	})
	parts := make([]string, 0, len(protocols))
	for _, p := range protocols {
		parts = append(parts, fmt.Sprintf("%s=%d", p, counts[p]))
	}
	return fmt.Sprintf(
		"total=%d identified=%d unknown=%d avg_confidence=%.2f\nprotocols: %s\n",
		len(results), len(results)-unknown, unknown, sum/float64(len(results)), strings.Join(parts, " "),
	)
}

// JSON 输出与接口完全一致的结果数组。
func JSON(results []model.Result) (string, error) {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data) + "\n", nil
}

func displayWidth(s string) int {
	return len([]rune(s))
}
