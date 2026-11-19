package compliance

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/codeswhat/sockguard/v3/app/internal/ui"
)

// WriteJSON writes the report as indented JSON with a stable key order.
func WriteJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func mdCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.ReplaceAll(s, "\n", " ")
}

// WriteMarkdown writes an auditor-friendly report: header facts, summary, one
// control table, per-control evidence, and the disclaimer.
func WriteMarkdown(w io.Writer, r Report) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s configuration report\n\n", r.Benchmark)
	fmt.Fprintf(&b, "> %s\n\n", r.Disclaimer)
	fmt.Fprintf(&b, "- Sockguard version: `%s`\n", r.SockguardVersion)
	fmt.Fprintf(&b, "- Config SHA-256: `%s`\n\n", r.ConfigSHA256)

	b.WriteString("## Summary\n\n| Status | Controls |\n|---|---|\n")
	for _, row := range summaryRows(r.Summary) {
		fmt.Fprintf(&b, "| %s | %d |\n", row.label, row.n)
	}
	fmt.Fprintf(&b, "| total | %d |\n\n", r.Summary.Total)

	b.WriteString("## Controls\n\n| Control | Title | Category | Status |\n|---|---|---|---|\n")
	for _, c := range r.Controls {
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", mdCell(c.ID), mdCell(c.Title), c.Category, c.Status)
	}
	b.WriteString("\n## Evidence\n")
	for _, c := range r.Controls {
		if len(c.Evidence) == 0 && len(c.Notes) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n### %s %s (%s)\n\n", mdCell(c.ID), mdCell(c.Title), c.Status)
		if len(c.Evidence) > 0 {
			b.WriteString("| Config path | Expected | Observed |\n|---|---|---|\n")
			for _, e := range c.Evidence {
				fmt.Fprintf(&b, "| `%s` | %s | %s |\n", mdCell(e.Path), mdCell(e.Expected), mdCell(e.Observed))
			}
			b.WriteString("\n")
		}
		for _, n := range c.Notes {
			fmt.Fprintf(&b, "- %s\n", n)
		}
	}
	if len(r.Notes) > 0 {
		b.WriteString("\n## Report notes\n\n")
		for _, n := range r.Notes {
			fmt.Fprintf(&b, "- %s\n", n)
		}
	}
	fmt.Fprintf(&b, "\n## Disclaimer\n\n%s\n", r.Disclaimer)
	_, err := io.WriteString(w, b.String())
	return err
}

type summaryRow struct {
	label string
	n     int
}

func summaryRows(s Summary) []summaryRow {
	return []summaryRow{
		{string(StatusConfigured), s.Configured},
		{string(StatusAlwaysOn), s.AlwaysOn},
		{string(StatusNeedsEvidence), s.NeedsEvidence},
		{string(StatusPartial), s.Partial},
		{string(StatusNotConfigured), s.NotConfigured},
		{string(StatusOutsideScope), s.OutsideScope},
	}
}

// WriteText writes the report in the same label style validate and match use.
func WriteText(w io.Writer, r Report) error {
	p := ui.New(w)
	label := func(s string) string { return p.Dim(fmt.Sprintf("%-18s", s)) }
	color := func(s Status) string {
		text := fmt.Sprintf("%-14s", string(s))
		switch s {
		case StatusConfigured, StatusAlwaysOn:
			return p.Green(text)
		case StatusPartial, StatusNeedsEvidence:
			return p.Cyan(text)
		case StatusNotConfigured:
			return p.Red(text)
		}
		return p.Dim(text)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\n", label("Benchmark:"), r.Benchmark)
	fmt.Fprintf(&b, "%s %s\n", label("Sockguard version:"), r.SockguardVersion)
	fmt.Fprintf(&b, "%s %s\n\n", label("Config SHA-256:"), r.ConfigSHA256)
	for _, row := range summaryRows(r.Summary) {
		fmt.Fprintf(&b, "%s %d\n", label(row.label+":"), row.n)
	}
	b.WriteString("\n")
	for _, c := range r.Controls {
		fmt.Fprintf(&b, "%-10s %s %s\n", c.ID, color(c.Status), c.Title)
		for _, e := range c.Evidence {
			fmt.Fprintf(&b, "    %s expected=%s observed=%s\n", e.Path, e.Expected, e.Observed)
		}
		for _, n := range c.Notes {
			fmt.Fprintf(&b, "    note: %s\n", n)
		}
	}
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "\nnote: %s\n", n)
	}
	fmt.Fprintf(&b, "\n%s\n", r.Disclaimer)
	_, err := io.WriteString(w, b.String())
	return err
}
