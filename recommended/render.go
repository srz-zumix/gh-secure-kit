package recommended

import (
	"fmt"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

// resultJSON is the JSON-friendly representation of a Result, omitting the
// Rule's non-serializable Check/Apply function fields.
type resultJSON struct {
	Rule     string   `json:"rule"`
	GHQRID   string   `json:"ghqr_id,omitempty"`
	Severity Severity `json:"severity"`
	Scope    Scope    `json:"scope"`
	Category string   `json:"category"`
	Fixable  bool     `json:"fixable"`
	Title    string   `json:"title"`
	Target   string   `json:"target"`
	Status   Status   `json:"status"`
	Detail   string   `json:"detail"`
}

func newResultJSON(res Result) resultJSON {
	return resultJSON{
		Rule:     res.Rule.ID,
		GHQRID:   res.Rule.GHQRID,
		Severity: res.Rule.Severity,
		Scope:    res.Rule.Scope,
		Category: res.Rule.Category,
		Fixable:  res.Rule.Fixable,
		Title:    res.Rule.Title,
		Target:   res.Target,
		Status:   res.Status,
		Detail:   res.Detail,
	}
}

// RenderResults renders the results of evaluating rules against a target as a
// table, or as structured data when an exporter is configured.
func RenderResults(exporter cmdutil.Exporter, results []Result) error {
	r := render.NewRenderer(exporter)
	if r.HasExporter() {
		data := make([]resultJSON, 0, len(results))
		for _, res := range results {
			data = append(data, newResultJSON(res))
		}
		return r.RenderExportedData(data)
	}
	if len(results) == 0 {
		r.WriteLine("No rules evaluated.")
		return nil
	}
	headers := []string{"Rule", "Severity", "Scope", "Target", "Status", "Fixable", "Title", "Detail"}
	table := r.NewTableWriter(headers)
	for _, res := range results {
		table.Append([]string{
			res.Rule.ID,
			string(res.Rule.Severity),
			string(res.Rule.Scope),
			res.Target,
			string(res.Status),
			fmt.Sprintf("%t", res.Rule.Fixable),
			res.Rule.Title,
			res.Detail,
		})
	}
	return table.Render()
}

// ruleJSON is the JSON-friendly representation of a Rule, omitting its
// non-serializable Check/Apply function fields.
type ruleJSON struct {
	Rule     string   `json:"rule"`
	GHQRID   string   `json:"ghqr_id,omitempty"`
	Scope    Scope    `json:"scope"`
	Category string   `json:"category"`
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	Fixable  bool     `json:"fixable"`
}

func newRuleJSON(rule Rule) ruleJSON {
	return ruleJSON{
		Rule:     rule.ID,
		GHQRID:   rule.GHQRID,
		Scope:    rule.Scope,
		Category: rule.Category,
		Severity: rule.Severity,
		Title:    rule.Title,
		Fixable:  rule.Fixable,
	}
}

// RenderRules renders the rule catalog as a table, or as structured data when
// an exporter is configured.
func RenderRules(exporter cmdutil.Exporter, rules []Rule) error {
	r := render.NewRenderer(exporter)
	if r.HasExporter() {
		data := make([]ruleJSON, 0, len(rules))
		for _, rule := range rules {
			data = append(data, newRuleJSON(rule))
		}
		return r.RenderExportedData(data)
	}
	if len(rules) == 0 {
		r.WriteLine("No rules found.")
		return nil
	}
	headers := []string{"Rule", "GHQR ID", "Severity", "Scope", "Category", "Fixable", "Title"}
	table := r.NewTableWriter(headers)
	for _, rule := range rules {
		table.Append([]string{
			rule.ID,
			rule.GHQRID,
			string(rule.Severity),
			string(rule.Scope),
			rule.Category,
			fmt.Sprintf("%t", rule.Fixable),
			rule.Title,
		})
	}
	return table.Render()
}

// applyResultJSON is the JSON-friendly representation of an ApplyResult.
type applyResultJSON struct {
	resultJSON
	Applied bool   `json:"applied"`
	DryRun  bool   `json:"dry_run"`
	Error   string `json:"error,omitempty"`
}

// RenderApplyResults renders the results of applying fixes as a table, or as
// structured data when an exporter is configured.
func RenderApplyResults(exporter cmdutil.Exporter, results []ApplyResult) error {
	r := render.NewRenderer(exporter)
	if r.HasExporter() {
		data := make([]applyResultJSON, 0, len(results))
		for _, res := range results {
			entry := applyResultJSON{resultJSON: newResultJSON(res.Result), Applied: res.Applied, DryRun: res.DryRun}
			if res.Error != nil {
				entry.Error = res.Error.Error()
			}
			data = append(data, entry)
		}
		return r.RenderExportedData(data)
	}
	if len(results) == 0 {
		r.WriteLine("No rules evaluated.")
		return nil
	}
	headers := []string{"Rule", "Severity", "Target", "Status", "Applied", "Title", "Detail"}
	table := r.NewTableWriter(headers)
	for _, res := range results {
		applied := ""
		if res.Status == StatusFail && res.Rule.Fixable {
			if res.Error != nil {
				applied = "error: " + res.Error.Error()
			} else if res.Applied && res.DryRun {
				applied = "would apply"
			} else if res.Applied {
				applied = "true"
			} else {
				applied = "false"
			}
		}
		table.Append([]string{
			res.Rule.ID,
			string(res.Rule.Severity),
			res.Target,
			string(res.Status),
			applied,
			res.Rule.Title,
			res.Detail,
		})
	}
	return table.Render()
}
