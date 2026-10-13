package auditlog

import (
	"time"

	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

// RenderDetections renders detections as a table, or through the configured exporter when one is set.
func RenderDetections(r *render.Renderer, detections []Detection) error {
	if r.HasExporter() {
		return r.RenderExportedData(detections)
	}
	if len(detections) == 0 {
		r.WriteLine("No credential-related audit log entries found.")
		return nil
	}
	table := r.NewTableWriter([]string{"CATEGORY", "TIMESTAMP", "ACTION", "ACTOR", "REPO", "TARGET"})
	for _, d := range detections {
		ts := ""
		if t, ok := EntryTime(d.Entry); ok {
			ts = t.UTC().Format(time.RFC3339)
		}
		table.Append([]string{
			d.Category,
			ts,
			render.ToString(d.Entry.Action),
			render.ToString(d.Entry.Actor),
			render.AuditEntryAdditionalField(d.Entry, "repo"),
			d.Target,
		})
	}
	return table.Render()
}
