package localscan

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

type actionsFindingWorkflow struct {
	finding ActionsFinding
	runs    []*actionsFindingRun
}

type actionsFindingRun struct {
	finding ActionsFinding
	jobs    []*actionsFindingJob
}

type actionsFindingJob struct {
	finding  ActionsFinding
	findings []ActionsFinding
}

// RenderActionsFindings renders Actions findings grouped by workflow, run, and job.
func RenderActionsFindings(r *render.Renderer, findings []ActionsFinding) error {
	if r.HasExporter() {
		return r.RenderExportedData(findings)
	}
	if len(findings) == 0 {
		return nil
	}
	type runKey struct {
		workflow, run, attempt int64
	}
	workflows := make(map[int64]*actionsFindingWorkflow)
	runs := make(map[runKey]*actionsFindingRun)
	jobs := make(map[int64]*actionsFindingJob)
	var ordered []*actionsFindingWorkflow
	for _, finding := range findings {
		workflow := workflows[finding.WorkflowID]
		if workflow == nil {
			workflow = &actionsFindingWorkflow{finding: finding}
			workflows[finding.WorkflowID] = workflow
			ordered = append(ordered, workflow)
		}
		key := runKey{finding.WorkflowID, finding.RunID, finding.RunAttempt}
		run := runs[key]
		if run == nil {
			run = &actionsFindingRun{finding: finding}
			runs[key] = run
			workflow.runs = append(workflow.runs, run)
		}
		job := jobs[finding.JobID]
		if job == nil {
			job = &actionsFindingJob{finding: finding}
			jobs[finding.JobID] = job
			run.jobs = append(run.jobs, job)
		}
		job.findings = append(job.findings, finding)
	}
	var output strings.Builder
	for index, workflow := range ordered {
		if index > 0 {
			output.WriteByte('\n')
		}
		name := workflow.finding.WorkflowName
		if name == "" {
			name = "(no name)"
		}
		writeFindingHeading(&output, r, fmt.Sprintf("* Workflow %s (ID %d)", name, workflow.finding.WorkflowID))
		for _, run := range workflow.runs {
			fmt.Fprintf(&output, "  Run: %d (attempt %d)\n", run.finding.RunID, run.finding.RunAttempt)
			for _, job := range run.jobs {
				name := job.finding.JobName
				if name == "" {
					name = "(no name)"
				}
				fmt.Fprintf(&output, "    Job: %s (ID %d)\n", findingText(name), job.finding.JobID)
				if job.finding.JobURL != "" {
					fmt.Fprintf(&output, "    URL: %s\n", findingText(job.finding.JobURL))
				}
				rows := slices.Clone(job.findings)
				slices.SortStableFunc(rows, func(left, right ActionsFinding) int {
					return cmp.Compare(left.StartLine, right.StartLine)
				})
				writer := tabwriter.NewWriter(&output, 0, 4, 2, ' ', 0)
				for _, finding := range rows {
					if _, err := fmt.Fprintf(writer, "      %d\t%s\t%s", finding.StartLine, findingText(finding.PatternID), findingText(finding.Secret)); err != nil {
						return err
					}
					if finding.LocationURL != "" {
						if _, err := fmt.Fprintf(writer, "\t%s", findingText(finding.LocationURL)); err != nil {
							return err
						}
					}
					if _, err := fmt.Fprintln(writer); err != nil {
						return err
					}
				}
				if err := writer.Flush(); err != nil {
					return err
				}
			}
		}
	}
	fmt.Fprintf(&output, "\n%s in %s\n", findingCount(len(findings), "finding"), findingCount(len(jobs), "job"))
	_, err := fmt.Fprint(r.IO.Out, output.String())
	return err
}

// RenderActionsSummary reports coverage and warnings separately from findings.
func RenderActionsSummary(w io.Writer, result ActionsScanResult) error {
	for _, warning := range result.Warnings {
		if _, err := fmt.Fprintf(w, "warning: %s\n", findingText(warning)); err != nil {
			return err
		}
	}
	if result.Interrupted {
		if _, err := fmt.Fprintln(w, "Scan interrupted; results cover only the job logs scanned before cancellation"); err != nil {
			return err
		}
	}
	s := result.Summary
	failed := findingCount(s.Failed, "failed job")
	if s.FailedRuns > 0 {
		failed += ", " + findingCount(s.FailedRuns, "failed run")
	}
	if s.FailedWorkflows > 0 {
		failed += ", " + findingCount(s.FailedWorkflows, "failed workflow")
	}
	_, err := fmt.Fprintf(w, "Scanned %s; %s considered, %s selected; %d unavailable, %s, %s, %d skipped, %d filtered from listed jobs, %s\n",
		findingCount(s.Scanned, "job log"), findingCount(s.Runs, "run"), findingCount(s.Workflows, "workflow"),
		s.Unavailable, failed, findingCount(s.Incomplete, "incomplete job"), s.Skipped, s.Filtered, findingCount(s.IncompleteRuns, "incomplete run"))
	return err
}
