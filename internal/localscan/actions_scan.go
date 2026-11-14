package localscan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/google/go-github/v93/github"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
)

// ActionsFinding identifies a secret in a GitHub Actions job log.
type ActionsFinding struct {
	Finding
	WorkflowID   int64  `json:"workflow_id"`
	WorkflowName string `json:"workflow_name,omitempty"`
	WorkflowPath string `json:"workflow_path,omitempty"`
	RunID        int64  `json:"run_id"`
	RunAttempt   int64  `json:"run_attempt"`
	JobID        int64  `json:"job_id"`
	JobName      string `json:"job_name,omitempty"`
	JobURL       string `json:"job_url,omitempty"`
	LocationURL  string `json:"location_url,omitempty"`
}

// ActionsScanSummary reports both scanned and unscanned targets.
type ActionsScanSummary struct {
	Workflows       int
	Runs            int
	IncompleteRuns  int
	Scanned         int
	Unavailable     int
	Incomplete      int
	Skipped         int
	Filtered        int
	Failed          int
	FailedRuns      int
	FailedWorkflows int
}

// ActionsScanResult includes findings collected before a later error.
// Interrupted is set when the scan was cancelled, in which case the result
// covers only the job logs scanned before cancellation.
type ActionsScanResult struct {
	Findings    []ActionsFinding
	Summary     ActionsScanSummary
	Warnings    []string
	Interrupted bool
}

// ExitCode returns 1 when secrets were found, 130 when an interrupted scan
// found nothing, and 0 otherwise.
func (r ActionsScanResult) ExitCode() int {
	switch {
	case len(r.Findings) > 0:
		return 1
	case r.Interrupted:
		return 130
	default:
		return 0
	}
}

type actionsWorkflowRef struct {
	name string
	path string
}

type actionsWorkflow struct {
	id       int64
	refs     []actionsWorkflowRef
	runs     []*github.WorkflowRun
	loaded   bool
	discover bool
	direct   []actionsJob
}

type actionsJob struct {
	job      *github.WorkflowJob
	run      *github.WorkflowRun
	workflow *actionsWorkflow
	attempt  int64
}

type actionsAttempt struct {
	run     int64
	attempt int64
}

type actionsRunSelection struct {
	latest   bool
	attempts []int64
	jobs     map[int64]bool
}

type actionsRunner struct {
	api          actionsAPI
	repo         repository.Repository
	opts         ActionsScanOptions
	scanner      *Scanner
	limiter      *actionsRateLimiter
	result       ActionsScanResult
	workflows    []*actionsWorkflow
	workflowByID map[int64]*actionsWorkflow
	runs         map[int64]*github.WorkflowRun
	seenRuns     map[int64]bool
	seenJobs     map[int64]bool
	jobIDs       map[int64]bool
	jobNames     map[string]bool
	attemptRuns  map[actionsAttempt]*github.WorkflowRun
	attemptJobs  map[actionsAttempt][]*github.WorkflowJob
	locations    map[actionsAttempt][]actionsLocationJob
	locationRuns []actionsAttempt
	errors       []error
	consecutive  int
}

// ScanActions scans selected GitHub Actions job logs without persisting them.
func ScanActions(ctx context.Context, client *gh.GitHubClient, repo repository.Repository, opts ActionsScanOptions, scanner *Scanner, progress io.Writer) (ActionsScanResult, error) {
	if err := opts.Validate(); err != nil {
		return ActionsScanResult{}, err
	}
	if client == nil || scanner == nil || progress == nil {
		return ActionsScanResult{}, fmt.Errorf("actions scanner requires a client, scanner, and progress writer")
	}
	api := newRetryingActionsAPI(&githubActionsAPI{
		client:     client,
		repo:       repo,
		httpClient: &http.Client{Timeout: 2 * time.Minute},
	}, func(operation string, delay time.Duration, err error) error {
		_, writeErr := fmt.Fprintf(progress, "Retrying %s in %s after error: %v\n", operation, delay.Round(time.Second), scanner.redactMetadata(err.Error()))
		return writeErr
	})
	limiter := newActionsRateLimiter(opts.MaxJobsPerHour, func(delay time.Duration) error {
		_, err := fmt.Fprintf(progress, "Waiting %s for the job log rate limit\n", delay.Round(time.Second))
		return err
	})
	return scanActions(ctx, api, repo, opts, scanner, limiter)
}

func scanActions(ctx context.Context, api actionsAPI, repo repository.Repository, opts ActionsScanOptions, scanner *Scanner, limiter *actionsRateLimiter) (ActionsScanResult, error) {
	result := ActionsScanResult{Findings: []ActionsFinding{}}
	if err := opts.Validate(); err != nil {
		return result, err
	}
	if api == nil || scanner == nil || limiter == nil {
		return result, fmt.Errorf("actions scanner requires an API, scanner, and rate limiter")
	}
	r := &actionsRunner{
		api:          api,
		repo:         repo,
		opts:         opts,
		scanner:      scanner,
		limiter:      limiter,
		result:       result,
		workflowByID: make(map[int64]*actionsWorkflow),
		runs:         make(map[int64]*github.WorkflowRun),
		seenRuns:     make(map[int64]bool),
		seenJobs:     make(map[int64]bool),
		jobIDs:       make(map[int64]bool),
		jobNames:     make(map[string]bool),
		attemptRuns:  make(map[actionsAttempt]*github.WorkflowRun),
		attemptJobs:  make(map[actionsAttempt][]*github.WorkflowJob),
	}
	if actionsInterrupted(ctx, ctx.Err()) {
		r.result.Interrupted = true
		return r.result, nil
	}
	err := r.scan(ctx)
	if actionsInterrupted(ctx, err) {
		r.result.Interrupted, err = true, nil
	}
	if opts.LocationURL && len(r.locationRuns) > 0 {
		switch {
		case r.result.Interrupted:
			r.result.Warnings = append(r.result.Warnings, "finding location URLs were not resolved because the scan was interrupted")
		case err != nil:
			r.result.Warnings = append(r.result.Warnings, "finding location URLs were not resolved because scanning stopped with an error")
		default:
			err = r.resolveLocations(ctx)
			if actionsInterrupted(ctx, err) {
				r.result.Interrupted, err = true, nil
				r.result.Warnings = append(r.result.Warnings, "some finding location URLs were not resolved because the scan was interrupted")
			}
		}
	}
	if r.result.Summary.Runs == 0 && err == nil && len(r.errors) == 0 && !r.result.Interrupted {
		r.result.Warnings = append(r.result.Warnings, "no matching workflow runs were available")
	}
	if len(r.errors) > 0 {
		err = errors.Join(append([]error{fmt.Errorf("%d error(s) occurred; the affected targets were not scanned or resolved", len(r.errors))}, append(r.errors, err)...)...)
	}
	return r.result, err
}

// actionsInterrupted reports whether err comes from cancelling ctx, so the
// scan can stop gracefully and keep the results collected so far.
func actionsInterrupted(ctx context.Context, err error) bool {
	return err != nil && ctx.Err() != nil && errors.Is(err, context.Canceled)
}

func (r *actionsRunner) scan(ctx context.Context) error {
	var jobIDs []int64
	directIDs := make(map[int64]bool)
	for _, selector := range r.opts.Jobs {
		id, numeric, err := actionsSelectorID(selector)
		if err != nil {
			return err
		}
		if numeric {
			if !r.jobIDs[id] {
				r.jobIDs[id] = true
				jobIDs = append(jobIDs, id)
				directIDs[id] = true
			}
		} else {
			r.jobNames[selector] = false
		}
	}

	selections := r.runSelections()
	urlJobs := make(map[int64]ActionsRunTarget)
	for _, target := range r.opts.RunTargets {
		if target.JobID == 0 {
			continue
		}
		previous, found := urlJobs[target.JobID]
		if !found || previous.Attempt == 0 {
			urlJobs[target.JobID] = target
		}
		if !directIDs[target.JobID] {
			jobIDs = append(jobIDs, target.JobID)
			directIDs[target.JobID] = true
		}
	}

	selectedRuns := make(map[int64]bool)
	selectedAttempts := make(map[actionsAttempt]bool)
	for _, id := range r.opts.Runs {
		if selectedRuns[id] {
			continue
		}
		selectedRuns[id] = true
		latest, err := r.getRun(ctx, id)
		if err != nil {
			return err
		}
		workflow := r.addRunWorkflow(latest)
		workflow.loaded = true
		selection := selections[id]
		attempts := slices.Clone(selection.attempts)
		if selection.latest {
			attempts = append([]int64{int64(latest.GetRunAttempt())}, attempts...)
		}
		for _, attempt := range attempts {
			key := actionsAttempt{run: id, attempt: attempt}
			if selectedAttempts[key] {
				continue
			}
			run, err := r.getRunAttempt(ctx, latest, attempt)
			if err != nil {
				return err
			}
			if err := r.validateSelectedAttempt(run); err != nil {
				return err
			}
			r.addRunWorkflow(run)
			workflow.runs = append(workflow.runs, run)
			selectedAttempts[key] = true
		}
	}

	for _, id := range jobIDs {
		job, err := r.api.getJob(ctx, id)
		if err != nil {
			return fmt.Errorf("failed to get job %d: %w", id, err)
		}
		if job == nil || job.GetID() != id || job.GetRunID() <= 0 || job.RunAttempt != nil && job.GetRunAttempt() <= 0 {
			return fmt.Errorf("job %d has incomplete or inconsistent run metadata", id)
		}
		urlTarget, fromURL := urlJobs[id]
		if fromURL && job.GetRunID() != urlTarget.RunID {
			return fmt.Errorf("job %d does not belong to the run in its --run URL", id)
		}
		if len(selectedRuns) > 0 && !selectedRuns[job.GetRunID()] {
			return fmt.Errorf("job %d does not belong to a specified run", id)
		}
		latest, err := r.getRun(ctx, job.GetRunID())
		if err != nil {
			return err
		}
		var hints []int64
		if selection := selections[job.GetRunID()]; selection != nil {
			hints = selection.attempts
		}
		attempt, err := r.resolveJobAttempt(ctx, job, latest, urlTarget.Attempt, hints)
		if err != nil {
			return err
		}
		if fromURL && urlTarget.Attempt != 0 && attempt != urlTarget.Attempt {
			return fmt.Errorf("job %d does not belong to the attempt in its --run URL", id)
		}
		if len(selectedRuns) > 0 && !selections[job.GetRunID()].includesJob(id, attempt) {
			return fmt.Errorf("job %d is outside the targets selected by --run", id)
		}
		workflow := r.addRunWorkflow(latest)
		run := latest
		key := actionsAttempt{run: job.GetRunID(), attempt: attempt}
		if selectedAttempts[key] {
			run = r.attemptRuns[key]
		}
		workflow.direct = append(workflow.direct, actionsJob{
			job: job, run: run, workflow: workflow, attempt: attempt,
		})
	}

	discoverJobs := len(r.opts.Jobs) == 0 || len(r.jobNames) > 0
	if len(selectedRuns) == 0 && discoverJobs {
		workflows, err := r.api.listWorkflows(ctx)
		if err != nil {
			return fmt.Errorf("failed to list workflows: %w", err)
		}
		for _, workflow := range workflows {
			if workflow == nil || workflow.GetID() <= 0 {
				return fmt.Errorf("workflow listing contains an invalid workflow ID")
			}
			state := r.addWorkflow(workflow.GetID(), workflow.GetName(), workflow.GetPath())
			state.discover = true
		}
	}

	selectedWorkflows, err := r.selectWorkflows()
	if err != nil {
		return err
	}
	for _, workflow := range r.workflows {
		var direct []actionsJob
		for _, candidate := range workflow.direct {
			id := candidate.job.GetID()
			if !selectedWorkflows[workflow.id] {
				if r.jobIDs[id] {
					return fmt.Errorf("job %d does not belong to a selected workflow", id)
				}
				continue
			}
			if !r.matchesJob(candidate.job) {
				continue
			}
			if _, fromURL := urlJobs[id]; fromURL {
				run, err := r.getRunAttempt(ctx, candidate.run, candidate.attempt)
				if err != nil {
					return err
				}
				if err := r.validateSelectedAttempt(run); err != nil {
					return err
				}
				candidate.run = run
			}
			direct = append(direct, candidate)
		}
		workflow.direct = direct
	}
	if len(selectedRuns) > 0 {
		for key := range r.attemptJobs {
			if !selectedAttempts[key] {
				delete(r.attemptJobs, key)
			}
		}
	}
	var selected []*actionsWorkflow
	incompleteAttempts := make(map[actionsAttempt]bool)
	for _, workflow := range r.workflows {
		if !selectedWorkflows[workflow.id] {
			continue
		}
		selected = append(selected, workflow)
		for _, run := range workflow.runs {
			r.markRun(run)
			r.markIncompleteAttempt(run, incompleteAttempts)
		}
		for _, job := range workflow.direct {
			r.markRun(job.run)
			if _, fromURL := urlJobs[job.job.GetID()]; fromURL {
				r.markIncompleteAttempt(job.run, incompleteAttempts)
			}
		}
	}
	r.result.Summary.Workflows = len(selected)

	if err := r.traverse(ctx, selected, discoverJobs); err != nil {
		return err
	}
	for _, selector := range r.opts.Jobs {
		_, numeric, _ := actionsSelectorID(selector)
		if !numeric && !r.jobNames[selector] {
			return fmt.Errorf("no job matches %q in the selected runs", r.scanner.redactMetadata(selector))
		}
	}
	return nil
}

func (r *actionsRunner) runSelections() map[int64]*actionsRunSelection {
	selections := make(map[int64]*actionsRunSelection, len(r.opts.Runs))
	hasTargets := make(map[int64]bool)
	for _, id := range r.opts.Runs {
		selections[id] = &actionsRunSelection{jobs: make(map[int64]bool)}
	}
	for _, target := range r.opts.RunTargets {
		selection := selections[target.RunID]
		hasTargets[target.RunID] = true
		switch {
		case target.JobID != 0:
			selection.jobs[target.JobID] = true
		case target.Attempt == 0:
			selection.latest = true
		case !slices.Contains(selection.attempts, target.Attempt):
			selection.attempts = append(selection.attempts, target.Attempt)
		}
	}
	for id, selection := range selections {
		if !hasTargets[id] {
			selection.latest = true
		}
	}
	return selections
}

func (s *actionsRunSelection) includesJob(jobID, attempt int64) bool {
	if s.latest || slices.Contains(s.attempts, attempt) {
		return true
	}
	return s.jobs[jobID]
}

func (r *actionsRunner) validateSelectedAttempt(run *github.WorkflowRun) error {
	if run.GetStatus() != "completed" && !r.opts.AllowInProgress {
		return fmt.Errorf("workflow run %d attempt %d is not complete; use --allow-in-progress to scan completed jobs", run.GetID(), run.GetRunAttempt())
	}
	return nil
}

func (r *actionsRunner) markIncompleteAttempt(run *github.WorkflowRun, seen map[actionsAttempt]bool) {
	key := actionsAttempt{run: run.GetID(), attempt: int64(run.GetRunAttempt())}
	if run.GetStatus() == "completed" || seen[key] {
		return
	}
	seen[key] = true
	r.result.Summary.IncompleteRuns++
	r.result.Warnings = append(r.result.Warnings, fmt.Sprintf("run %d attempt %d is incomplete; jobs that have not completed cannot be scanned", key.run, key.attempt))
}

func (r *actionsRunner) matchesJob(job *github.WorkflowJob) bool {
	if len(r.opts.Jobs) == 0 {
		return true
	}
	matches := r.jobIDs[job.GetID()]
	for name := range r.jobNames {
		if job.GetName() == name {
			r.jobNames[name] = true
			matches = true
		}
	}
	return matches
}

func (r *actionsRunner) resolveJobAttempt(ctx context.Context, job *github.WorkflowJob, run *github.WorkflowRun, expected int64, hints []int64) (int64, error) {
	if job.RunAttempt != nil {
		return job.GetRunAttempt(), nil
	}
	if expected != 0 {
		found, err := r.attemptContainsJob(ctx, run.GetID(), expected, job.GetID())
		if err != nil {
			return 0, fmt.Errorf("failed to find attempt for job %d: %w", job.GetID(), err)
		}
		if found {
			return expected, nil
		}
		return 0, fmt.Errorf("job %d does not belong to the attempt in its --run URL", job.GetID())
	}
	for _, attempt := range hints {
		if attempt <= int64(run.GetRunAttempt()) {
			continue
		}
		found, err := r.attemptContainsJob(ctx, run.GetID(), attempt, job.GetID())
		if err != nil {
			return 0, fmt.Errorf("failed to find attempt for job %d in run %d: %w", job.GetID(), run.GetID(), err)
		}
		if found {
			return attempt, nil
		}
	}
	for attempt := int64(run.GetRunAttempt()); attempt > 0; attempt-- {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		found, err := r.attemptContainsJob(ctx, run.GetID(), attempt, job.GetID())
		if err != nil {
			return 0, fmt.Errorf("failed to find attempt for job %d in run %d: %w", job.GetID(), run.GetID(), err)
		}
		if found {
			return attempt, nil
		}
	}
	return 0, fmt.Errorf("could not determine the attempt for job %d in run %d", job.GetID(), run.GetID())
}

func (r *actionsRunner) attemptContainsJob(ctx context.Context, runID, attempt, jobID int64) (bool, error) {
	jobs, err := r.listAttemptJobs(ctx, runID, attempt)
	if err != nil {
		return false, err
	}
	for _, candidate := range jobs {
		if candidate.GetID() == jobID {
			return true, nil
		}
	}
	return false, nil
}

func (r *actionsRunner) getRun(ctx context.Context, id int64) (*github.WorkflowRun, error) {
	if run := r.runs[id]; run != nil {
		return run, nil
	}
	run, err := r.api.getRun(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get workflow run %d: %w", id, err)
	}
	if err := validateActionsRun(run, id); err != nil {
		return nil, err
	}
	r.runs[id] = run
	r.attemptRuns[actionsAttempt{run: id, attempt: int64(run.GetRunAttempt())}] = run
	return run, nil
}

func (r *actionsRunner) getRunAttempt(ctx context.Context, latest *github.WorkflowRun, attempt int64) (*github.WorkflowRun, error) {
	key := actionsAttempt{run: latest.GetID(), attempt: attempt}
	if run := r.attemptRuns[key]; run != nil {
		return run, nil
	}
	run, err := r.api.getRunAttempt(ctx, key.run, key.attempt)
	if err != nil {
		return nil, fmt.Errorf("failed to get workflow run %d attempt %d: %w", key.run, key.attempt, err)
	}
	if err := validateActionsRun(run, key.run); err != nil {
		return nil, err
	}
	if int64(run.GetRunAttempt()) != key.attempt || run.GetWorkflowID() != latest.GetWorkflowID() {
		return nil, fmt.Errorf("workflow run %d attempt %d has inconsistent metadata", key.run, key.attempt)
	}
	r.attemptRuns[key] = run
	return run, nil
}

func validateActionsRun(run *github.WorkflowRun, id int64) error {
	if run == nil || id <= 0 || run.GetID() != id || run.GetWorkflowID() <= 0 || run.GetRunAttempt() <= 0 || run.GetStatus() == "" {
		return fmt.Errorf("workflow run %d has incomplete or inconsistent metadata", id)
	}
	return nil
}

func (r *actionsRunner) addRunWorkflow(run *github.WorkflowRun) *actionsWorkflow {
	return r.addWorkflow(run.GetWorkflowID(), run.GetName(), run.GetPath())
}

func (r *actionsRunner) addWorkflow(id int64, name, workflowPath string) *actionsWorkflow {
	workflow := r.workflowByID[id]
	if workflow == nil {
		workflow = &actionsWorkflow{id: id}
		r.workflowByID[id] = workflow
		r.workflows = append(r.workflows, workflow)
	}
	ref := actionsWorkflowRef{name: name, path: workflowPath}
	for _, existing := range workflow.refs {
		if existing == ref {
			return workflow
		}
	}
	workflow.refs = append(workflow.refs, ref)
	return workflow
}

func (r *actionsRunner) selectWorkflows() (map[int64]bool, error) {
	selected := make(map[int64]bool)
	if len(r.opts.Workflows) == 0 {
		for _, workflow := range r.workflows {
			selected[workflow.id] = true
		}
		return selected, nil
	}
	for _, selector := range r.opts.Workflows {
		var matches []*actionsWorkflow
		for _, workflow := range r.workflows {
			if workflow.matches(selector) {
				matches = append(matches, workflow)
			}
		}
		switch len(matches) {
		case 0:
			return nil, fmt.Errorf("no workflow matches %q", r.scanner.redactMetadata(selector))
		case 1:
			selected[matches[0].id] = true
		default:
			return nil, fmt.Errorf("workflow selector %q is ambiguous; use its ID or full path", r.scanner.redactMetadata(selector))
		}
	}
	return selected, nil
}

func (w *actionsWorkflow) matches(selector string) bool {
	id, numeric, _ := actionsSelectorID(selector)
	if numeric {
		return w.id == id
	}
	for _, ref := range w.refs {
		if strings.EqualFold(selector, ref.name) && ref.name != "" {
			return true
		}
		if ref.path != "" && (selector == ref.path || !strings.Contains(selector, "/") && selector == path.Base(ref.path)) {
			return true
		}
	}
	return false
}

func (r *actionsRunner) loadRuns(ctx context.Context, workflow *actionsWorkflow) error {
	if workflow.loaded || !workflow.discover {
		return nil
	}
	// A failed listing is not retried at later depths.
	workflow.loaded = true
	runs, err := r.api.listRuns(ctx, workflow.id, r.opts.RunsPerWorkflow)
	if err != nil {
		return fmt.Errorf("failed to list runs for workflow %d: %w", workflow.id, err)
	}
	if len(runs) > r.opts.RunsPerWorkflow {
		runs = runs[:r.opts.RunsPerWorkflow]
	}
	for _, run := range runs {
		if run == nil {
			return fmt.Errorf("workflow %d returned an invalid run", workflow.id)
		}
		if err := validateActionsRun(run, run.GetID()); err != nil {
			return err
		}
		if run.GetWorkflowID() != workflow.id || run.GetStatus() != "completed" {
			return fmt.Errorf("workflow run %d is not a completed run of workflow %d", run.GetID(), workflow.id)
		}
	}
	seen := make(map[int64]bool)
	for _, run := range runs {
		id := run.GetID()
		if seen[id] {
			continue
		}
		seen[id] = true
		workflow.runs = append(workflow.runs, run)
		r.runs[id] = run
	}
	return nil
}

// maxActionsConsecutiveErrors stops a scan whose every request keeps failing,
// e.g. during a GitHub outage, instead of exhausting the remaining targets.
const maxActionsConsecutiveErrors = 10

// continueAfter records a recoverable per-target error so the scan can move on,
// and returns the error when the scan must stop: on cancellation, on
// authentication or rate-limit failures that would affect every later request,
// or after too many consecutive failures.
func (r *actionsRunner) continueAfter(ctx context.Context, err error) error {
	if err == nil {
		r.consecutive = 0
		return nil
	}
	if ctx.Err() != nil || errors.Is(err, context.Canceled) || actionsFatalError(err) {
		return err
	}
	r.errors = append(r.errors, err)
	r.consecutive++
	if r.consecutive >= maxActionsConsecutiveErrors {
		return fmt.Errorf("stopped after %d consecutive errors", r.consecutive)
	}
	return nil
}

// countFailure increments counter for a recoverable error and returns err.
func (r *actionsRunner) countFailure(ctx context.Context, err error, counter *int) error {
	if err != nil && ctx.Err() == nil && !errors.Is(err, context.Canceled) && !actionsFatalError(err) {
		*counter++
	}
	return err
}

func (r *actionsRunner) markRun(run *github.WorkflowRun) {
	if !r.seenRuns[run.GetID()] {
		r.seenRuns[run.GetID()] = true
		r.result.Summary.Runs++
	}
}

func (r *actionsRunner) traverse(ctx context.Context, workflows []*actionsWorkflow, discoverJobs bool) error {
	for depth := 0; ; depth++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		queues := make([][]actionsJob, len(workflows))
		moreRuns := false
		for index, workflow := range workflows {
			if depth == 0 {
				for _, job := range workflow.direct {
					r.enqueue(&queues[index], job)
				}
			}
			if discoverJobs {
				if err := r.continueAfter(ctx, r.countFailure(ctx, r.loadRuns(ctx, workflow), &r.result.Summary.FailedWorkflows)); err != nil {
					return err
				}
				if depth < len(workflow.runs) {
					run := workflow.runs[depth]
					r.markRun(run)
					if err := r.continueAfter(ctx, r.countFailure(ctx, r.enqueueRunJobs(ctx, &queues[index], workflow, run), &r.result.Summary.FailedRuns)); err != nil {
						return err
					}
				}
				if depth+1 < len(workflow.runs) {
					moreRuns = true
				}
			}
			if len(queues[index]) > 0 {
				if err := r.continueAfter(ctx, r.countFailure(ctx, r.scanJob(ctx, queues[index][0]), &r.result.Summary.Failed)); err != nil {
					return err
				}
				queues[index] = queues[index][1:]
			}
		}
		for {
			any := false
			for index := range queues {
				if len(queues[index]) == 0 {
					continue
				}
				any = true
				if err := r.continueAfter(ctx, r.countFailure(ctx, r.scanJob(ctx, queues[index][0]), &r.result.Summary.Failed)); err != nil {
					return err
				}
				queues[index] = queues[index][1:]
			}
			if !any {
				break
			}
		}
		if !moreRuns {
			return nil
		}
	}
}

func (r *actionsRunner) enqueueRunJobs(ctx context.Context, queue *[]actionsJob, workflow *actionsWorkflow, run *github.WorkflowRun) error {
	attempt := int64(run.GetRunAttempt())
	jobs, err := r.listAttemptJobs(ctx, run.GetID(), attempt)
	if err != nil {
		return err
	}
	delete(r.attemptJobs, actionsAttempt{run: run.GetID(), attempt: attempt})
	for _, job := range jobs {
		if !r.matchesJob(job) {
			r.result.Summary.Filtered++
			continue
		}
		r.enqueue(queue, actionsJob{job: job, run: run, workflow: workflow, attempt: attempt})
	}
	return nil
}

func (r *actionsRunner) listAttemptJobs(ctx context.Context, runID, attempt int64) ([]*github.WorkflowJob, error) {
	key := actionsAttempt{run: runID, attempt: attempt}
	if jobs, found := r.attemptJobs[key]; found {
		return jobs, nil
	}
	jobs, err := r.api.listJobs(ctx, runID, attempt)
	if err != nil {
		return nil, fmt.Errorf("failed to list jobs for run %d attempt %d: %w", runID, attempt, err)
	}
	for _, job := range jobs {
		if job == nil || job.GetID() <= 0 || job.GetRunID() != runID || job.RunAttempt != nil && job.GetRunAttempt() != attempt {
			return nil, fmt.Errorf("run %d attempt %d returned a job with inconsistent metadata", runID, attempt)
		}
	}
	r.attemptJobs[key] = jobs
	return jobs, nil
}

func (r *actionsRunner) enqueue(queue *[]actionsJob, job actionsJob) {
	if r.seenJobs[job.job.GetID()] {
		return
	}
	r.seenJobs[job.job.GetID()] = true
	*queue = append(*queue, job)
}

func (r *actionsRunner) scanJob(ctx context.Context, candidate actionsJob) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	job := candidate.job
	if job.GetStatus() == "" {
		return fmt.Errorf("job %d has no status", job.GetID())
	}
	if job.GetStatus() != "completed" {
		r.result.Summary.Incomplete++
		r.result.Warnings = append(r.result.Warnings, fmt.Sprintf("job %d in run %d has not completed and was not scanned", job.GetID(), candidate.run.GetID()))
		return nil
	}
	if actionsJobWasNotRun(job) {
		r.result.Summary.Skipped++
		return nil
	}
	if err := r.limiter.acquire(ctx); err != nil {
		return fmt.Errorf("failed to wait for the job log limit: %w", err)
	}
	fragment := Fragment{
		FilePath:  fmt.Sprintf("actions/jobs/%d.log", job.GetID()),
		CommitSHA: candidate.run.GetHeadSHA(),
	}
	var logStats actionsLogStats
	var findings []Finding
	err := r.api.streamLog(ctx, job.GetID(), func(content io.Reader) error {
		var scanErr error
		logStats, findings, scanErr = scanActionsJobLog(content, fragment, r.scanner)
		return scanErr
	})
	if actionsLogUnavailable(err) {
		r.result.Summary.Unavailable++
		r.result.Warnings = append(r.result.Warnings, fmt.Sprintf("log for job %d in run %d is unavailable and was not scanned", job.GetID(), candidate.run.GetID()))
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to get log for job %d in run %d: %w", job.GetID(), candidate.run.GetID(), err)
	}
	r.result.Summary.Scanned++
	name, workflowPath := candidate.run.GetName(), candidate.run.GetPath()
	if len(candidate.workflow.refs) > 0 {
		if name == "" {
			name = candidate.workflow.refs[0].name
		}
		if workflowPath == "" {
			workflowPath = candidate.workflow.refs[0].path
		}
	}
	firstFinding := len(r.result.Findings)
	for _, finding := range findings {
		finding.PatternID = r.scanner.redactMetadata(finding.PatternID)
		finding.TokenType = r.scanner.redactMetadata(finding.TokenType)
		finding.DisplayName = r.scanner.redactMetadata(finding.DisplayName)
		finding.Commit = r.scanner.redactMetadata(finding.Commit)
		r.result.Findings = append(r.result.Findings, ActionsFinding{
			Finding:      finding,
			WorkflowID:   candidate.workflow.id,
			WorkflowName: r.scanner.redactMetadata(name),
			WorkflowPath: r.scanner.redactMetadata(workflowPath),
			RunID:        candidate.run.GetID(),
			RunAttempt:   candidate.attempt,
			JobID:        job.GetID(),
			JobName:      r.scanner.redactMetadata(job.GetName()),
			JobURL:       r.scanner.redactMetadata(job.GetHTMLURL()),
		})
	}
	if r.opts.LocationURL && len(findings) > 0 {
		if job.GetHTMLURL() == "" {
			jobURL, err := actionsJobURL(r.repo, candidate.run.GetID(), job.GetID())
			if err != nil {
				return fmt.Errorf("failed to build job URL for job %d: %w", job.GetID(), err)
			}
			for index := firstFinding; index < len(r.result.Findings); index++ {
				r.result.Findings[index].JobURL = r.scanner.redactMetadata(jobURL.String())
			}
		}
		r.queueLocation(candidate, logStats, firstFinding, len(r.result.Findings))
	}
	return nil
}

func actionsJobWasNotRun(job *github.WorkflowJob) bool {
	if job.GetConclusion() != "skipped" {
		return false
	}
	for _, step := range job.Steps {
		if step != nil && (step.StartedAt != nil || step.GetStatus() == "completed" && step.GetConclusion() != "skipped") {
			return false
		}
	}
	return true
}
