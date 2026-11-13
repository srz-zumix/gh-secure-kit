package secretscanning

import (
	"errors"
	"fmt"
	"os"
	"os/signal"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/srz-zumix/gh-secure-kit/internal/localscan"
	"github.com/srz-zumix/go-gh-extension/pkg/render"
)

// NewActionsCmd returns the secret-scanning actions command.
func NewActionsCmd() *cobra.Command {
	var (
		repo       string
		configFile string
		showSecret bool
		runInputs  []string
		opts       localscan.ActionsScanOptions
		exporter   cmdutil.Exporter
	)
	cmd := &cobra.Command{
		Use:   "actions",
		Short: "Scan GitHub Actions job logs for secrets",
		Long: `Scan GitHub Actions job logs in one repository using built-in and user-defined secret patterns.
By default, scan the latest completed run of each workflow, rotating between workflows by job. Use --runs-per-workflow to include older runs.
Use --workflow to select workflows by ID, name, or filename, and --job to select jobs by ID or exact name. Both flags are repeatable.
Use --run to scan only specified run IDs or HTTPS run, attempt, and job URLs. Repeat the flag; numeric IDs can also be comma-separated.
A run URL selects the latest attempt, an attempt URL selects that attempt, and a job URL selects only that job. Multiple targets are combined per run.
--workflow and --job further restrict the selected targets. An explicit job ID can select an older attempt when a full latest run is selected.
URLs must refer to one repository and host, and must match --repo if specified.
URL hosts must be GitHub.com, configured in gh, or explicitly named by a matching host-qualified --repo.
--run cannot be combined with --runs-per-workflow.
By default, explicitly selected attempts must be complete. With --allow-in-progress, scan their completed jobs and warn about uncompleted jobs.
The running job's own log cannot be downloaded before it completes.
--max-jobs-per-hour limits job log acquisition starts in this process over a rolling hour; failed acquisitions count, and 0 disables the limit.
Metadata requests, storage transfers, and other processes are not included in the limit.
The default of 1000 leaves headroom within a 5000 requests/hour token limit; use a lower value with a workflow GITHUB_TOKEN.
With --location-url, download the run attempt's log archive only when a secret is found and link findings to verified step lines.
The archive can contain other jobs' logs; they are not scanned. When needed, fetch individual step logs to verify missing locations.
Archive and additional step-log requests are not included in --max-jobs-per-hour.
Archives are limited to 256 MiB, 100000 entries, 128 MiB per extracted entry, 1 GiB total extraction work, and a 1 GiB search budget per job.
Additional step logs are limited to 128 MiB each, 1 GiB total per job, and a separate 1 GiB search budget per job.
If step locations cannot be verified, retain the job URL and report a warning.
Transient failures (HTTP 500, 502, 503, 504, and network errors) are retried with backoff before being treated as errors.
Unavailable logs are reported as warnings. Other errors for an individual workflow, run, job, or location lookup are skipped and reported together at the end.
Authentication, permission, and rate-limit errors, or 10 consecutive errors, stop the scan.
This is an independent reimplementation and does not use GitHub's official secret scanning patterns.
When interrupted (Ctrl-C), stop scanning and report the findings from the job logs scanned so far; location URLs are not resolved after an interruption.
Exits with status 1 if any secret is found, 130 if interrupted without findings.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			targets, err := localscan.ParseActionsRunTargets(runInputs)
			if err != nil {
				return fmt.Errorf("invalid Actions scan options: %w", err)
			}
			opts.Runs, opts.RunTargets = targets.Runs, targets.Targets
			opts.RunsPerWorkflowSet = cmd.Flags().Changed("runs-per-workflow")
			if err := opts.Validate(); err != nil {
				return fmt.Errorf("invalid Actions scan options: %w", err)
			}
			repository, err := localscan.ResolveActionsRepository(repo, targets.Repository)
			if err != nil {
				return fmt.Errorf("failed to parse repository: %w", err)
			}
			scanner, err := localscan.BuildScanner(".", configFile, showSecret)
			if err != nil {
				return fmt.Errorf("failed to configure secret scanning: %w", err)
			}
			client, err := localscan.NewActionsClient(repository, targets.Repository != nil, repo)
			if err != nil {
				return fmt.Errorf("failed to create GitHub client: %w", err)
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()
			result, scanErr := localscan.ScanActions(ctx, client, repository, opts, scanner, cmd.ErrOrStderr())
			if scanErr != nil {
				scanErr = fmt.Errorf("failed to scan Actions logs: %w", scanErr)
			}
			renderer := render.NewRenderer(exporter)
			renderErr := localscan.RenderActionsFindings(renderer, result.Findings)
			if renderErr != nil {
				renderErr = fmt.Errorf("failed to render Actions findings: %w", renderErr)
			}
			summaryErr := localscan.RenderActionsSummary(cmd.ErrOrStderr(), result)
			if summaryErr != nil {
				summaryErr = fmt.Errorf("failed to report Actions scan coverage: %w", summaryErr)
			}
			if err := errors.Join(scanErr, renderErr, summaryErr); err != nil {
				return err
			}
			if code := result.ExitCode(); code != 0 {
				os.Exit(code)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&repo, "repo", "R", "", "Repository as '[HOST/]OWNER/REPO' (default: --run URL repository, otherwise current repository)")
	f.StringArrayVar(&opts.Workflows, "workflow", nil, "Workflow ID, name, or filename to scan (repeatable; default: all workflows)")
	f.StringArrayVar(&runInputs, "run", nil, "Run ID or HTTPS run, attempt, or job URL (repeatable; IDs may be comma-separated)")
	f.StringArrayVar(&opts.Jobs, "job", nil, "Job ID or exact name to scan (repeatable; default: all selected jobs)")
	f.IntVar(&opts.RunsPerWorkflow, "runs-per-workflow", 1, "Number of latest completed runs per workflow (cannot be combined with --run)")
	f.BoolVar(&opts.AllowInProgress, "allow-in-progress", false, "Allow unfinished --run values and scan only completed jobs")
	f.IntVar(&opts.MaxJobsPerHour, "max-jobs-per-hour", 1000, "Maximum job log acquisition starts per rolling hour in this process (0: unlimited)")
	f.BoolVar(&opts.LocationURL, "location-url", false, "Download run log archives on findings to link to verified step lines")
	f.StringVar(&configFile, "config", "", "Path to local secret scanning config (default: auto-discover .gh-secure-kit-secret-scanning.yml)")
	f.BoolVar(&showSecret, "show-secret", false, "Show full matched secrets instead of redacted values")
	cmd.MarkFlagsMutuallyExclusive("run", "runs-per-workflow")
	cmdutil.AddFormatFlags(cmd, &exporter)
	return cmd
}
