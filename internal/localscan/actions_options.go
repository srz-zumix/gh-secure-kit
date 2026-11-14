package localscan

import (
	"fmt"
	"strconv"
	"strings"
)

// ActionsScanOptions selects workflow runs and jobs to scan.
type ActionsScanOptions struct {
	Workflows          []string
	Runs               []int64
	RunTargets         []ActionsRunTarget
	Jobs               []string
	RunsPerWorkflow    int
	RunsPerWorkflowSet bool
	MaxJobsPerHour     int
	AllowInProgress    bool
	LocationURL        bool
}

// Validate checks options before any GitHub API requests are made.
func (o ActionsScanOptions) Validate() error {
	if o.RunsPerWorkflow < 1 {
		return fmt.Errorf("--runs-per-workflow must be positive")
	}
	if o.MaxJobsPerHour < 0 {
		return fmt.Errorf("--max-jobs-per-hour must be non-negative")
	}
	if len(o.Runs) > 0 && o.RunsPerWorkflowSet {
		return fmt.Errorf("--run cannot be combined with --runs-per-workflow")
	}
	if o.AllowInProgress && len(o.Runs) == 0 {
		return fmt.Errorf("--allow-in-progress requires --run")
	}
	runs := make(map[int64]bool, len(o.Runs))
	for _, id := range o.Runs {
		if id <= 0 {
			return fmt.Errorf("--run requires positive run IDs")
		}
		runs[id] = true
	}
	type jobTarget struct {
		run, attempt int64
	}
	jobs := make(map[int64]jobTarget)
	for _, target := range o.RunTargets {
		if !runs[target.RunID] || target.Attempt < 0 || target.JobID < 0 || int64(int(target.Attempt)) != target.Attempt {
			return fmt.Errorf("invalid --run target")
		}
		if target.JobID == 0 {
			continue
		}
		previous, found := jobs[target.JobID]
		if found && (previous.run != target.RunID || previous.attempt != 0 && target.Attempt != 0 && previous.attempt != target.Attempt) {
			return fmt.Errorf("conflicting --run job targets")
		}
		if !found || previous.attempt == 0 {
			jobs[target.JobID] = jobTarget{target.RunID, target.Attempt}
		}
	}
	for _, selectors := range []struct {
		flag   string
		values []string
	}{
		{"--workflow", o.Workflows},
		{"--job", o.Jobs},
	} {
		for _, selector := range selectors.values {
			if strings.TrimSpace(selector) == "" {
				return fmt.Errorf("%s requires a non-empty selector", selectors.flag)
			}
			if _, _, err := actionsSelectorID(selector); err != nil {
				return fmt.Errorf("%s numeric selectors must be positive 64-bit IDs", selectors.flag)
			}
		}
	}
	return nil
}

func actionsSelectorID(selector string) (int64, bool, error) {
	digits := strings.TrimPrefix(selector, "-")
	if digits == "" {
		return 0, false, nil
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return 0, false, nil
		}
	}
	id, err := strconv.ParseInt(selector, 10, 64)
	if err != nil || id <= 0 {
		return 0, true, fmt.Errorf("invalid ID")
	}
	return id, true, nil
}
