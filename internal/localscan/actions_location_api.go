package localscan

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/google/go-github/v93/github"
)

func (r *actionsRunner) apiStepRanges(ctx context.Context, job *github.WorkflowJob, content []byte) ([]actionsStepRange, error) {
	log := normalizedActionsLocationLog(content)
	if len(log) == 0 {
		return nil, ctx.Err()
	}
	var ranges []actionsStepRange
	remainingBytes := maxActionsArchiveExpandedBytes
	remainingSearch := maxActionsArchiveSearchBytes
	unavailable := 0
	steps := slices.Clone(job.Steps)
	slices.SortFunc(steps, func(left, right *github.TaskStep) int {
		switch {
		case left.GetNumber() < right.GetNumber():
			return -1
		case left.GetNumber() > right.GetNumber():
			return 1
		default:
			return 0
		}
	})
	for _, step := range steps {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if step.GetConclusion() == "skipped" {
			continue
		}
		if remainingBytes <= 0 {
			return nil, fmt.Errorf("step logs exceed the %d-byte processing limit", maxActionsArchiveExpandedBytes)
		}
		data, err := r.api.getStepLog(ctx, job.GetID(), step.GetNumber(), min(maxActionsArchiveEntryBytes, remainingBytes))
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if actionsLogUnavailable(err) {
			unavailable++
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("failed to get step %d: %w", step.GetNumber(), err)
		}
		remainingBytes -= int64(len(data))
		normalized := normalizedActionsLocationLog(data)
		if len(normalized) == 0 || len(normalized) > len(log) {
			continue
		}
		if err := reserveActionsArchiveSearch(int64(len(log)), &remainingSearch); err != nil {
			return nil, err
		}
		if position, ok := uniqueActionsStepRange(log, normalized, step.GetNumber()); ok {
			ranges = append(ranges, position)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if unavailable > 0 {
		r.result.Warnings = append(r.result.Warnings, fmt.Sprintf(
			"%d step log(s) are unavailable for job %d", unavailable, job.GetID()))
	}
	// All available steps are checked so overlapping candidate ranges remain ambiguous.
	return ranges, nil
}

func normalizedActionsLocationLog(content []byte) []byte {
	if actionsBareCarriageReturn(content) {
		return nil
	}
	normalized := normalizeActionsLog(string(content))
	normalized = strings.ReplaceAll(normalized, "\r\n", "\n")
	if normalized != "" && !strings.HasSuffix(normalized, "\n") {
		normalized += "\n"
	}
	return []byte(normalized)
}

func uniqueActionsStepRange(log, step []byte, number int64) (actionsStepRange, bool) {
	if len(step) == 0 {
		return actionsStepRange{}, false
	}
	start := bytes.Index(log, step)
	if start < 0 || bytes.Contains(log[start+1:], step) || !actionsStepAt(log, step, start) {
		return actionsStepRange{}, false
	}
	first := 1 + bytes.Count(log[:start], []byte{'\n'})
	return actionsStepRange{number: number, firstLine: first, lastLine: first + actionsLineCount(step) - 1}, true
}
