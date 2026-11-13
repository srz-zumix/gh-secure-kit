package localscan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"syscall"
	"time"

	"github.com/google/go-github/v93/github"
)

const (
	actionsRetryBaseDelay = 2 * time.Second
	// actionsMaxRetryAfter is the longest server-requested delay honored;
	// a longer one gives up so the target is reported as an error instead.
	actionsMaxRetryAfter = time.Minute
)

// retryingActionsAPI retries transient GitHub failures (HTTP 500, 502, 503,
// 504, and network errors) with exponential backoff. Retries are not counted
// against the job log rate limit.
type retryingActionsAPI struct {
	api     actionsAPI
	wait    func(context.Context, time.Duration) error
	jitter  func(time.Duration) time.Duration
	onRetry func(operation string, delay time.Duration, err error) error
}

func newRetryingActionsAPI(api actionsAPI, onRetry func(string, time.Duration, error) error) *retryingActionsAPI {
	return &retryingActionsAPI{
		api:  api,
		wait: waitForActionsLimit,
		jitter: func(delay time.Duration) time.Duration {
			return time.Duration(rand.Int64N(int64(delay)/4 + 1))
		},
		onRetry: onRetry,
	}
}

func actionsRetry[T any](ctx context.Context, a *retryingActionsAPI, operation string, call func() (T, error)) (T, error) {
	for retry := 0; ; retry++ {
		value, err := call()
		if err == nil || ctx.Err() != nil || retry >= actionsRetryLimit(err) {
			return value, err
		}
		delay := actionsRetryBaseDelay << retry
		if requested := actionsRetryAfter(err); requested > 0 {
			if requested > actionsMaxRetryAfter {
				return value, err
			}
			delay = requested
		} else if a.jitter != nil {
			delay += a.jitter(delay)
		}
		if a.onRetry != nil {
			if notifyErr := a.onRetry(operation, delay, err); notifyErr != nil {
				return value, notifyErr
			}
		}
		if waitErr := a.wait(ctx, delay); waitErr != nil {
			return value, waitErr
		}
	}
}

// actionsRetryLimit returns how many times a failed request is retried.
// Gateway errors and network failures are usually transient; an internal
// server error may be persistent, so it is retried only once.
func actionsRetryLimit(err error) int {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return 0
	}
	status := actionsGitHubStatus(err)
	var logErr *actionsLogError
	if errors.As(err, &logErr) {
		if logErr.status != 0 {
			status = logErr.status
		} else if logErr.transient {
			return 3
		}
	}
	switch status {
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return 3
	case http.StatusInternalServerError:
		return 1
	case 0:
		if logErr == nil && actionsTransientNetworkError(err) {
			return 3
		}
	}
	return 0
}

// actionsTransientNetworkError reports transport failures such as timeouts,
// connection resets, and truncated responses.
func actionsTransientNetworkError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	var networkErr net.Error
	return errors.As(err, &networkErr)
}

func actionsRetryAfter(err error) time.Duration {
	var logErr *actionsLogError
	if errors.As(err, &logErr) && logErr.retryAfter > 0 {
		return logErr.retryAfter
	}
	var response *github.ErrorResponse
	if errors.As(err, &response) && response.Response != nil {
		return actionsRetryAfterHeader(response.Response.Header)
	}
	return 0
}

func actionsRetryAfterHeader(header http.Header) time.Duration {
	value := header.Get("Retry-After")
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds <= 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	if at, err := http.ParseTime(value); err == nil {
		return max(time.Until(at), 0)
	}
	return 0
}

func (a *retryingActionsAPI) listWorkflows(ctx context.Context) ([]*github.Workflow, error) {
	return actionsRetry(ctx, a, "listing workflows", func() ([]*github.Workflow, error) {
		return a.api.listWorkflows(ctx)
	})
}

func (a *retryingActionsAPI) listRuns(ctx context.Context, workflowID int64, limit int) ([]*github.WorkflowRun, error) {
	return actionsRetry(ctx, a, fmt.Sprintf("listing runs for workflow %d", workflowID), func() ([]*github.WorkflowRun, error) {
		return a.api.listRuns(ctx, workflowID, limit)
	})
}

func (a *retryingActionsAPI) getRun(ctx context.Context, runID int64) (*github.WorkflowRun, error) {
	return actionsRetry(ctx, a, fmt.Sprintf("getting run %d", runID), func() (*github.WorkflowRun, error) {
		return a.api.getRun(ctx, runID)
	})
}

func (a *retryingActionsAPI) getRunAttempt(ctx context.Context, runID, attempt int64) (*github.WorkflowRun, error) {
	return actionsRetry(ctx, a, fmt.Sprintf("getting run %d attempt %d", runID, attempt), func() (*github.WorkflowRun, error) {
		return a.api.getRunAttempt(ctx, runID, attempt)
	})
}

func (a *retryingActionsAPI) listJobs(ctx context.Context, runID, attempt int64) ([]*github.WorkflowJob, error) {
	return actionsRetry(ctx, a, fmt.Sprintf("listing jobs for run %d attempt %d", runID, attempt), func() ([]*github.WorkflowJob, error) {
		return a.api.listJobs(ctx, runID, attempt)
	})
}

func (a *retryingActionsAPI) getJob(ctx context.Context, jobID int64) (*github.WorkflowJob, error) {
	return actionsRetry(ctx, a, fmt.Sprintf("getting job %d", jobID), func() (*github.WorkflowJob, error) {
		return a.api.getJob(ctx, jobID)
	})
}

func (a *retryingActionsAPI) getLog(ctx context.Context, jobID int64) ([]byte, error) {
	return actionsRetry(ctx, a, fmt.Sprintf("getting log for job %d", jobID), func() ([]byte, error) {
		return a.api.getLog(ctx, jobID)
	})
}

func (a *retryingActionsAPI) getStepLog(ctx context.Context, jobID, stepNumber, limit int64) ([]byte, error) {
	return actionsRetry(ctx, a, fmt.Sprintf("getting log for job %d step %d", jobID, stepNumber), func() ([]byte, error) {
		return a.api.getStepLog(ctx, jobID, stepNumber, limit)
	})
}

func (a *retryingActionsAPI) getRunLogArchive(ctx context.Context, runID, attempt int64) ([]byte, error) {
	return actionsRetry(ctx, a, fmt.Sprintf("getting log archive for run %d attempt %d", runID, attempt), func() ([]byte, error) {
		return a.api.getRunLogArchive(ctx, runID, attempt)
	})
}
