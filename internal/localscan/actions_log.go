package localscan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/google/go-github/v93/github"
	"github.com/srz-zumix/go-gh-extension/pkg/gh"
	"github.com/srz-zumix/go-gh-extension/pkg/logger"
)

type actionsAPI interface {
	listWorkflows(context.Context) ([]*github.Workflow, error)
	listRuns(context.Context, int64, int) ([]*github.WorkflowRun, error)
	getRun(context.Context, int64) (*github.WorkflowRun, error)
	getRunAttempt(context.Context, int64, int64) (*github.WorkflowRun, error)
	listJobs(context.Context, int64, int64) ([]*github.WorkflowJob, error)
	getJob(context.Context, int64) (*github.WorkflowJob, error)
	getLog(context.Context, int64) ([]byte, error)
	getStepLog(context.Context, int64, int64, int64) ([]byte, error)
	getRunLogArchive(context.Context, int64, int64) ([]byte, error)
}

type githubActionsAPI struct {
	client     *gh.GitHubClient
	repo       repository.Repository
	httpClient *http.Client
}

func (a *githubActionsAPI) listWorkflows(ctx context.Context) ([]*github.Workflow, error) {
	return a.client.ListWorkflows(ctx, a.repo.Owner, a.repo.Name)
}

func (a *githubActionsAPI) listRuns(ctx context.Context, workflowID int64, limit int) ([]*github.WorkflowRun, error) {
	return gh.ListWorkflowRunsByID(ctx, a.client, a.repo, workflowID, &gh.ListWorkflowRunsOptions{
		Status: "completed",
		Limit:  limit,
	})
}

func (a *githubActionsAPI) getRun(ctx context.Context, runID int64) (*github.WorkflowRun, error) {
	return gh.GetWorkflowRunByID(ctx, a.client, a.repo, runID)
}

func (a *githubActionsAPI) getRunAttempt(ctx context.Context, runID, attempt int64) (*github.WorkflowRun, error) {
	return gh.GetWorkflowRunAttempt(ctx, a.client, a.repo, runID, int(attempt), nil)
}

func (a *githubActionsAPI) listJobs(ctx context.Context, runID, attempt int64) ([]*github.WorkflowJob, error) {
	return gh.ListWorkflowJobsAttempt(ctx, a.client, a.repo, runID, attempt)
}

func (a *githubActionsAPI) getJob(ctx context.Context, jobID int64) (*github.WorkflowJob, error) {
	return gh.GetWorkflowJobByID(ctx, a.client, a.repo, jobID)
}

func (a *githubActionsAPI) getLog(ctx context.Context, jobID int64) ([]byte, error) {
	apiCtx, cancel := context.WithTimeout(ctx, gh.DefaultHTTPTimeout)
	defer cancel()
	location, err := gh.GetWorkflowJobLogsURL(apiCtx, a.client, a.repo, jobID, 1)
	if err != nil {
		return nil, newActionsRequestError("requesting the GitHub job log", err)
	}
	return downloadActionsLog(ctx, a.httpClient, location)
}

func (a *githubActionsAPI) getRunLogArchive(ctx context.Context, runID, attempt int64) ([]byte, error) {
	apiCtx, cancel := context.WithTimeout(ctx, gh.DefaultHTTPTimeout)
	defer cancel()
	location, err := gh.GetWorkflowRunAttemptLogsURL(apiCtx, a.client, a.repo, runID, int(attempt), 1)
	if err != nil {
		return nil, newActionsRequestError("requesting the GitHub run log archive", err)
	}
	return downloadActionsContent(ctx, a.httpClient, location, "run log archive", maxActionsArchiveBytes)
}

func (a *githubActionsAPI) getStepLog(ctx context.Context, jobID, stepNumber, limit int64) ([]byte, error) {
	apiCtx, cancel := context.WithTimeout(ctx, gh.DefaultHTTPTimeout)
	defer cancel()
	location, err := gh.GetWorkflowJobStepLogsURL(apiCtx, a.client, a.repo, jobID, stepNumber)
	if err != nil {
		return nil, newActionsRequestError("requesting the GitHub step log", err)
	}
	return downloadActionsContent(ctx, a.httpClient, location, "step log", limit)
}

// newActionsRequestError converts a GitHub API error into an actionsLogError
// without exposing the redirect URL, keeping the status and retry hints.
func newActionsRequestError(stage string, err error) *actionsLogError {
	if status := actionsGitHubStatus(err); status != 0 {
		return &actionsLogError{stage: stage, status: status, retryAfter: actionsRetryAfter(err)}
	}
	return &actionsLogError{stage: stage, cause: safeActionsNetworkError(err), transient: actionsTransientNetworkError(err)}
}

type actionsLogError struct {
	stage  string
	status int
	cause  error
	// transient marks network failures that may succeed when retried.
	transient  bool
	retryAfter time.Duration
}

func (e *actionsLogError) Error() string {
	if e.status != 0 {
		return fmt.Sprintf("%s: HTTP %d", e.stage, e.status)
	}
	return fmt.Sprintf("%s: %v", e.stage, e.cause)
}

func (e *actionsLogError) Unwrap() error {
	return e.cause
}

func actionsGitHubStatus(err error) int {
	var response *github.ErrorResponse
	if errors.As(err, &response) && response.Response != nil {
		return response.Response.StatusCode
	}
	var rate *github.RateLimitError
	if errors.As(err, &rate) && rate.Response != nil {
		return rate.Response.StatusCode
	}
	var abuse *github.AbuseRateLimitError
	if errors.As(err, &abuse) && abuse.Response != nil {
		return abuse.Response.StatusCode
	}
	return 0
}

// actionsFatalError reports authentication, permission, and rate-limit
// failures, which would make every later request fail as well.
func actionsFatalError(err error) bool {
	var rate *github.RateLimitError
	var abuse *github.AbuseRateLimitError
	if errors.As(err, &rate) || errors.As(err, &abuse) {
		return true
	}
	status := actionsGitHubStatus(err)
	var logErr *actionsLogError
	if errors.As(err, &logErr) && logErr.status != 0 {
		status = logErr.status
	}
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
		return true
	}
	return false
}

func actionsLogUnavailable(err error) bool {
	var logErr *actionsLogError
	return errors.As(err, &logErr) && (logErr.status == http.StatusNotFound || logErr.status == http.StatusGone)
}

func safeActionsNetworkError(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	var networkErr net.Error
	if errors.As(err, &networkErr) && networkErr.Timeout() {
		return fmt.Errorf("network request timed out")
	}
	return fmt.Errorf("network or redirect error")
}

var errActionsDownloadRedirect = errors.New("invalid or excessive download redirect")

func validActionsLogURL(u *url.URL) bool {
	return u != nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == ""
}

func downloadActionsLog(ctx context.Context, client *http.Client, location string) ([]byte, error) {
	return downloadActionsContent(ctx, client, location, "job log", 0)
}

func downloadActionsContent(ctx context.Context, client *http.Client, location, kind string, limit int64) (body []byte, err error) {
	downloadStage := "downloading the " + kind
	target, err := url.Parse(location)
	if err != nil || !validActionsLogURL(target) {
		return nil, &actionsLogError{stage: downloadStage, cause: fmt.Errorf("invalid HTTPS download URL")}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, &actionsLogError{stage: downloadStage, cause: fmt.Errorf("invalid download request")}
	}
	httpClient := *client
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 || !validActionsLogURL(req.URL) {
			return errActionsDownloadRedirect
		}
		req.Header.Del("Authorization")
		req.Header.Del("Proxy-Authorization")
		req.Header.Del("Referer")
		return nil
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, &actionsLogError{stage: downloadStage, cause: safeActionsNetworkError(err),
			transient: !errors.Is(err, errActionsDownloadRedirect) && actionsTransientNetworkError(err)}
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			safeErr := safeActionsNetworkError(closeErr)
			logger.Warn("failed to close actions download response body", "error", safeErr)
			body = nil
			err = errors.Join(err, &actionsLogError{
				stage: "closing the " + kind, cause: safeErr, transient: actionsTransientNetworkError(closeErr),
			})
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, &actionsLogError{stage: downloadStage, status: resp.StatusCode, retryAfter: actionsRetryAfterHeader(resp.Header)}
	}
	reader := io.Reader(resp.Body)
	if limit > 0 {
		reader = io.LimitReader(reader, limit+1)
	}
	body, err = io.ReadAll(reader)
	if err != nil {
		return nil, &actionsLogError{stage: "reading the " + kind, cause: safeActionsNetworkError(err), transient: actionsTransientNetworkError(err)}
	}
	if limit > 0 && int64(len(body)) > limit {
		return nil, &actionsLogError{stage: downloadStage, cause: fmt.Errorf("content exceeds the %d-byte limit", limit)}
	}
	return body, nil
}

func normalizeActionsLog(content string) string {
	content = strings.TrimPrefix(content, "\xef\xbb\xbf")
	var output strings.Builder
	output.Grow(len(content))
	for len(content) > 0 {
		line, rest, hasNewline := strings.Cut(content, "\n")
		prefix, text, hasSpace := strings.Cut(line, " ")
		if hasSpace && len(prefix) >= len("2006-01-02T15:04:05Z") && len(prefix) <= 35 {
			if _, err := time.Parse(time.RFC3339Nano, prefix); err == nil {
				line = text
			}
		}
		output.WriteString(line)
		if hasNewline {
			output.WriteByte('\n')
		}
		content = rest
	}
	return output.String()
}

type actionsRateLimiter struct {
	limit  int
	starts []time.Time
	now    func() time.Time
	wait   func(context.Context, time.Duration) error
	onWait func(time.Duration) error
}

func newActionsRateLimiter(limit int, onWait func(time.Duration) error) *actionsRateLimiter {
	return &actionsRateLimiter{limit: limit, now: time.Now, wait: waitForActionsLimit, onWait: onWait}
}

func waitForActionsLimit(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (l *actionsRateLimiter) acquire(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if l.limit == 0 {
			return nil
		}
		now := l.now()
		cutoff := now.Add(-time.Hour)
		expired := 0
		for expired < len(l.starts) && !l.starts[expired].After(cutoff) {
			expired++
		}
		l.starts = l.starts[expired:]
		if len(l.starts) < l.limit {
			l.starts = append(l.starts, now)
			return nil
		}
		delay := l.starts[0].Add(time.Hour).Sub(now)
		if l.onWait != nil {
			if err := l.onWait(delay); err != nil {
				return err
			}
		}
		if err := l.wait(ctx, delay); err != nil {
			return err
		}
	}
}
