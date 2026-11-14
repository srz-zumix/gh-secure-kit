package localscan

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/edsrzf/mmap-go"
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
	streamLog(context.Context, int64, func(io.Reader) error) error
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

func (a *githubActionsAPI) streamLog(ctx context.Context, jobID int64, consume func(io.Reader) error) error {
	apiCtx, cancel := context.WithTimeout(ctx, gh.DefaultHTTPTimeout)
	defer cancel()
	location, err := gh.GetWorkflowJobLogsURL(apiCtx, a.client, a.repo, jobID, 1)
	if err != nil {
		return newActionsRequestError("requesting the GitHub job log", err)
	}
	return downloadActionsContentStream(ctx, a.httpClient, location, "job log", 0, consume)
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
	err = downloadActionsContentStream(ctx, client, location, kind, limit, func(reader io.Reader) error {
		body, err = io.ReadAll(reader)
		return err
	})
	if err != nil {
		return nil, err
	}
	return body, nil
}

type actionsReadTracker struct {
	reader io.Reader
	count  int64
	err    error
}

func (r *actionsReadTracker) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.count += int64(n)
	if err != nil && err != io.EOF {
		r.err = err
	}
	return n, err
}

func downloadActionsContentStream(ctx context.Context, client *http.Client, location, kind string, limit int64, consume func(io.Reader) error) (err error) {
	downloadStage := "downloading the " + kind
	target, err := url.Parse(location)
	if err != nil || !validActionsLogURL(target) {
		return &actionsLogError{stage: downloadStage, cause: fmt.Errorf("invalid HTTPS download URL")}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return &actionsLogError{stage: downloadStage, cause: fmt.Errorf("invalid download request")}
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
		return &actionsLogError{stage: downloadStage, cause: safeActionsNetworkError(err),
			transient: !errors.Is(err, errActionsDownloadRedirect) && actionsTransientNetworkError(err)}
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			safeErr := safeActionsNetworkError(closeErr)
			logger.Warn("failed to close actions download response body", "error", safeErr)
			err = errors.Join(err, &actionsLogError{
				stage: "closing the " + kind, cause: safeErr, transient: actionsTransientNetworkError(closeErr),
			})
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return &actionsLogError{stage: downloadStage, status: resp.StatusCode, retryAfter: actionsRetryAfterHeader(resp.Header)}
	}
	reader := io.Reader(resp.Body)
	if limit > 0 {
		reader = io.LimitReader(reader, limit+1)
	}
	tracked := &actionsReadTracker{reader: reader}
	if err := consume(tracked); err != nil {
		if tracked.err != nil {
			return &actionsLogError{stage: "reading the " + kind, cause: safeActionsNetworkError(tracked.err), transient: actionsTransientNetworkError(tracked.err)}
		}
		return err
	}
	if limit > 0 && tracked.count > limit {
		return &actionsLogError{stage: downloadStage, cause: fmt.Errorf("content exceeds the %d-byte limit", limit)}
	}
	return nil
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

type actionsLogStats struct {
	size int64
	hash [sha256.Size]byte
}

type actionsLogHashReader struct {
	reader io.Reader
	hash   hash.Hash
	size   int64
	err    error
}

func (r *actionsLogHashReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		_, _ = r.hash.Write(p[:n])
		r.size += int64(n)
	}
	if err != nil && err != io.EOF {
		r.err = err
	}
	return n, err
}

func scanActionsJobLog(reader io.Reader, fragment Fragment, scanner *Scanner) (stats actionsLogStats, findings []Finding, retErr error) {
	tempFile, err := os.CreateTemp("", "gh-secure-kit-actions-log-*")
	if err != nil {
		return actionsLogStats{}, nil, fmt.Errorf("failed to create temporary job log: %w", err)
	}
	name := tempFile.Name()
	defer func() {
		if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			retErr = errors.Join(retErr, fmt.Errorf("failed to remove temporary job log: %w", err))
			stats, findings = actionsLogStats{}, nil
		}
	}()
	tempOpen := true
	defer func() {
		if tempOpen {
			if err := tempFile.Close(); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("failed to close temporary job log: %w", err))
				stats, findings = actionsLogStats{}, nil
			}
		}
	}()

	hash := sha256.New()
	tracked := &actionsLogHashReader{reader: reader, hash: hash}
	if err := normalizeActionsLogTo(tempFile, tracked); err != nil {
		if tracked.err != nil {
			return actionsLogStats{}, nil, &actionsLogError{
				stage: "reading the job log", cause: safeActionsNetworkError(tracked.err), transient: actionsTransientNetworkError(tracked.err),
			}
		}
		return actionsLogStats{}, nil, fmt.Errorf("failed to write temporary job log: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		tempOpen = false
		return actionsLogStats{}, nil, fmt.Errorf("failed to close temporary job log: %w", err)
	}
	tempOpen = false
	stats = actionsLogStats{size: tracked.size}
	copy(stats.hash[:], hash.Sum(nil))
	info, err := os.Stat(name)
	if err != nil {
		return actionsLogStats{}, nil, fmt.Errorf("failed to inspect temporary job log: %w", err)
	}
	if info.Size() == 0 {
		return stats, nil, nil
	}

	logFile, err := os.Open(name)
	if err != nil {
		return actionsLogStats{}, nil, fmt.Errorf("failed to open temporary job log: %w", err)
	}
	defer func() {
		if err := logFile.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("failed to close temporary job log: %w", err))
			stats, findings = actionsLogStats{}, nil
		}
	}()
	mapped, err := mmap.Map(logFile, mmap.RDONLY, 0)
	if err != nil {
		return actionsLogStats{}, nil, fmt.Errorf("failed to map temporary job log: %w", err)
	}
	defer func() {
		if err := mapped.Unmap(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("failed to unmap temporary job log: %w", err))
			stats, findings = actionsLogStats{}, nil
		}
	}()

	findings = scanner.scanFragmentBytes(fragment, mapped)
	type findingKey struct {
		pattern string
		hash    [sha256.Size]byte
	}
	seen := make(map[findingKey]struct{}, len(findings))
	unique := findings[:0]
	for _, finding := range findings {
		key := findingKey{pattern: finding.PatternID, hash: finding.matchHash}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, finding)
	}
	return stats, unique, nil
}

func normalizeActionsLogTo(writer io.Writer, reader io.Reader) error {
	buffered := bufio.NewReader(reader)
	if prefix, _ := buffered.Peek(3); bytes.Equal(prefix, []byte{0xef, 0xbb, 0xbf}) {
		_, _ = buffered.Discard(3)
	}
	normalizer := &actionsLogNormalizer{writer: writer, lineStart: true}
	if _, err := io.Copy(normalizer, buffered); err != nil {
		return err
	}
	return normalizer.Flush()
}

type actionsLogNormalizer struct {
	writer      io.Writer
	prefix      []byte
	lineStart   bool
	passthrough bool
}

func (n *actionsLogNormalizer) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		if !n.lineStart {
			i := bytes.IndexByte(p, '\n')
			if i < 0 {
				if err := writeActionsLogBytes(n.writer, p); err != nil {
					return written, err
				}
				return written + len(p), nil
			}
			if err := writeActionsLogBytes(n.writer, p[:i+1]); err != nil {
				return written, err
			}
			written += i + 1
			p = p[i+1:]
			n.lineStart = true
			n.passthrough = false
			continue
		}

		if n.passthrough {
			i := bytes.IndexByte(p, '\n')
			if i < 0 {
				if err := writeActionsLogBytes(n.writer, p); err != nil {
					return written, err
				}
				return written + len(p), nil
			}
			if err := writeActionsLogBytes(n.writer, p[:i+1]); err != nil {
				return written, err
			}
			written += i + 1
			p = p[i+1:]
			n.lineStart = true
			n.passthrough = false
			continue
		}

		b := p[0]
		n.prefix = append(n.prefix, b)
		p = p[1:]
		written++
		switch {
		case b == '\n':
			if err := writeActionsLogBytes(n.writer, n.prefix); err != nil {
				return written, err
			}
			n.prefix = n.prefix[:0]
			n.lineStart = true
		case b == ' ':
			if !actionsTimestampPrefix(n.prefix[:len(n.prefix)-1]) {
				if err := writeActionsLogBytes(n.writer, n.prefix); err != nil {
					return written, err
				}
			}
			n.prefix = n.prefix[:0]
			n.lineStart = false
			n.passthrough = true
		case len(n.prefix) == 36:
			if err := writeActionsLogBytes(n.writer, n.prefix); err != nil {
				return written, err
			}
			n.prefix = n.prefix[:0]
			n.lineStart = false
			n.passthrough = true
		}
	}
	return written, nil
}

func (n *actionsLogNormalizer) Flush() error {
	if len(n.prefix) > 0 {
		if err := writeActionsLogBytes(n.writer, n.prefix); err != nil {
			return err
		}
		n.prefix = n.prefix[:0]
	}
	return nil
}

func actionsTimestampPrefix(prefix []byte) bool {
	if len(prefix) < len("2006-01-02T15:04:05Z") || len(prefix) > 35 {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, string(prefix))
	return err == nil
}

func writeActionsLogBytes(writer io.Writer, content []byte) error {
	for len(content) > 0 {
		n, err := writer.Write(content)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		content = content[n:]
	}
	return nil
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
