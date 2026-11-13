package localscan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func testActionsOptions() ActionsScanOptions {
	return ActionsScanOptions{RunsPerWorkflow: 1, MaxJobsPerHour: 100}
}

func TestActionsScanOptionsValidation(t *testing.T) {
	tests := []struct {
		name   string
		change func(*ActionsScanOptions)
		want   string
	}{
		{"defaults", func(*ActionsScanOptions) {}, ""},
		{"unlimited", func(o *ActionsScanOptions) { o.MaxJobsPerHour = 0 }, ""},
		{"runs", func(o *ActionsScanOptions) { o.Runs = []int64{12, 34} }, ""},
		{"negative rate", func(o *ActionsScanOptions) { o.MaxJobsPerHour = -1 }, "--max-jobs-per-hour"},
		{"zero history", func(o *ActionsScanOptions) { o.RunsPerWorkflow = 0 }, "--runs-per-workflow"},
		{"negative history", func(o *ActionsScanOptions) { o.RunsPerWorkflow = -1 }, "--runs-per-workflow"},
		{"zero run", func(o *ActionsScanOptions) { o.Runs = []int64{0} }, "--run"},
		{"negative run", func(o *ActionsScanOptions) { o.Runs = []int64{-1} }, "--run"},
		{"run and explicit history", func(o *ActionsScanOptions) { o.Runs, o.RunsPerWorkflowSet = []int64{12}, true }, "--run"},
		{"in progress without run", func(o *ActionsScanOptions) { o.AllowInProgress = true }, "--allow-in-progress"},
		{"in progress with run", func(o *ActionsScanOptions) { o.AllowInProgress, o.Runs = true, []int64{12} }, ""},
		{"empty workflow", func(o *ActionsScanOptions) { o.Workflows = []string{" \t"} }, "--workflow"},
		{"negative workflow ID", func(o *ActionsScanOptions) { o.Workflows = []string{"-10"} }, "--workflow"},
		{"empty job", func(o *ActionsScanOptions) { o.Jobs = []string{""} }, "--job"},
		{"zero job ID", func(o *ActionsScanOptions) { o.Jobs = []string{"0"} }, "--job"},
		{"overflow job ID", func(o *ActionsScanOptions) { o.Jobs = []string{"99999999999999999999999999"} }, "--job"},
		{"job name with comma", func(o *ActionsScanOptions) { o.Jobs = []string{"build, test"} }, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := testActionsOptions()
			tt.change(&opts)
			err := opts.Validate()
			if tt.want == "" && err != nil {
				t.Fatal(err)
			}
			if tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
				t.Fatalf("got %v, want an error containing %q", err, tt.want)
			}
		})
	}
}

func TestActionsRateLimiterRollingHour(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := start
	var waits []time.Duration
	limiter := newActionsRateLimiter(2, nil)
	limiter.now = func() time.Time { return now }
	limiter.wait = func(_ context.Context, delay time.Duration) error {
		waits = append(waits, delay)
		now = now.Add(delay)
		return nil
	}
	var starts []time.Time
	acquire := func() {
		t.Helper()
		if err := limiter.acquire(t.Context()); err != nil {
			t.Fatal(err)
		}
		starts = append(starts, now)
	}
	acquire()
	now = start.Add(10 * time.Minute)
	acquire()
	now = start.Add(59 * time.Minute)
	acquire()
	acquire()
	want := []time.Time{start, start.Add(10 * time.Minute), start.Add(time.Hour), start.Add(70 * time.Minute)}
	if !reflect.DeepEqual(starts, want) || !reflect.DeepEqual(waits, []time.Duration{time.Minute, 10 * time.Minute}) {
		t.Fatalf("starts = %v, waits = %v", starts, waits)
	}
	for _, end := range starts {
		count := 0
		for _, candidate := range starts {
			if candidate.After(end.Add(-time.Hour)) && !candidate.After(end) {
				count++
			}
		}
		if count > 2 {
			t.Fatalf("%d starts in the rolling hour ending %v", count, end)
		}
	}
}

func TestActionsRateLimiterCancellationAndUnlimited(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	limiter := newActionsRateLimiter(1, nil)
	limiter.now = func() time.Time { return now }
	if err := limiter.acquire(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	limiter.wait = func(ctx context.Context, _ time.Duration) error {
		cancel()
		return ctx.Err()
	}
	if err := limiter.acquire(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want cancellation", err)
	}
	if len(limiter.starts) != 1 {
		t.Fatalf("cancelled wait reserved another start: %v", limiter.starts)
	}
	unlimited := newActionsRateLimiter(0, nil)
	unlimited.now = func() time.Time { t.Fatal("unlimited limiter read the clock"); return now }
	if err := unlimited.acquire(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := unlimited.acquire(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled unlimited limiter returned %v", err)
	}
}

func TestActionsRateLimiterPropagatesProgressError(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	limiter := newActionsRateLimiter(1, func(time.Duration) error { return io.ErrClosedPipe })
	limiter.now = func() time.Time { return now }
	limiter.wait = func(context.Context, time.Duration) error {
		t.Fatal("wait was called after progress output failed")
		return nil
	}
	if err := limiter.acquire(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := limiter.acquire(t.Context()); !errors.Is(err, io.ErrClosedPipe) || len(limiter.starts) != 1 {
		t.Fatalf("progress error = %v, starts = %v", err, limiter.starts)
	}
}

func TestNormalizeActionsLogPreservesLinesAndMultilineMatches(t *testing.T) {
	prefix := "2026-01-02T03:04:05.1234567Z "
	content := prefix + "ordinary text\n" +
		prefix + "-----BEGIN RSA PRIVATE KEY-----\n" +
		prefix + strings.Repeat("A", 48) + "\n" +
		"not-a-timestamp unchanged\n" +
		prefix + "fixture-start\n" +
		prefix + "fixture-end\n"
	normalized := normalizeActionsLog(content)
	if strings.Count(content, "\n") != strings.Count(normalized, "\n") {
		t.Fatal("normalization changed the number of lines")
	}
	if strings.Contains(normalized, prefix) || !strings.Contains(normalized, "not-a-timestamp unchanged\n") {
		t.Fatalf("unexpected normalized log: %q", normalized)
	}
	scanner, err := NewScanner(&Config{Patterns: []ConfigPattern{{ID: "multiline", Regex: `fixture-start\nfixture-end`}}}, false)
	if err != nil {
		t.Fatal(err)
	}
	findings := scanner.ScanFragment(Fragment{Content: normalized})
	lines := make(map[string]int)
	for _, finding := range findings {
		lines[finding.PatternID] = finding.StartLine
	}
	if lines["rsa_private_key"] != 2 || lines["multiline"] != 5 {
		t.Fatalf("findings have incorrect multiline locations: %v", lines)
	}
}

func TestDownloadActionsLogAndStatusClassification(t *testing.T) {
	var authorized []string
	var referrers []string
	var mu sync.Mutex
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		authorized = append(authorized, r.Header.Get("Authorization"))
		referrers = append(referrers, r.Header.Get("Referer"))
		mu.Unlock()
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/log?signature=synthetic-value", http.StatusFound)
		case "/log":
			fmt.Fprint(w, "example log")
		case "/missing":
			w.WriteHeader(http.StatusNotFound)
		case "/gone":
			w.WriteHeader(http.StatusGone)
		case "/unauthorized":
			w.WriteHeader(http.StatusUnauthorized)
		case "/forbidden":
			w.WriteHeader(http.StatusForbidden)
		case "/limited":
			w.WriteHeader(http.StatusTooManyRequests)
		case "/unsafe":
			http.Redirect(w, r, "http://example.invalid/log?signature=synthetic-value", http.StatusFound)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()
	content, err := downloadActionsLog(t.Context(), server.Client(), server.URL+"/redirect?signature=synthetic-value")
	if err != nil || string(content) != "example log" {
		t.Fatalf("content = %q, err = %v", content, err)
	}
	mu.Lock()
	for _, value := range authorized {
		if value != "" {
			mu.Unlock()
			t.Fatalf("storage request received Authorization: %q", value)
		}
	}
	for _, value := range referrers {
		if value != "" {
			mu.Unlock()
			t.Fatalf("signed URL was sent as a redirect referrer: %q", value)
		}
	}
	mu.Unlock()
	for _, tt := range []struct {
		path        string
		unavailable bool
		status      string
	}{
		{"/missing", true, "404"},
		{"/gone", true, "410"},
		{"/unauthorized", false, "401"},
		{"/forbidden", false, "403"},
		{"/limited", false, "429"},
		{"/error", false, "500"},
	} {
		t.Run(tt.path, func(t *testing.T) {
			_, err := downloadActionsLog(t.Context(), server.Client(), server.URL+tt.path+"?signature=synthetic-value")
			if err == nil || actionsLogUnavailable(err) != tt.unavailable || !strings.Contains(err.Error(), tt.status) {
				t.Fatalf("unexpected status classification: %v", err)
			}
			if strings.Contains(err.Error(), "signature") || strings.Contains(err.Error(), server.URL) {
				t.Fatalf("download URL leaked in error: %v", err)
			}
		})
	}
	_, err = downloadActionsLog(t.Context(), server.Client(), server.URL+"/unsafe?signature=synthetic-value")
	if err == nil || strings.Contains(err.Error(), "signature") || strings.Contains(err.Error(), server.URL) {
		t.Fatalf("unsafe redirect did not produce a sanitized error: %v", err)
	}
	_, err = downloadActionsLog(t.Context(), server.Client(), "http://example.invalid/log?signature=synthetic-value")
	if err == nil || strings.Contains(err.Error(), "signature") {
		t.Fatalf("HTTP URL was not rejected safely: %v", err)
	}
}

type actionsErrorTransport struct{}

func (actionsErrorTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("synthetic-secret-in-network-error")
}

func TestDownloadActionsLogSanitizesNetworkErrors(t *testing.T) {
	client := &http.Client{Transport: actionsErrorTransport{}}
	_, err := downloadActionsLog(t.Context(), client, "https://example.invalid/log?signature=synthetic-value")
	if err == nil || strings.Contains(err.Error(), "synthetic") || strings.Contains(err.Error(), "example.invalid") {
		t.Fatalf("network error leaked a sensitive URL or cause: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = downloadActionsLog(ctx, &http.Client{}, "https://example.invalid/log?signature=synthetic-value")
	if !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "signature") {
		t.Fatalf("cancellation was not preserved safely: %v", err)
	}
}

func TestDownloadActionsArchiveLimit(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/at-limit" {
			fmt.Fprint(w, "12345678")
			return
		}
		fmt.Fprint(w, "123456789")
	}))
	defer server.Close()
	content, err := downloadActionsContent(t.Context(), server.Client(), server.URL+"/at-limit", "run log archive", 8)
	if err != nil || string(content) != "12345678" {
		t.Fatalf("content = %q, err = %v", content, err)
	}
	_, err = downloadActionsContent(t.Context(), server.Client(), server.URL+"/above-limit?signature=synthetic-value", "run log archive", 8)
	if err == nil || !strings.Contains(err.Error(), "8-byte limit") || strings.Contains(err.Error(), "signature") {
		t.Fatalf("unexpected limit error: %v", err)
	}
}
