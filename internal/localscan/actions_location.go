package localscan

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/cli/go-gh/v2/pkg/repository"
	"github.com/google/go-github/v93/github"
)

const (
	maxActionsArchiveBytes         int64 = 256 << 20
	maxActionsArchiveEntryBytes    int64 = 128 << 20
	maxActionsArchiveExpandedBytes int64 = 1 << 30
	maxActionsArchiveSearchBytes   int64 = 1 << 30
	maxActionsArchiveEntries             = 100000
)

type actionsLocationJob struct {
	job                      *github.WorkflowJob
	logSize                  int64
	logHash                  [sha256.Size]byte
	firstFinding, endFinding int
}

type actionsArchiveStep struct {
	number int64
	file   *zip.File
}

type actionsLogArchive struct {
	jobs      map[string][]*zip.File
	jobFiles  []*zip.File
	steps     map[string][]actionsArchiveStep
	hashes    map[*zip.File][sha256.Size]byte
	remaining int64
}

type actionsStepRange struct {
	number              int64
	firstLine, lastLine int
}

type actionsArchiveContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r actionsArchiveContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.reader.Read(p)
	if ctxErr := r.ctx.Err(); ctxErr != nil {
		return n, ctxErr
	}
	return n, err
}

func (r *actionsRunner) queueLocation(candidate actionsJob, content []byte, first, end int) {
	if r.locations == nil {
		r.locations = make(map[actionsAttempt][]actionsLocationJob)
	}
	key := actionsAttempt{run: candidate.run.GetID(), attempt: candidate.attempt}
	if _, exists := r.locations[key]; !exists {
		r.locationRuns = append(r.locationRuns, key)
	}
	r.locations[key] = append(r.locations[key], actionsLocationJob{
		job:          candidate.job,
		logSize:      int64(len(content)),
		logHash:      sha256.Sum256(content),
		firstFinding: first,
		endFinding:   end,
	})
}

func (r *actionsRunner) resolveLocations(ctx context.Context) error {
	for _, key := range r.locationRuns {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := r.resolveAttemptLocations(ctx, key); err != nil {
			var stopped actionsStoppedError
			if errors.As(err, &stopped) {
				return stopped.err
			}
			if err := r.continueAfter(ctx, err); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

// actionsStoppedError carries a job-level error that already stopped location
// resolution, so it is not recorded again as a recoverable attempt error.
type actionsStoppedError struct{ err error }

func (e actionsStoppedError) Error() string { return e.err.Error() }
func (e actionsStoppedError) Unwrap() error { return e.err }

type actionsLogIdentity struct {
	size int64
	hash [sha256.Size]byte
}

func (r *actionsRunner) resolveAttemptLocations(ctx context.Context, key actionsAttempt) error {
	content, err := r.api.getRunLogArchive(ctx, key.run, key.attempt)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if actionsLogUnavailable(err) {
		r.result.Warnings = append(r.result.Warnings, fmt.Sprintf(
			"log archive for run %d attempt %d is unavailable; finding location URLs could not be resolved", key.run, key.attempt))
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to get log archive for run %d attempt %d: %w", key.run, key.attempt, err)
	}
	archive, err := newActionsLogArchive(content)
	if err != nil {
		return fmt.Errorf("failed to read log archive for run %d attempt %d: %w", key.run, key.attempt, err)
	}
	identities := make(map[actionsLogIdentity]int)
	for _, target := range r.locations[key] {
		identities[actionsLogIdentity{target.logSize, target.logHash}]++
	}
	for _, target := range r.locations[key] {
		if err := ctx.Err(); err != nil {
			return err
		}
		unique := identities[actionsLogIdentity{target.logSize, target.logHash}] == 1
		if err := r.continueAfter(ctx, r.resolveJobLocations(ctx, key, archive, target, unique)); err != nil {
			return actionsStoppedError{err}
		}
	}
	return nil
}

func (r *actionsRunner) resolveJobLocations(ctx context.Context, key actionsAttempt, archive *actionsLogArchive, target actionsLocationJob, unique bool) error {
	job, numbers, err := r.locationJobMetadata(ctx, key, target.job)
	if err != nil {
		return err
	}
	var ranges []actionsStepRange
	if len(numbers) > 0 && job.GetName() != "" && unique {
		ranges, err = archive.jobRanges(ctx, target, job.GetName(), numbers)
		if err != nil {
			return fmt.Errorf("failed to resolve locations for job %d: %w", job.GetID(), err)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	missing, err := r.applyLocationRanges(key, target, ranges)
	if err != nil {
		return err
	}
	if missing > 0 && len(numbers) > 0 {
		log, err := archive.selectedJobLog(ctx, target, job.GetName())
		if err != nil {
			return fmt.Errorf("failed to read log for job %d: %w", job.GetID(), err)
		}
		if log != nil {
			ranges, err = r.apiStepRanges(ctx, job, log)
			if err != nil {
				return fmt.Errorf("failed to resolve step logs for job %d: %w", job.GetID(), err)
			}
			missing, err = r.applyLocationRanges(key, target, ranges)
			if err != nil {
				return err
			}
		}
	}
	if missing > 0 {
		r.result.Warnings = append(r.result.Warnings, fmt.Sprintf(
			"could not verify step locations for %d finding(s) in job %d; only the job URL is available", missing, job.GetID()))
	}
	return nil
}

func (r *actionsRunner) applyLocationRanges(key actionsAttempt, target actionsLocationJob, ranges []actionsStepRange) (int, error) {
	missing := 0
	for index := target.firstFinding; index < target.endFinding; index++ {
		finding := &r.result.Findings[index]
		if finding.LocationURL != "" {
			continue
		}
		position, ok := actionsStepForLine(ranges, finding.StartLine)
		if !ok {
			missing++
			continue
		}
		location, err := actionsJobLocationURL(r.repo, key.run, target.job.GetID(), position.number, finding.StartLine-position.firstLine+1)
		if err != nil {
			return missing, fmt.Errorf("failed to build location URL for job %d: %w", target.job.GetID(), err)
		}
		finding.LocationURL = r.scanner.redactMetadata(location)
	}
	return missing, nil
}

func (a *actionsLogArchive) selectedJobLog(ctx context.Context, target actionsLocationJob, name string) ([]byte, error) {
	files := a.jobs[actionsArchiveJobName(name)]
	if len(files) != 1 || files[0].UncompressedSize64 != uint64(target.logSize) {
		return nil, nil
	}
	content, err := a.read(ctx, files[0])
	if err != nil {
		return nil, err
	}
	if sha256.Sum256(content) != target.logHash {
		return nil, nil
	}
	return content, nil
}

func (r *actionsRunner) locationJobMetadata(ctx context.Context, key actionsAttempt, job *github.WorkflowJob) (*github.WorkflowJob, map[int64]bool, error) {
	numbers := actionsStepNumbers(job)
	if len(numbers) > 0 && job.GetName() != "" {
		return job, numbers, nil
	}
	fetched, err := r.api.getJob(ctx, job.GetID())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get step metadata for job %d: %w", job.GetID(), err)
	}
	if fetched == nil || fetched.GetID() != job.GetID() || fetched.GetRunID() != key.run ||
		fetched.RunAttempt != nil && fetched.GetRunAttempt() != key.attempt {
		return nil, nil, fmt.Errorf("job %d has inconsistent step metadata", job.GetID())
	}
	return fetched, actionsStepNumbers(fetched), nil
}

func actionsStepNumbers(job *github.WorkflowJob) map[int64]bool {
	if job == nil || len(job.Steps) == 0 {
		return nil
	}
	numbers := make(map[int64]bool, len(job.Steps))
	for _, step := range job.Steps {
		if step == nil || step.GetNumber() <= 0 || numbers[step.GetNumber()] {
			return nil
		}
		numbers[step.GetNumber()] = true
	}
	return numbers
}

func actionsJobLocationURL(repo repository.Repository, runID, jobID, step int64, line int) (string, error) {
	u, err := actionsJobURL(repo, runID, jobID)
	if err != nil || step <= 0 || line <= 0 {
		return "", fmt.Errorf("invalid repository or log location")
	}
	u.Fragment = fmt.Sprintf("step:%d:%d", step, line)
	return u.String(), nil
}

func actionsJobURL(repo repository.Repository, runID, jobID int64) (*url.URL, error) {
	host, err := canonicalActionsHostString(repo.Host)
	if err != nil || !validActionsRepositoryPart(repo.Owner) || !validActionsRepositoryPart(repo.Name) ||
		runID <= 0 || jobID <= 0 {
		return nil, fmt.Errorf("invalid repository or job")
	}
	return &url.URL{
		Scheme: "https",
		Host:   host,
		Path:   fmt.Sprintf("/%s/%s/actions/runs/%d/job/%d", repo.Owner, repo.Name, runID, jobID),
	}, nil
}

func newActionsLogArchive(content []byte) (*actionsLogArchive, error) {
	if err := validateActionsArchiveSize(int64(len(content))); err != nil {
		return nil, err
	}
	reader, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return nil, fmt.Errorf("invalid ZIP archive")
	}
	if err := validateActionsArchiveEntries(len(reader.File)); err != nil {
		return nil, err
	}
	archive := &actionsLogArchive{
		jobs:      make(map[string][]*zip.File),
		steps:     make(map[string][]actionsArchiveStep),
		hashes:    make(map[*zip.File][sha256.Size]byte),
		remaining: maxActionsArchiveExpandedBytes,
	}
	for _, file := range reader.File {
		if file.FileInfo().IsDir() || strings.Contains(file.Name, `\`) {
			continue
		}
		parts := strings.Split(file.Name, "/")
		switch len(parts) {
		case 1:
			if name, ok := actionsArchiveJobFilename(parts[0]); ok {
				archive.jobs[name] = append(archive.jobs[name], file)
				archive.jobFiles = append(archive.jobFiles, file)
			}
		case 2:
			if parts[0] == "" || parts[0] == "." || parts[0] == ".." {
				continue
			}
			if number, ok := actionsArchiveStepFilename(parts[1]); ok {
				archive.steps[parts[0]] = append(archive.steps[parts[0]], actionsArchiveStep{number: number, file: file})
			}
		}
	}
	return archive, nil
}

func validateActionsArchiveSize(size int64) error {
	if size > maxActionsArchiveBytes {
		return fmt.Errorf("archive exceeds the %d-byte limit", maxActionsArchiveBytes)
	}
	return nil
}

func validateActionsArchiveEntries(count int) error {
	if count > maxActionsArchiveEntries {
		return fmt.Errorf("archive exceeds the %d-entry limit", maxActionsArchiveEntries)
	}
	return nil
}

func validateActionsArchiveEntry(size uint64, remaining int64) error {
	if size > uint64(maxActionsArchiveEntryBytes) {
		return fmt.Errorf("archive entry exceeds the %d-byte limit", maxActionsArchiveEntryBytes)
	}
	if remaining < 0 || size > uint64(remaining) {
		return fmt.Errorf("archive contents exceed the %d-byte processing limit", maxActionsArchiveExpandedBytes)
	}
	return nil
}

func actionsArchiveJobFilename(name string) (string, bool) {
	number, rest, found := strings.Cut(name, "_")
	if !found || !strings.HasSuffix(rest, ".txt") {
		return "", false
	}
	if _, err := strconv.ParseInt(number, 10, 64); err != nil {
		return "", false
	}
	job := strings.TrimSuffix(rest, ".txt")
	return job, job != ""
}

func actionsArchiveStepFilename(name string) (int64, bool) {
	number, rest, found := strings.Cut(name, "_")
	if !found || !strings.HasSuffix(rest, ".txt") {
		return 0, false
	}
	value, err := strconv.ParseInt(number, 10, 64)
	return value, err == nil && value > 0
}

func actionsArchiveJobName(name string) string {
	name = strings.NewReplacer("/", "", ":", "").Replace(name)
	// GitHub truncates archive job names in UTF-16 code units.
	units := utf16.Encode([]rune(name))
	if len(units) > 90 {
		name = string(utf16.Decode(units[:90]))
	}
	return strings.TrimSpace(name)
}

func (a *actionsLogArchive) read(ctx context.Context, file *zip.File) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateActionsArchiveEntry(file.UncompressedSize64, a.remaining); err != nil {
		return nil, err
	}
	reader, err := file.Open()
	if err != nil {
		return nil, fmt.Errorf("cannot open archive entry: %w", err)
	}
	limited := io.LimitReader(reader, int64(file.UncompressedSize64)+1)
	content, readErr := io.ReadAll(actionsArchiveContextReader{ctx: ctx, reader: limited})
	closeErr := reader.Close()
	if readErr != nil {
		return nil, fmt.Errorf("cannot read archive entry: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("cannot close archive entry: %w", closeErr)
	}
	if uint64(len(content)) != file.UncompressedSize64 {
		return nil, fmt.Errorf("archive entry size is inconsistent")
	}
	a.remaining -= int64(len(content))
	return content, nil
}

func (a *actionsLogArchive) jobRanges(ctx context.Context, target actionsLocationJob, name string, numbers map[int64]bool) ([]actionsStepRange, error) {
	name = actionsArchiveJobName(name)
	steps := sortedActionsArchiveSteps(a.steps[name])
	if len(steps) == 0 || !uniqueActionsArchiveSteps(steps) {
		return nil, nil
	}
	files := a.jobs[name]
	if len(files) > 1 {
		return nil, nil
	}
	var log []byte
	var ranges []actionsStepRange
	var err error
	if len(files) == 1 {
		if files[0].UncompressedSize64 != uint64(target.logSize) {
			return nil, nil
		}
		log, err = a.read(ctx, files[0])
		if err != nil {
			return nil, err
		}
		if sha256.Sum256(log) != target.logHash {
			return nil, nil
		}
		a.hashes[files[0]] = target.logHash
	} else {
		var ok bool
		var hash [sha256.Size]byte
		hash, ranges, ok, err = a.stepOnlyIdentity(ctx, steps, target.logSize, numbers)
		if err != nil || !ok {
			return nil, err
		}
		if hash != target.logHash {
			return nil, nil
		}
	}
	for _, file := range a.jobFiles {
		if (len(files) == 1 && file == files[0]) || file.UncompressedSize64 != uint64(target.logSize) {
			continue
		}
		hash, found := a.hashes[file]
		if !found {
			other, err := a.read(ctx, file)
			if err != nil {
				return nil, err
			}
			hash = sha256.Sum256(other)
			a.hashes[file] = hash
		}
		if hash == target.logHash {
			return nil, nil
		}
	}
	var otherNames []string
	for other := range a.steps {
		if other != name {
			otherNames = append(otherNames, other)
		}
	}
	slices.Sort(otherNames)
	for _, other := range otherNames {
		otherSteps := sortedActionsArchiveSteps(a.steps[other])
		if !uniqueActionsArchiveSteps(otherSteps) {
			return nil, nil
		}
		if len(a.jobs[other]) > 0 {
			continue
		}
		hash, _, ok, err := a.stepOnlyIdentity(ctx, otherSteps, target.logSize, nil)
		if err != nil {
			return nil, err
		}
		if ok && hash == target.logHash {
			return nil, nil
		}
	}
	if len(files) == 0 {
		return ranges, nil
	}
	return a.stepRanges(ctx, log, steps, numbers)
}

func sortedActionsArchiveSteps(steps []actionsArchiveStep) []actionsArchiveStep {
	steps = slices.Clone(steps)
	slices.SortFunc(steps, func(left, right actionsArchiveStep) int {
		switch {
		case left.number < right.number:
			return -1
		case left.number > right.number:
			return 1
		default:
			return 0
		}
	})
	return steps
}

func uniqueActionsArchiveSteps(steps []actionsArchiveStep) bool {
	for i := 1; i < len(steps); i++ {
		if steps[i-1].number == steps[i].number {
			return false
		}
	}
	return true
}

func (a *actionsLogArchive) stepOnlyIdentity(ctx context.Context, steps []actionsArchiveStep, size int64, numbers map[int64]bool) ([sha256.Size]byte, []actionsStepRange, bool, error) {
	var digest [sha256.Size]byte
	if size < 0 {
		return digest, nil, false, nil
	}
	var total uint64
	for _, step := range steps {
		if step.file.UncompressedSize64 > uint64(size)-total {
			return digest, nil, false, nil
		}
		total += step.file.UncompressedSize64
	}
	if total != uint64(size) {
		return digest, nil, false, nil
	}
	hash := sha256.New()
	var ranges []actionsStepRange
	var offset int64
	firstLine := 1
	aligned := true
	for _, step := range steps {
		content, err := a.read(ctx, step.file)
		if err != nil {
			return digest, nil, false, err
		}
		_, _ = hash.Write(content)
		if len(content) == 0 {
			continue
		}
		end := offset + int64(len(content))
		endsOnBoundary := end == size || content[len(content)-1] == '\n'
		if numbers[step.number] && aligned && endsOnBoundary && !actionsBareCarriageReturn(content) {
			ranges = append(ranges, actionsStepRange{
				number: step.number, firstLine: firstLine, lastLine: firstLine + actionsLineCount(content) - 1,
			})
		}
		offset = end
		firstLine += bytes.Count(content, []byte{'\n'})
		aligned = content[len(content)-1] == '\n'
	}
	if err := ctx.Err(); err != nil {
		return digest, nil, false, err
	}
	copy(digest[:], hash.Sum(nil))
	return digest, ranges, true, nil
}

func (a *actionsLogArchive) stepRanges(ctx context.Context, log []byte, steps []actionsArchiveStep, numbers map[int64]bool) ([]actionsStepRange, error) {
	var ranges []actionsStepRange
	offset, firstLine := 0, 1
	complete := true
	for _, step := range steps {
		if step.file.UncompressedSize64 > uint64(len(log)-offset) {
			complete = false
			break
		}
		content, err := a.read(ctx, step.file)
		if err != nil {
			return nil, err
		}
		if len(content) == 0 {
			continue
		}
		if !actionsStepAt(log, content, offset) {
			complete = false
			break
		}
		if numbers[step.number] && !actionsBareCarriageReturn(content) {
			ranges = append(ranges, actionsStepRange{
				number: step.number, firstLine: firstLine, lastLine: firstLine + actionsLineCount(content) - 1,
			})
		}
		offset += len(content)
		firstLine += bytes.Count(content, []byte{'\n'})
	}
	if complete && offset == len(log) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return ranges, nil
	}

	ranges = nil
	var lastEnd int
	remainingSearch := maxActionsArchiveSearchBytes
	for _, step := range steps {
		if step.file.UncompressedSize64 == 0 || step.file.UncompressedSize64 > uint64(len(log)) {
			continue
		}
		if err := reserveActionsArchiveSearch(int64(len(log)), &remainingSearch); err != nil {
			return nil, err
		}
		content, err := a.read(ctx, step.file)
		if err != nil {
			return nil, err
		}
		start := bytes.Index(log, content)
		if start < 0 || bytes.Contains(log[start+1:], content) || !actionsStepAt(log, content, start) {
			continue
		}
		end := start + len(content)
		if start < lastEnd {
			return nil, nil
		}
		lastEnd = end
		if numbers[step.number] && !actionsBareCarriageReturn(content) {
			first := 1 + bytes.Count(log[:start], []byte{'\n'})
			ranges = append(ranges, actionsStepRange{
				number: step.number, firstLine: first, lastLine: first + actionsLineCount(content) - 1,
			})
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return ranges, nil
}

func reserveActionsArchiveSearch(size int64, remaining *int64) error {
	if size > *remaining/2 {
		return fmt.Errorf("archive matching exceeds the %d-byte search limit", maxActionsArchiveSearchBytes)
	}
	*remaining -= 2 * size
	return nil
}

func actionsStepAt(log, content []byte, offset int) bool {
	end := offset + len(content)
	return len(content) > 0 && offset >= 0 && end <= len(log) &&
		(offset == 0 || log[offset-1] == '\n') &&
		(end == len(log) || content[len(content)-1] == '\n') &&
		bytes.Equal(log[offset:end], content)
}

func actionsLineCount(content []byte) int {
	lines := bytes.Count(content, []byte{'\n'})
	if len(content) > 0 && content[len(content)-1] != '\n' {
		lines++
	}
	return lines
}

func actionsBareCarriageReturn(content []byte) bool {
	for index, b := range content {
		if b == '\r' && (index+1 == len(content) || content[index+1] != '\n') {
			return true
		}
	}
	return false
}

func actionsStepForLine(ranges []actionsStepRange, line int) (actionsStepRange, bool) {
	var found actionsStepRange
	matches := 0
	for _, candidate := range ranges {
		if line >= candidate.firstLine && line <= candidate.lastLine {
			found = candidate
			matches++
		}
	}
	return found, matches == 1
}
