package localscan

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"
)

const (
	ValidityActive      = "active"
	ValidityInactive    = "inactive"
	ValidityUnknown     = "unknown"
	ValidityUnsupported = "unsupported"
)

func VerifyFindings(ctx context.Context, findings []Finding, githubHosts ...string) error {
	return verifyFindings(ctx, findings, &http.Client{Timeout: 10 * time.Second}, githubHosts...)
}

func verifyFindings(ctx context.Context, findings []Finding, client *http.Client, githubHosts ...string) error {
	defer func() {
		for index := range findings {
			findings[index].rawSecret = ""
			findings[index].verificationPattern = ""
		}
	}()
	if err := ValidateVerificationOptions(true, false, githubHosts...); err != nil {
		return err
	}
	host := ""
	if len(githubHosts) == 1 {
		host = githubHosts[0]
	}
	githubEndpoint, err := githubVerificationURL(host)
	if err != nil {
		return err
	}
	safeClient := *client
	safeClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if safeClient.Timeout <= 0 {
		safeClient.Timeout = 10 * time.Second
	}
	type verificationKey struct {
		pattern string
		hash    [32]byte
	}
	type verificationJob struct {
		pattern string
		secret  string
		indices []int
	}
	jobs := make([]verificationJob, 0)
	seen := make(map[verificationKey]int)
	for index := range findings {
		finding := &findings[index]
		finding.Validity = ValidityUnsupported
		if finding.rawSecret == "" || finding.verificationPattern == "" {
			continue
		}
		pattern := finding.verificationPattern
		if pattern != "jwt" {
			if _, ok := verificationProviders[pattern]; !ok {
				continue
			}
		}
		finding.Validity = ValidityUnknown
		key := verificationKey{pattern: pattern, hash: sha256.Sum256([]byte(finding.rawSecret))}
		if jobIndex, ok := seen[key]; ok {
			jobs[jobIndex].indices = append(jobs[jobIndex].indices, index)
			continue
		}
		seen[key] = len(jobs)
		jobs = append(jobs, verificationJob{pattern: pattern, secret: finding.rawSecret, indices: []int{index}})
	}
	queue := make(chan verificationJob)
	var workers sync.WaitGroup
	for range min(4, len(jobs)) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for job := range queue {
				validity := verifyToken(ctx, &safeClient, job.pattern, job.secret, githubEndpoint)
				if provider, ok := verificationProviders[job.pattern]; ok && provider.github && githubEndpoint != githubPublicVerificationURL {
					publicValidity := verifyToken(ctx, &safeClient, job.pattern, job.secret, githubPublicVerificationURL)
					switch {
					case validity == ValidityActive || publicValidity == ValidityActive:
						validity = ValidityActive
					case validity == ValidityInactive && publicValidity == ValidityInactive:
						validity = ValidityInactive
					default:
						validity = ValidityUnknown
					}
				}
				for _, index := range job.indices {
					findings[index].Validity = validity
				}
			}
		}()
	}
send:
	for _, job := range jobs {
		select {
		case <-ctx.Done():
			break send
		case queue <- job:
		}
	}
	close(queue)
	workers.Wait()
	return ctx.Err()
}

func ValidateVerificationOptions(verify, excludeInactive bool, githubHosts ...string) error {
	if excludeInactive && !verify {
		return fmt.Errorf("excluding inactive findings requires verification (--verify, or --hook-verify for hooks)")
	}
	if len(githubHosts) > 1 {
		return fmt.Errorf("specify only one GitHub verification host")
	}
	if len(githubHosts) == 1 && githubHosts[0] != "" {
		if !verify {
			return fmt.Errorf("a verification host requires verification (--verify, or --hook-verify for hooks)")
		}
		if _, err := githubVerificationURL(githubHosts[0]); err != nil {
			return err
		}
	}
	return nil
}

func ExcludeInactiveFindings(findings []Finding) []Finding {
	return slices.DeleteFunc(findings, func(finding Finding) bool {
		return finding.Validity == ValidityInactive
	})
}
