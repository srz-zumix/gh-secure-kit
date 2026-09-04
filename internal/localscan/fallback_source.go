package localscan

import (
	"errors"

	"github.com/srz-zumix/go-gh-extension/pkg/logger"
)

// FallbackSource scans with Primary, switching to Fallback when the local
// repository does not hold the requested content, for example in a shallow CI
// checkout.
type FallbackSource struct {
	Primary  Source
	Fallback Source
}

// NewFallbackSource creates a FallbackSource.
func NewFallbackSource(primary, fallback Source) *FallbackSource {
	return &FallbackSource{Primary: primary, Fallback: fallback}
}

// Fragments implements Source.
func (s *FallbackSource) Fragments() ([]Fragment, error) {
	frags, err := s.Primary.Fragments()
	if err == nil || !errors.Is(err, ErrLocalContentMissing) {
		return frags, err
	}
	logger.Debug("content missing from the local repository, falling back to the remote source", "error", err)
	return s.Fallback.Fragments()
}
