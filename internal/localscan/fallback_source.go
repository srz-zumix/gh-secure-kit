package localscan

import "errors"

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
	return s.Fallback.Fragments()
}
