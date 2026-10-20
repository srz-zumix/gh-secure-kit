package localscan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/srz-zumix/go-gh-extension/pkg/copilotext"
)

// CopilotSource scans GitHub Copilot session logs on disk.
type CopilotSource struct {
	Options copilotext.LogOptions
}

// NewCopilotSource creates a CopilotSource for the given log selection.
func NewCopilotSource(opts copilotext.LogOptions) *CopilotSource {
	return &CopilotSource{Options: opts}
}

// Fragments implements Source.
func (s *CopilotSource) Fragments() ([]Fragment, error) {
	var frags []Fragment
	err := s.StreamFragments(func(f Fragment) error {
		frags = append(frags, f)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return frags, nil
}

// StreamFragments implements FragmentStreamer.
func (s *CopilotSource) StreamFragments(yield func(Fragment) error) error {
	return copilotext.WalkLogFiles(s.Options, func(file copilotext.LogFile) error {
		data, err := os.ReadFile(file.Path)
		if err != nil {
			return fmt.Errorf("failed to read file %q: %w", file.Path, err)
		}
		content := string(data)
		if isBinaryString(content) {
			return nil
		}

		base := Fragment{
			FilePath:    file.Path,
			Date:        file.ModifiedAt,
			Source:      file.Source,
			SessionID:   file.SessionID,
			SessionName: file.SessionName,
			Workspace:   file.Workspace,
		}
		switch strings.ToLower(filepath.Ext(file.Path)) {
		case ".jsonl":
			return streamJSONFragments(content, true, base, yield)
		case ".json":
			return streamJSONFragments(content, false, base, yield)
		}
		base.Content = content
		return yield(base)
	})
}
