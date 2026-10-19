package localscan

import "time"

// Finding represents a single secret detected in a scanned fragment.
type Finding struct {
	PatternID   string    `json:"pattern_id"`
	TokenType   string    `json:"token_type"`
	DisplayName string    `json:"display_name"`
	Commit      string    `json:"commit,omitempty"`
	Author      string    `json:"author,omitempty"`
	Date        time.Time `json:"date,omitempty"`
	File        string    `json:"file"`
	StartLine   int       `json:"start_line"`
	Match       string    `json:"match"`
	Secret      string    `json:"secret"`
	Source      string    `json:"source,omitempty"`
	SessionID   string    `json:"session_id,omitempty"`
	SessionName string    `json:"session_name,omitempty"`
	Workspace   string    `json:"workspace,omitempty"`
	matchHash   [32]byte
}
