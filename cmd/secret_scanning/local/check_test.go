package local

import (
	"strings"
	"testing"
)

// TestCheckRejectsNoOpOwnerRepoFlags verifies that --owner/--repo error out
// when they would otherwise be silently ignored, and stay valid when they
// actually feed the pattern config or the rev-range API source.
func TestCheckRejectsNoOpOwnerRepoFlags(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "owner without pattern-config",
			args:    []string{"--owner", "acme", "--staged"},
			wantErr: "--owner has no effect without --pattern-config",
		},
		{
			name:    "repo without pattern-config outside rev-range",
			args:    []string{"--repo", "acme/app", "--staged"},
			wantErr: "--repo has no effect without --pattern-config",
		},
		{
			name:    "repo in a rev-range scan with no-api",
			args:    []string{"--repo", "acme/app", "--rev-range", "A..B", "--no-api"},
			wantErr: "--repo has no effect without --pattern-config",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewCheckCmd()
			cmd.SetArgs(tt.args)
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			err := cmd.Execute()
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want it to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}
