package localscan

import "testing"

// changedSet builds a "changed" predicate that reports true for the given flag
// names, mimicking cobra's FlagSet.Changed.
func changedSet(names ...string) func(string) bool {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[n] = true
	}
	return func(name string) bool { return set[name] }
}

func TestValidateDanglingModeFlags(t *testing.T) {
	tests := []struct {
		name    string
		local   bool
		changed func(string) bool
		wantErr string
	}{
		{
			name:    "no-reflogs without local",
			local:   false,
			changed: changedSet("no-reflogs"),
			wantErr: "--no-reflogs only applies to --local",
		},
		{
			name:    "no-reflogs with local is accepted",
			local:   true,
			changed: changedSet("no-reflogs"),
		},
		{
			name:    "no changed flags without local",
			local:   false,
			changed: changedSet(),
		},
		{
			name:    "no changed flags with local",
			local:   true,
			changed: changedSet(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDanglingModeFlags(tt.local, tt.changed)
			assertValidationErr(t, err, tt.wantErr)
		})
	}
}

// TestValidateDanglingModeFlagsLocalOnlyMatrix verifies every pull-request-only
// flag is rejected with --local but accepted without it.
func TestValidateDanglingModeFlagsLocalOnlyMatrix(t *testing.T) {
	for _, flag := range danglingLocalOnlyFlags {
		t.Run(flag+" with local", func(t *testing.T) {
			err := ValidateDanglingModeFlags(true, changedSet(flag))
			want := "--" + flag + " does not apply to --local, which inspects local refs instead of pull requests"
			assertValidationErr(t, err, want)
		})
		t.Run(flag+" without local", func(t *testing.T) {
			err := ValidateDanglingModeFlags(false, changedSet(flag))
			assertValidationErr(t, err, "")
		})
	}
}

func assertValidationErr(t *testing.T, err error, want string) {
	t.Helper()
	if want == "" {
		if err != nil {
			t.Fatalf("ValidateDanglingModeFlags() error = %v, want nil", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("ValidateDanglingModeFlags() error = nil, want %q", want)
	}
	if err.Error() != want {
		t.Fatalf("ValidateDanglingModeFlags() error = %q, want %q", err.Error(), want)
	}
}
