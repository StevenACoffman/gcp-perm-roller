package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunExitCodes(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"),
		[]byte("module example.com/m\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := map[string]struct {
		ctx        context.Context
		args       []string
		wantCode   int
		wantStderr string
	}{
		"success": {ctx: context.Background(), args: []string{"version"}},
		"a usage error": {
			ctx:        context.Background(),
			args:       []string{"analyze", "--bogus"},
			wantCode:   exitUsage,
			wantStderr: "error: parse: ",
		},
		// spec: an interrupted command exits as a shell reports SIGINT,
		// with one line rather than a stack trace.
		"interrupted": {
			ctx:        cancelled,
			args:       []string{"analyze", "-C", dir, "./..."},
			wantCode:   exitInterrupted,
			wantStderr: "error: interrupted\n",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tc.ctx, append([]string{"gcp-perm-roller"}, tc.args...),
				strings.NewReader(""), &stdout, &stderr)
			if code != tc.wantCode {
				t.Fatalf("exit %d, want %d; stderr:\n%s", code, tc.wantCode, stderr.String())
			}
			// The usage case also prints help above its error line.
			if got := stderr.String(); tc.wantStderr != "" &&
				!strings.Contains(got, tc.wantStderr) {
				t.Fatalf("stderr %q lacks %q", got, tc.wantStderr)
			}
		})
	}
}
