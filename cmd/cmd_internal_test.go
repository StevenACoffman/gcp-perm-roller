package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"

	"github.com/peterbourgon/ff/v4"
)

func TestRunRegistersEveryCommand(t *testing.T) {
	var stderr bytes.Buffer
	err := Run(context.Background(), []string{"--help"}, strings.NewReader(""), io.Discard, &stderr)
	if !errors.Is(err, ff.ErrHelp) {
		t.Fatalf("got %v, want ff.ErrHelp", err)
	}
	// subcommandRE matches a subcommand's line in the root's help: its name.
	subcommandRE := regexp.MustCompile(`(?m)^ {2}([a-z-]+) {2,}\S`)
	var got []string
	for _, m := range subcommandRE.FindAllStringSubmatch(stderr.String(), -1) {
		got = append(got, m[1])
	}
	// spec: every command is registered, in the order help lists them.
	want := []string{
		"analyze", "verify-table", "version", "wrappers", "import", "troubleshoot", "compare-usage",
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("help lists %v, want %v:\n%s", got, want, stderr.String())
	}
}
