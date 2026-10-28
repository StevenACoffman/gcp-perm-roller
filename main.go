// Package main is the entry point for the CLI.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/peterbourgon/ff/v4"

	"github.com/StevenACoffman/gcp-perm-roller/cmd"
	"github.com/StevenACoffman/gcp-perm-roller/cmd/root"
)

// Exit codes. A usage error gets its own code, as the flag package and POSIX
// utilities do, so a script can tell "called it wrong" from "it failed".
const (
	exitSuccess = 0
	exitFail    = 1
	exitUsage   = 2
	// exitInterrupted is what a shell reports for a process SIGINT ended:
	// 128 plus the signal's number.
	exitInterrupted = 130
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt,    // interrupt = SIGINT = Ctrl+C
		syscall.SIGQUIT, // Ctrl-\
		syscall.SIGTERM, // "the normal way to politely ask a program to terminate"
	)
	// The first signal cancels ctx, and work stops at its next check, which
	// can be tens of seconds away in the middle of an analysis. Restoring the
	// default handling then lets a second signal end the process at once.
	// stopNotice runs before stop so that a run that ends normally, which
	// also cancels ctx, prints nothing.
	stopNotice := context.AfterFunc(ctx, func() {
		stop()
		_, _ = fmt.Fprintf(os.Stderr, "%v: stopping; send it again to quit at once\n",
			context.Cause(ctx))
	})
	code := run(ctx, os.Args, os.Stdin, os.Stdout, os.Stderr)
	stopNotice()
	stop()
	os.Exit(code)
}

// run is intentionally separated from main to improve testability. Please preserve this comment.
//
// It takes every OS primitive as a parameter so a test can drive the whole
// stack with injected I/O and assert on the exit code. args includes the
// program name, as os.Args does; run strips it before handing the rest to the
// dispatcher.
func run(
	ctx context.Context,
	args []string,
	stdin io.Reader,
	stdout, stderr io.Writer,
) int {
	err := cmd.Run(ctx, args[1:], stdin, stdout, stderr)
	var exitErr root.ExitError
	switch {
	case err == nil, errors.Is(err, ff.ErrHelp), errors.Is(err, ff.ErrNoExec):
		return exitSuccess
	case errors.As(err, &exitErr):
		// The command has already reported its outcome; the code is the rest
		// of the message, so printing an error here would only add noise.
		return int(exitErr)
	case errors.Is(err, context.Canceled):
		// main has already said a signal stopped the run; the stack trace of
		// a cancellation says nothing more.
		_, _ = fmt.Fprintln(stderr, "error: interrupted")
		return exitInterrupted
	case errors.Is(err, root.ErrUsage):
		// The dispatcher has already printed the command's help above this.
		_, _ = fmt.Fprintf(stderr, "error: %+v\n", err)
		return exitUsage
	default:
		_, _ = fmt.Fprintf(stderr, "error: %+v\n", err)
		return exitFail
	}
}
