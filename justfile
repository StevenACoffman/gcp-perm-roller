# Recipes for gcp-perm-roller. `just` with no arguments lists them.

# The package mutation testing gates on: the analysis, the permission table's logic and
# role selection. Its known equivalent mutants are in the baseline next to it.
gcpperms := "./internal/gcpperms/"
baseline := "internal/gcpperms/mutago-baseline.json"

# mutago, pinned: a new release can add a mutator, which changes the escape set on a change
# that touched nothing. v2.10.24 is also the first release whose source annotations suppress
# composite/field-clear, which internal/gcpperms/table.go relies on.
mutago := "go run github.com/quality-gates/mutago/v2/cmd/mutago@v2.10.24"

default:
    @just --list

# Install the toolchains pinned in .mise.toml (Go, golangci-lint, mutago, govulncheck, ...)
setup:
    mise install

# Build every package
build:
    go build ./...

# Run the CLI, e.g. `just run analyze -C ~/src/myworkspace ./cmd/server`
run *args:
    go run . {{args}}

# Recommend least-privilege predefined roles for every binary in a workspace, one file per
# binary, in a form to commit next to the code. Reads roles from the IAM API, so run
# `gcloud auth application-default login` first.
#
# Write recommended roles for each binary of a workspace to a directory
recommend workspace outdir:
    go run . analyze -C {{workspace}} --format=predefined --roles=api \
        --include-conditional --outdir={{outdir}}

# Check the permission table against Google's documentation, tracing a workspace's SDK calls
verify-table workspace="." *flags:
    go run . verify-table -C {{workspace}} {{flags}}

# The end-to-end test in internal/gcpperms loads and type-checks the Google Cloud SDK, which
# takes about ten seconds; `test-short` skips it.
#
# Run the full suite with the race detector
test:
    go test -race ./...

# Run the suite without the end-to-end analyzer test
test-short:
    go test -short ./...

# rapid runs 100 checks per property by default; this is the deeper sweep.
#
# Run the rapid properties with more attempts than the default
proptest checks="1000":
    go test ./internal/... -rapid.checks={{checks}}

# Run the suite with a coverage report (a report for humans, not a gate)
test-cover:
    go test -race -coverprofile=coverage.out -covermode=atomic ./...
    go tool cover -func=coverage.out | tail -1
    @echo "HTML report: go tool cover -html=coverage.out"

# Run golangci-lint
lint:
    golangci-lint run ./...

# Format Go source with the formatters configured in .golangci.yaml
fmt:
    golangci-lint fmt ./...

# --fix rewrites source, and some rewrites are wrong, so the tree is built and tested
# afterwards: a bad rewrite fails here instead of in a commit.
#
# Auto-fix what the linters can fix, then prove the tree still works
lint-fix:
    golangci-lint run --fix ./... || true
    @echo "── verifying --fix did not break the tree ──"
    go build ./...
    go vet ./...
    go test -short ./...
    @echo "── remaining issues --fix could not resolve ──"
    golangci-lint run ./...

# Check that the CLI still follows the climax structure (main.go, cmd/cmd.go, cmd/root)
climax-lint:
    climax lint .

# `vale sync` first: the style packages are not checked in, so a fresh checkout has none and
# vale would otherwise report every rule as missing rather than saying why.
#
# Lint the prose in Markdown
vale:
    vale sync
    vale README.md TODO.md

# Verify go.mod/go.sum are tidy (CI runs this; a dirty tree fails the build)
tidy-check:
    #!/usr/bin/env bash
    set -euo pipefail
    backup=$(mktemp -d)
    trap 'rm -rf "$backup"' EXIT
    cp go.mod go.sum "$backup"/
    go mod tidy
    if ! diff -q "$backup"/go.mod go.mod >/dev/null || ! diff -q "$backup"/go.sum go.sum >/dev/null; then
        cp "$backup"/go.mod "$backup"/go.sum .
        echo "go.mod/go.sum are not tidy; run 'go mod tidy' and commit the result" >&2
        exit 1
    fi
    echo "go.mod and go.sum are tidy"

# Run govulncheck vulnerability scanner
vulncheck:
    govulncheck ./...

# Run every gate CI runs
check: tidy-check lint climax-lint vulncheck test

# The end-to-end test must run for each mutant: it is what kills mutants in the call graph
# walk, so there is no -short here. Each mutant reruns it, which loads the SDK; with parallel
# workers a low --timeout-coefficient times out mutants that would have survived, and mutago
# counts timeouts as kills (a coefficient of 4 reported 99.6% where the honest score was 91%).
#
# RAPID_NOFAILFILE stops rapid saving a failure file in testdata/rapid/ for every mutant it
# kills. It must be an environment variable: mutago puts --test-flags before the package path,
# and `go test` hands everything after an unknown flag to the test binary.
#
# Mutation-test internal/gcpperms against its baseline (about 25 minutes); fails below the threshold
mutate threshold="95":
    RAPID_NOFAILFILE=true {{mutago}} --config=.mutago.yml --baseline={{baseline}} \
        --min-msi={{threshold}} --workers=4 --timeout-coefficient=15 --quiet --no-diffs \
        {{gcpperms}}

# Mutation-test internal/gcpperms and show the diff for every surviving mutant
mutate-report:
    RAPID_NOFAILFILE=true {{mutago}} --config=.mutago.yml --baseline={{baseline}} \
        --workers=4 --timeout-coefficient=15 --html-output {{gcpperms}}
    @echo "wrote mutago-report.html"

# This is what makes the technique affordable: seconds per change rather than the 25 minutes
# a whole-package run takes. Informational, with no floor.
#
# Mutation-test only the lines changed against a base ref
mutate-diff base="main":
    RAPID_NOFAILFILE=true {{mutago}} --config=.mutago.yml --git-diff-lines --git-diff-base={{base}} \
        --timeout-coefficient=15 --quiet --no-diffs ./internal/... ./cmd/...

# verify-table and the commands have no recorded floor yet; read the result per file.
#
# Mutation-test every package, informational only
mutate-all:
    RAPID_NOFAILFILE=true {{mutago}} --config=.mutago.yml --baseline={{baseline}} \
        --coverage --workers=4 --timeout-coefficient=15 --quiet --no-diffs ./internal/... ./cmd/...

# Read mutago-agentic.json, then target a single survivor with
# `just mutate-one <id> <file>`.
#
# Write the surviving mutants of internal/gcpperms as JSON, to work through one at a time
mutate-survivors:
    RAPID_NOFAILFILE=true {{mutago}} --config=.mutago.yml --baseline={{baseline}} \
        --workers=4 --timeout-coefficient=15 --quiet --no-diffs --logger-agentic-json {{gcpperms}}
    @echo "wrote mutago-agentic.json"

# Run one mutant by the id mutago-agentic.json gives it
mutate-one id file:
    RAPID_NOFAILFILE=true {{mutago}} --config=.mutago.yml --run-mutant-id={{id}} {{file}}

# Fuzz one target, e.g. `just fuzz FuzzLookup 60s`
fuzz target="FuzzSplitAPI" duration="30s":
    #!/usr/bin/env bash
    set -euo pipefail
    # `go test -fuzz` exits 0 when the pattern matches nothing, so a renamed or deleted
    # target would silently "pass". Check it exists first. The list is captured before
    # matching rather than piped into `grep -q`, whose early exit kills `go test` with
    # SIGPIPE and fails the pipeline under pipefail.
    targets=$(go test -list '^Fuzz' {{gcpperms}})
    if ! printf '%s\n' "$targets" | grep -qx '{{target}}'; then
        echo "no such fuzz target: {{target}}" >&2
        printf '%s\n' "$targets" | grep '^Fuzz' >&2
        exit 1
    fi
    go test -run='^$' -fuzz='^{{target}}$' -fuzztime={{duration}} {{gcpperms}}

# Fuzz every target for a short burst each
fuzz-all duration="20s":
    #!/usr/bin/env bash
    set -euo pipefail
    # Packages and targets are derived rather than listed, so a new target anywhere under
    # internal/ joins the sweep. `go test -fuzz` takes one package at a time.
    found=0
    for pkg in $(go list ./internal/...); do
        targets=$(go test -list '^Fuzz' "$pkg" | grep '^Fuzz' || true)
        for target in $targets; do
            echo "== $pkg $target"
            found=$((found + 1))
            go test -run='^$' -fuzz="^${target}$" -fuzztime={{duration}} "$pkg"
        done
    done
    if [ "$found" -eq 0 ]; then
        echo "no fuzz targets found under ./internal/..." >&2
        exit 1
    fi
