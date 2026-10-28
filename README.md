# Gcp-Perm-Roller

A whole-program static analyzer that lists the Google Cloud API calls each Go binary in a
workspace can actually make, the IAM permissions its service account needs for them, and
the predefined roles that grant those permissions with the least excess.

## Install

```sh
go install github.com/StevenACoffman/gcp-perm-roller@latest
```

## Usage

`-C` names the Go workspace (a directory with `go.work`) or module to analyze. Package
patterns are resolved there. With no patterns, every module of the workspace is analyzed.

```sh
# Every binary in the workspace
gcp-perm-roller analyze -C ~/src/myworkspace

# One binary, with the first-party call sites behind each SDK call
gcp-perm-roller analyze -C ~/src/myworkspace -v ./cmd/server

# Least-privilege predefined roles, from saved role data or the IAM API
gcp-perm-roller analyze -C ~/src/myworkspace --format=predefined \
  --roles ~/src/iam-dataset/gcp/roles ./cmd/server
gcp-perm-roller analyze -C ~/src/myworkspace --format=predefined ./cmd/server # --roles=api

# One file per binary, to commit next to the code
gcp-perm-roller analyze -C ~/src/myworkspace --format=predefined --include-conditional \
  --outdir=$HOME/src/myworkspace/iam/recommended

# A custom role definition for gcloud
gcp-perm-roller analyze -C ~/src/myworkspace --format=role ./cmd/server >server-role.yaml
gcloud iam roles create serverJob --project=PROJECT --file=server-role.yaml

# Binaries from several workspaces in one report: save each as JSON, then combine
gcp-perm-roller analyze -C ~/src/one --format=json >one.json
gcp-perm-roller analyze -C ~/src/two --format=json ./cmd/... >two.json
gcp-perm-roller analyze --from=one.json --from=two.json --union --format=predefined
```

| Flag             | Meaning                                                                     |
| ---------------- | --------------------------------------------------------------------------- |
| `-C`, `--dir`    | Workspace or module to analyze (default `.`)                                |
| `--format`       | `text` (default), `json`, `role` (gcloud custom role YAML), or `predefined` |
| `--union`        | Merge every binary into a single report                                     |
| `-v`             | Show call sites for each SDK call (text format)                             |
| `--strict`       | Exit non-zero when an SDK call has no rule in `table.go`                    |
| `--outdir`       | Write one file per binary to a directory instead of stdout                  |
| `--tags`         | A build tag; repeat the flag for more                                       |
| `--algo`         | Call graph algorithm: `vta` (default) or `rta`                              |
| `-j`, `--jobs`   | Binaries analyzed in parallel (default GOMAXPROCS, at most 4)               |
| `--wrapper`      | A function that calls its function arguments by reflection; repeatable      |
| `--wrapper-file` | Wrappers saved by the `wrappers` command; repeatable                        |
| `--from`         | Read results saved with `--format=json` instead of analyzing; repeatable    |

Every flag can also be set with an environment variable: prefix `GCP_PERM_ROLLER_`,
uppercase it, and replace dashes with underscores (`GCP_PERM_ROLLER_FORMAT=json`).

Analyzing a workspace of 20 modules takes about 90 seconds and 9 GB of memory with VTA,
or about 45 seconds with `--algo=rta`. Patterns that match no main package are an error.

`--outdir` names each file for the package's directory relative to `-C`, with slashes
turned into dashes (`billing/cmd/worker` becomes `billing-cmd-worker.txt`). Each file
starts with a `Code generated` line naming the command that reproduces it. A run also
removes generated files it did not rewrite, so binaries that went away leave nothing
behind. JSON files carry no such line, so they are never removed.

## Predefined Roles

`--format=predefined` recommends, for each binary, the predefined (built-in) IAM roles that
grant its permissions with the least excess. `--format=json` includes the same selection
whenever `--roles` is given.

| Flag                    | Meaning                                                           |
| ----------------------- | ----------------------------------------------------------------- |
| `--roles`               | Where to read roles: `api`, or saved JSON (a directory or a file) |
| `--role-stages`         | A launch stage to recommend; repeatable (default `GA`)            |
| `--include-conditional` | Also cover conditional permissions                                |

Roles come from one of two places:

- **The IAM API** (`--roles=api`), using Application Default Credentials. Run
  `gcloud auth application-default login` first. Listing predefined roles is read-only
  and needs no IAM permission. This is the same call [gcp-iam-lookup] and
  [gcp_iam_search] make.
- **Saved roles.** This is either a directory with one role per file, as
  `gcloud iam roles describe --format=json` writes them (for example [iam-dataset]'s
  `gcp/roles`, refreshed daily), or a file holding a JSON array of roles.

How roles are chosen:

1. **Some roles are never recommended:**

   - basic roles (`owner`, `editor`, `viewer`, `browser`);
   - service agent and `system` roles, which Google grants to its own service accounts;
   - `legacy` roles, kept for ACL compatibility;
   - deprecated and deleted roles.

   Only GA roles are considered unless `--role-stages` says otherwise. Many BETA roles are
   meant for one special principal, such as BigQuery's authorized-routine roles.

2. **A permission is granted through roles of its own service** (`datastore.*` through
   `roles/datastore.*`) whenever such a role holds it. Without this rule, the smallest
   role holding a Datastore or Pub/Sub permission is often another product's, such as
   `roles/firebaserules.system` or `roles/storagetransfer.transferAgent`. Granting one of
   those would be hard to review, and it changes with that product's needs.

3. **The cheapest set wins.** Among the allowed roles, the selection minimizes the total
   number of permissions granted, then the number of roles. For example, it picks
   `storage.objectCreator` and `storage.objectViewer` (18 permissions) over
   `storage.objectUser` (28) when that covers what the binary needs. Permissions no role
   links are solved separately, and each group is solved exactly by a search over its
   subsets. A group of more than 20 linked permissions is solved greedily, and the report
   says so.

4. **Redundant roles are pruned.** A chosen role is dropped when the other chosen roles
   already grant every permission it was chosen for. This happens when a role chosen for
   its own service also holds another service's permission, so that service's role adds
   nothing, or when one chosen role holds every permission of another. Larger roles are
   tried first, so the most permissions are shed. A dropped role's permissions are
   credited to a remaining role that holds them, preferring one of the permission's own
   service.

Permissions that no allowed role grants are listed for a custom role; `--format=role`
writes one. Each role's `for` line lists the permissions it was chosen for. A role chosen
for its own service may also hold other services' permissions, which count toward the
excess unless they are required.

A role chosen this way can still be one meant for a Google service. For
`storage.buckets.get` alone, the cheapest GA role is `roles/storage.insightsCollectorService`
(4 permissions), the role of Storage Insights' inventory service. The role meant for it,
`roles/storage.bucketViewer` (2 permissions), is BETA; add `--role-stages=GA --role-stages=BETA` to have it chosen. The only other GA, non-legacy Storage role holding
the permission is `roles/storage.admin`, with 113.

## How It Works

1. Loads the packages and builds SSA for the whole program, dependencies included.
   Test files are excluded.
2. For each `main` package, builds a call graph from `main` and `init` and finds the
   reachable functions. Code that is never called, such as
   `tracing.RegisterOpenTelemetryTracingForProd`, contributes nothing. See
   [Call Graph Algorithms](#call-graph-algorithms).
3. In each reachable first-party function, records every exported SDK function or method
   it calls or takes the value of, plus SDK methods reached through first-party
   interfaces. Adapters in `google-cloud-go-testing` (`dsiface`, `stiface`) count as
   first-party code.
4. Maps each SDK entry point to permissions with the rules in [`table.go`](internal/gcpperms/table.go).

The output for each binary contains:

- **Permissions**: always required when the call runs.
- **Conditional permissions**: required only on some paths, for example
  `storage.objects.delete` when a writer overwrites an existing object.
- **APIs**: services that must be enabled in the project.
- **Notes**: requirements the analyzer cannot check, such as
  `bigquery.tables.getData` on the tables a query reads, or OAuth scopes for the
  Sheets and Drive APIs, which do not use IAM.
- **Unmapped SDK calls**: entry points with no rule. Add a rule for each one.

## Call Graph Algorithms

The default, `--algo=vta`, runs in two steps:

1. Rapid Type Analysis (RTA) finds a first set of reachable functions and an initial
   call graph.
2. Variable Type Analysis (VTA) refines that graph. It tracks which types and function
   values flow to each interface call and function-value call, and keeps only the
   edges they allow. Reachability is then recomputed from `main` and `init` over the
   refined graph.

VTA only removes edges from RTA's graph, so it never reports more than RTA does. What
it removes are RTA's assumptions about reflection:

- RTA treats every exported method of a type converted to an interface as callable
  through reflection. With RTA, calling one method of a `dsiface` adapter reports
  all 20 SDK calls in the adapter. VTA reports just the one.
- RTA lets `reflect.Value.Call` call any address-taken function. Protobuf descriptor
  formatting reaches `reflect.Value.Call`, so RTA can report a permission for a binary
  through a table of closures that the binary loads but never calls. VTA drops such a
  permission.

Use
`--algo=rta` for a quicker check, or to compare against VTA: a permission RTA reports
and VTA does not is reachable only through reflection.

## Maintaining the Table

When a new SDK call appears, the report lists it under **Unmapped SDK calls** with its
call sites. Add a rule to `rules` in [`internal/gcpperms/table.go`](internal/gcpperms/table.go):

- Use the permission for the RPC that the call sends. The per-service IAM pages linked
  at the top of `rules` list the permission for each method.
- Calls that send no RPC, such as constructors, key builders, and getters, get a rule
  with no permissions. A `"pkg.*"` catch-all after the specific rules covers most of
  them.
- Rules are checked in order, so put specific patterns before broad ones.

Run with `--strict` in CI to fail when the table falls behind the code.

## Verifying the Table

`gcp-perm-roller verify-table` ([`internal/verifytable`](internal/verifytable)) checks
`table.go` against Google's public documentation, independently of the analyzer. It parses
`table.go` from source (the copy built into the binary, or `--table`) and builds its own
call graph of the workspace in `-C`. It reads only public pages, so it needs no Google
Cloud credentials.

```sh
# About a minute once pages are cached
gcp-perm-roller verify-table -C ~/src/myworkspace >table-report.md

# Only some binaries of a large module: package patterns, resolved in -C
gcp-perm-roller verify-table -C ~/src/monorepo ./services/billing/cmd/... >table-report.md

# Fail on any mismatch, and add iam-dataset as a second opinion
gcp-perm-roller verify-table -C ~/src/myworkspace --strict \
  --iam-dataset ~/src/iam-dataset >table-report.md
```

It runs two checks:

1. **Permission names.** Every permission the table grants must appear in the
   [IAM roles and permissions reference](https://cloud.google.com/iam/docs/roles-permissions).
   Names are compared ignoring case, because REST pages sometimes spell them differently
   from the reference (`dockerImages`, `dockerimages`).
2. **Method documentation.** For each SDK call the workspace makes, the verifier traces
   the RPCs the call sends: gRPC method constants, gapic REST transports, and generated REST
   clients. It maps each RPC to its REST method through its `google.api.http` binding and
   the API's discovery document. It then reads the permissions the method's reference page
   states, falling back to the service's access-control table. A sentence that makes a
   permission depend on the request ("to cancel a job", "must also have") marks that
   permission as conditional, not required.

The table charges some permissions to the call that creates an iterator, writer, or mutation
rather than the call that sends the request. The verifier pairs these calls through the SDK
types they share. `Client.Run` is checked against `Iterator.Next`, `NewWriter` against
`Writer.Close`, and `Transaction.Put` against `RunInTransaction`, which commits the
transaction.

The report sorts each SDK call into one of these groups:

| Group      | Meaning                                                                     |
| ---------- | --------------------------------------------------------------------------- |
| Mismatches | The docs require a permission the rule lacks, or name none of one it grants |
| Accepted   | Differences kept on purpose, each with a reason (`accepted` in `verify.go`) |
| Unverified | No RPC could be traced or documented                                        |
| Not IAM    | The rule grants nothing and notes an OAuth-scope requirement                |
| Confirmed  | The docs state what the rule grants                                         |

RPCs that are reachable but not real requirements are listed in `explainedRPC`, with the
SDK source that shows why. One example is the bucket metadata fetch that storage sends only
when `GO_STORAGE_DEV_OTEL_TRACING=true`, except from `BucketHandle.Attrs`, which sends it
on purpose.

Some calls only build the value that sends their RPCs, which something the trace cannot
follow calls later: the metric exporter `metric.New` returns is called by the
OpenTelemetry SDK. `deferredSenders` names the type whose methods send such a call's RPCs,
and the trace follows those methods too.

A gRPC API with no discovery document, such as the BigQuery Storage API, cannot be mapped
to REST reference pages. For those listed in `rpcReferencePage`, the verifier reads each
method's permissions from its request message on the API's RPC reference page instead.

`--algo=rta` builds the call graph the verifier traces with RTA alone, which also follows calls
VTA cannot resolve. Package patterns after the flags limit the trace to those binaries,
which a large module needs.

With `--iam-dataset`, the verifier also reads a clone of
[iam-dataset](https://github.com/iann0036/iam-dataset). It checks permission names against
that dataset's predefined roles, which come from the IAM roles API. It lists where the
dataset's method map disagrees with the table, and what the dataset says about methods
Google does not document. The map is partly hand-written and does not cite its sources,
so the verifier reports it but never treats it as authoritative.

## Testing

The [`justfile`](justfile) has a recipe for each of these; `just` lists them.

```sh
# Unit, property, and end-to-end tests (just test-short skips the end-to-end test)
just test

# rapid properties with 1000 checks each instead of 100
just proptest

# Fuzz one target (just fuzz-all runs each one briefly); the others are FuzzShortAPI,
# FuzzLookup, FuzzUnionMergesEveryBinary, FuzzWriteRoles, and FuzzSelectRolesIsOptimal
just fuzz FuzzSplitAPI 30s

# Mutation testing of internal/gcpperms against its baseline, about 25 minutes
just mutate
```

The suite has six layers:

- **Role selection tests** in `roles_internal_test.go`, including rapid properties. The chosen
  roles cost no more than a brute-force search over every subset finds, cover everything
  coverable, and do not depend on input order. No chosen role is redundant: dropping any
  one leaves a required permission that the others' full permission sets lack.
- **Property tests** ([rapid](https://github.com/flyingmutant/rapid)) in
  `gcpperms_internal_test.go` check invariants of the pure helpers and the report
  writers. Examples: `splitAPI` round-trips, `lookup` returns the first matching
  rule, no table rule is shadowed by an earlier one, `Union` ignores binary order,
  and JSON output round-trips. Increase the case count with `-rapid.checks=N`.
  Under `-short`, rapid runs a fifth of the checks.
- **Fuzz tests** in `fuzz_internal_test.go` run the API-name helpers on arbitrary strings.
  The structured targets reuse rapid generators with `rapid.MakeFuzz`, so Go's
  coverage-guided fuzzer drives them.
- **SSA unit tests** in `ssa_internal_test.go` build a fake
  `cloud.google.com/go/fake` package in memory to test `apiName`, `pkgPath`, and `site`
  on closures, method values and expressions, generic instances, and universe methods.
- **Call graph tests** in `ssa_internal_test.go` check that RTA reports a wrapper method that
  only reflection could call and VTA does not.
- **End-to-end test** `TestAnalyze` analyzes the programs in `testdata/`. Each
  case pins down one behavior: interface calls, method values, package
  initializers, generic instances, build tags, unmapped calls, unreachable code,
  wrapper adapters, and packages with type errors.

Mutation testing with [mutago](https://github.com/quality-gates/mutago) fails below 95%
MSI. It mutates every source file in `internal/gcpperms`, including the permission
table's logic but not its data: `ignore_source_lines` in [`.mutago.yml`](.mutago.yml)
skips the rules' field lines, and a `mutator-disable-regexp` annotation in `table.go`
skips the rule literals themselves. The text, role, and JSON reports are pinned by golden
files in `testdata/golden`.

The last run, with mutago v2.10.24, killed 853 of 888 mutants (96.06%):

| File           | Killed    | Score  |
| -------------- | --------- | ------ |
| `callgraph.go` | 35 / 35   | 100%   |
| `gcpperms.go`  | 199 / 204 | 97.55% |
| `report.go`    | 149 / 149 | 100%   |
| `roles.go`     | 419 / 449 | 93.32% |
| `table.go`     | 51 / 51   | 100%   |

A whole-package run takes over two hours with four workers; `roles.go` alone takes about
50 minutes. To run one file, pass its path in place of the package.

The 35 surviving mutants are recorded in
[`internal/gcpperms/mutago-baseline.json`](internal/gcpperms/mutago-baseline.json). None
of them can change a result. In `gcpperms.go`:

- Three disable the error return after `filepath.Abs`, which fails only if the working
  directory is deleted.
- One passes -1 instead of 0 to `runtime.GOMAXPROCS`; both values only read the setting.
- One releases each worker's slot immediately instead of when it finishes. This lifts the
  limit on concurrent workers but leaves every report the same.

In `roles.go`:

- Four replace a `return false` case body with a zero-value return, which is `false`.
- Four remove the error guards after `filepath.Glob` and `os.ReadFile` while loading saved
  roles. Loading fails either way: on finding no role files, or on parsing no data.
- One passes a nil context to `iam.NewService`, which only uses it to build the client.
- Eight change constants the greedy search overwrites or never reads: the size hint of a
  bitset that grows on demand, and the initial `pick`, `pickNew`, and zero-coverage check,
  which the first covering role replaces.
- One adds 2 instead of 1 per role to the exact search's cost, which scales every cost
  alike; one changes the `unreached` sentinel, which is only compared with itself; one
  visits the full set once more, which adds nothing; one drops the `next != m` guard,
  whose skipped roles could never lower a cost.
- Two change `heir`'s comparison of equal candidates, which only differ when two roles
  have the same name.
- Two change `boolInt`'s values, which are only compared with each other.
- One sets `granted[p] = false`; the map is used as a set, so only its keys count.
- Two skip copying each chosen role's set before pruning; the originals are not read
  again.
- Two weaken union-find (path compression, and linking a permission to itself); grouping
  only splits the search, so a coarser grouping finds the same roles.

Keep `--timeout-coefficient` high. Each mutant reruns the end-to-end test, which
loads the SDK. With parallel workers, a low coefficient times out mutants that
would have survived, and mutago counts timeouts as kills. A coefficient of 4
reported 99.6%, and the honest score was 91%.

`RAPID_NOFAILFILE=true` stops rapid from saving a failure file in `testdata/rapid/`
for every mutant it kills. Set it in the environment. Do not pass
`-rapid.nofailfile` through `--test-flags`: mutago puts test flags before the
package path, and `go test` passes everything after an unrecognized flag to the
test binary. The tests would then run in the wrong directory, and every mutant
would escape.

## Reflection Wrappers

`gcp-perm-roller wrappers` finds the functions in a workspace that call a function passed
to them by reflection, and saves them as JSON for `analyze --wrapper-file`:

```sh
gcp-perm-roller wrappers -C ~/src/monorepo --out=wrappers.json
gcp-perm-roller analyze -C ~/src/monorepo --wrapper-file=wrappers.json ./services/billing/cmd/...
```

A function is a wrapper when a `reflect.Value` it makes from one of its parameters with
`reflect.ValueOf` is called with `reflect.Value.Call` or `CallSlice`. The call can be in the
function, in a closure it creates (such as one passed to `reflect.MakeFunc`), through a method
value (`next := v.Call`), or in a helper it passes the value to, at any depth. Each entry
records the parameters whose functions are called, so only those arguments count as
called; where the wrapper is declared; how many calls to it the search saw; and how it
calls them:

```json
{
  "wrappers": [
    {
      "function": "example.com/mymodule/pkg/cache.Cache",
      "params": [
        0
      ],
      "site": {
        "file": "pkg/cache/api.go",
        "line": 96
      },
      "calls": 252,
      "reason": "passes parameter 0 to reflect.ValueOf and calls it through wrapCall"
    }
  ]
}
```

Only the packages the patterns name are loaded from source, with dependencies' types
from compiled export data, and no call graph is built, so searching a large module is far
cheaper than analyzing it. Wrappers that keep the function in a struct field or a global
before calling it are not found; add them to the file by hand. An entry needs only
`function`; without `params`, every function argument counts.

## Limitations

- The report is an upper bound on what a binary can do. VTA still over-approximates
  dynamic calls: a call site is resolved to every type that may flow to it. Because the
  analysis is static, it cannot tell which branches run in production.
- VTA does not model reflection. An SDK call made only through `reflect.Value.Call`,
  or through a method invoked by reflection such as a `text/template` method call,
  is missed. RTA covers those cases at the cost of false positives. This matters for
  code that caches function results by reflection: a memoizing wrapper that builds its
  result with `reflect.MakeFunc` hides from VTA every SDK call behind a cached function.
  Name such wrappers with `--wrapper`, for example
  `--wrapper=example.com/mymodule/pkg/cache.Cache`, or find them with the `wrappers`
  command and load them with `--wrapper-file` (see [Reflection Wrappers](#reflection-wrappers)):
  each call to one then counts as calling every function passed to it, which brings those
  calls back while VTA still leaves out RTA's false positives, such as clients a binary
  holds but never uses.
- Calls through standard-library or third-party interfaces (`io.Closer`, `error`) are
  not followed. They match too many SDK types to be useful, and the operations that need
  permissions are reached by name elsewhere.
- Permissions are reported per binary, not per resource. Grant them on the narrowest
  resource that works, for example a single bucket or secret.
- Packages that fail to type-check are skipped, with a warning.
- Only Go SDK calls are seen. Raw HTTP calls to Google APIs and permissions used by
  sidecars or the deployment platform are not.

[gcp-iam-lookup]: https://github.com/joemiller/gcp-iam-lookup
[gcp_iam_search]: https://github.com/google/gcp_iam_search
[iam-dataset]: https://github.com/iann0036/iam-dataset
