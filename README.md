# modreplace-audit

Flags what changed in a `go.mod`'s `replace`, `exclude` and `retract` directives —
the one Go-specific supply-chain redirection mechanism that dependency-review
tools built around resolved dependency sets don't look at.

```
replace directives: 1 total (1 added, 0 changed, 0 removed, 0 unchanged) vs examples/testdata/base.gomod

FORK+REPLACE     NEW replace golang.org/x/net => github.com/attacker-mirror/x-net v0.59.0 — redirects to a different module path (github.com/attacker-mirror/x-net) instead of a version of golang.org/x/net — verify this is an intentional fork, not a tamper
```

That's `modreplace-audit` run against a real go.mod — `prometheus/prometheus`'s,
264 lines, 150+ requirements — with three routine patch bumps and one
attacker-shaped `replace` added (`go run ./examples`, real output):

```
base go.mod: 264 lines (real prometheus/prometheus go.mod)
head go.mod: 3 routine patch bumps + 1 replace added

raw diff:               35 lines
modreplace-audit output: 1 signal line(s)
```

## The problem

A `replace` directive in `go.mod` silently redirects a module to a different
source: a fork, a local filesystem path, or an entirely unrelated repository.
It bypasses the module proxy and the checksum database (`go.sum`) for that
module entirely — that's the point of `replace`, and also exactly what makes
it a clean way to smuggle in tampered code. `replace github.com/real/pkg =>
github.com/almost-the-same-name/pkg v1.2.3` reads, at a glance in a PR diff,
like a version bump. It isn't one.

**No tool specifically flags a pull request that adds or changes a `replace`.**
This was verified, not assumed, before writing a line of the tool:

- **`govulncheck`** analyzes the modules that actually get built — for a
  `replace`, that means the *replacement's* code, resolved silently, with no
  mention anywhere in its output (text or JSON) that a redirection took place.
  Confirmed by building a two-module repro (a `victim` module and an `app`
  module requiring it, then replaced with `replace example.com/victim =>
  ../victim`) and running `govulncheck ./...` and `govulncheck -format json
  ./...` against it: clean output, and grepping the JSON for `"replace"` turns
  up nothing but an unrelated CVE description that happens to contain the
  English word "replaced".
- **OSV-Scanner** (`osv-scanner scan source`) does something more telling: it
  runs, finds the `go.mod`, and reports **"Filtered 1 local/unscannable
  package/s from the scan."** The locally-replaced module isn't flagged as
  suspicious — it's silently dropped from consideration. The exact case this
  tool is built to catch (a filesystem-path `replace` reaching something that
  gets scanned) is the one case OSV-Scanner explicitly declines to look at.
- **GitHub's Dependency Review / dependency graph for Go** builds its graph
  from `go.mod`/`go.sum` as a resolved, flat dependency set — the same shape
  `govulncheck` and OSV-Scanner consume. A `replace` to a local path has no
  `go.sum` entry to begin with, so it can't appear in that graph at all; a
  `replace` to a remote fork *does* get a `go.sum` entry, under the fork's own
  module path, and shows up as an ordinary dependency with an ordinary name —
  nothing marks it as "this used to be a different module." Socket and Snyk
  operate the same way: on the resolved set, not on the redirection that
  produced it.

Two shapes of the same gap, confirmed by running the actual tools: **drop it
silently** (OSV-Scanner, and implicitly the dependency graphs built from
`go.sum`), or **show it with nothing to mark it as unusual** (govulncheck,
which just analyzes whatever the replacement resolves to). Either way, the
redirection itself — the part a human needs to see — never becomes a signal.

The usual workaround doesn't fix this either:

- **"Just read the go.mod diff."** A `replace` line is one line among
  dozens of routine version bumps in a real PR (see the 35-line/1-signal
  example above), and a fork's module path can be one character off from the
  real one. Skimming a diff is exactly how this gets missed.

## Install

```sh
go install github.com/__GH_OWNER__/modreplace-audit/cmd/modreplace-audit@latest
```

Go >= 1.27.1 (the `go` directive in `go.mod`). No runtime dependencies — see
[What it does not do](#what-it-does-not-do) for why that also shaped what
this tool checks.

## Use

```sh
# Against a git ref (uses `git show <ref>:go.mod`)
modreplace-audit --base origin/main
modreplace-audit                          # --base defaults to HEAD
modreplace-audit go.mod --base origin/main

# Against two files directly — no git repository required
modreplace-audit old/go.mod new/go.mod

# CI
modreplace-audit --base origin/main --fail-on fork,local-path,downgrade --json
```

`--base` accepts either a git ref (`origin/main`, a commit SHA, `HEAD~3`) or,
if it names a file that exists on disk, that file is read directly instead —
so the same flag works whether or not you're in a git repository. With two
positional file arguments, `--base` isn't used at all; the two files are
compared directly, and neither has to be named `go.mod` — the file is parsed
as go.mod content regardless of what it's called (see below).

If a `go.sum` or a `vendor/modules.txt` exists next to the `go.mod` being
audited, both are read automatically to power the `sum` and `goflags` checks.

## Options

| Flag | Default | What it does |
| --- | --- | --- |
| `--base <ref-or-path>` | `HEAD` | What to diff against. Git ref via `git show`, or a literal file path. Ignored (and an error) with two positional file arguments. |
| `--json` | off | Print the full result as JSON instead of the text summary. |
| `--fail-on <signals>` | *(none)* | Comma-separated signal kinds that make the exit code `1`. |
| `--help` | | Print usage. |

**By default the tool never fails your build** — it prints what it found and
exits `0`. You opt into gating CI:

```sh
modreplace-audit --base origin/main --fail-on fork,local-path,downgrade
```

Exit codes: `0` clean run (nothing matched `--fail-on`, or `--fail-on` wasn't
given), `1` a `--fail-on` signal was found, `2` usage error or a file that
couldn't be read or didn't look like a go.mod.

## What each signal means

Signal kinds, for `--fail-on`, in the priority order they're printed:

| Signal | What it means | Why it's a signal |
| --- | --- | --- |
| `fork` | A `replace` redirects to a **different module path**, not just a different version of the same one. | The core tamper vector this tool exists for. The message names the fork target explicitly so it can be checked against the real upstream. |
| `local-path` | A `replace` target is a **filesystem path** (`./...`, `../...`, or absolute) rather than a module. | Fine in development. A broken, or worse, unreviewable, build if it reaches a release — the module that ships is whatever happens to be at that path in whoever's checkout runs `go build`, not what `go.sum` would otherwise pin. |
| `downgrade` | A same-module `replace`'s version is **lower** than what's required elsewhere in the file. | Can silently reintroduce a vulnerability that was already fixed by the version bump the `replace` overrides. |
| `replace` | Any other added or changed `replace` not already covered above (e.g. a same-module pin to a *higher* version). | Still a redirection worth a human's attention, just not one of the higher-severity shapes. |
| `exclude` | An `exclude` directive was added or removed. | Removing an `exclude` can silently let back in a version that was deliberately blocked (often for exactly the "has breaking changes" or "contains retractions" reasons real go.mod files give — see `testdata/real/consul.gomod.txt`). |
| `retract` | The go.mod being audited **changed its own `retract` directives**. | Relevant when auditing a module other code depends on: retracting a version tells consumers not to use it; un-retracting reverses that. See the scope limit below — this is not the same as seeing a *dependency's* retractions. |
| `sum` | The replacement module has **no `go.sum` entry** (and isn't a local path, where that's expected). | Usually means `go mod tidy` wasn't run after editing the `replace` — the build will need network access to fetch and verify it, and can fail outright without one. |
| `removed` | A `replace` directive that existed in the base is gone. | Lowest priority, but still worth a glance — the go.mod changed more than the PR's stated purpose. |
| `goflags` | `GOFLAGS` contains `-mod=mod`, or `vendor/modules.txt` doesn't match what `go.mod` resolves to. | Either one means the file you're reviewing may not be the source that actually builds: `-mod=mod` lets a build silently rewrite `go.mod`/`go.sum`, and a stale `vendor/` directory is used by default over the module cache whenever it's present. |

## What it does not do

- **It does not verify a fork is malicious, or that a version is actually
  vulnerable.** It has no vulnerability database and makes no network calls
  of any kind. It answers "did the redirection mechanism itself change, and
  how" — pair it with `govulncheck` / OSV-Scanner / Dependency Review, which
  answer "is something in the resolved dependency set a known bad version"
  — a question this tool's own research found none of them ask about
  `replace` (see above).
- **`retract` is scoped to the go.mod being audited, not its dependencies.**
  A module's `retract` directives live in *that module's own* go.mod, at
  whatever version gets resolved — seeing a dependency's retractions would
  mean fetching that dependency's go.mod over the network, which this tool
  never does. What it checks instead: whether the go.mod under audit changed
  what *it itself* retracts, which is exactly what matters when the module
  being audited is one other code depends on.
- **Block comments (`/* ... */`) in go.mod are not supported.** They're valid
  in the go.mod grammar, but neither `gofmt` nor `go mod edit` ever emits one,
  and none of the six real-world go.mod files this parser was cross-checked
  against contain one either (see Rigour, below). Line comments (`//`,
  including the `// indirect` convention and the semicolon-suffixed variant
  some large projects use, e.g. `// indirect; @team/owner`) are fully
  supported.
- **Version comparison follows documented Go semver precedence rules**,
  independently implemented (no `golang.org/x/mod/semver` dependency — see
  Install). Pseudo-versions need no special-casing under those rules: a
  pseudo-version's timestamp is itself a semver prerelease identifier that
  already sorts chronologically. When either side of a `downgrade` check
  doesn't parse as a Go module version, the tool says so explicitly rather
  than guessing.
- **The `goflags` vendor check is best-effort.** It compares
  `vendor/modules.txt`'s recorded versions against what `go.mod` (with
  `replace` applied) resolves to, for modules that are actually vendored. It
  does not simulate `go mod vendor` or inspect vendored source.
- **No monorepo/workspace (`go.work`) awareness.** Each invocation audits one
  `go.mod`; a workspace's other modules aren't cross-checked against it.

## Rigour

The parser is hand-written (see [Install](#install) for why: no
`golang.org/x/mod/modfile` dependency), so it was checked two ways:

- **Constructed fixtures, one per signal** — `internal/audit/audit_test.go`
  reproduces each row of the signal table above from scratch: a fork, a
  local-path replace, a version downgrade, an `exclude`/`retract` change, a
  missing `go.sum` entry (and, separately, the *expected* missing entry for a
  local-path replace, which must *not* fire `sum`), `GOFLAGS=-mod=mod`, and a
  stale `vendor/modules.txt`.
- **Six real go.mod files**, fetched from public repositories and cross-checked
  against `go mod edit -json` — the Go toolchain's own parser — field by
  field (`Module`, every `Require` with its `Indirect` flag, every `Replace`,
  every `Exclude`): `spf13/cobra` (a minimal file), `prometheus/prometheus`
  (four separate `require` blocks, 150+ `// indirect` markers, pseudo-versions
  like `v0.0.0-20260709172345-9ea1abe57597`), `etcd-io/etcd` and
  `hashicorp/terraform` (multi-line and single-line local-path `replace`
  directives — `go.etcd.io/etcd/api/v3 => ./api`), `hashicorp/consul` (an
  `exclude` block with rationale comments — `v1.1.5 // has breaking changes`),
  and `grafana/grafana` (turned up a real bug during development: `// indirect;
  @grafana/observability-traces-and-profiling` — a semicolon-suffixed indirect
  marker that an exact `== "indirect"` comparison missed; fixed to match on the
  leading token only, which is what `go mod edit -json` itself does). These
  live in `testdata/real/`, deliberately **not** named `go.mod` or `*.mod`, and
  a test fails outright if they ever are — the point is proving the parser
  works from content, not from a filename.

`go mod edit -json` is used only inside these tests, run with
`GOTOOLCHAIN=local` and `GOPROXY=off` so the check can never itself reach the
network; the shipped tool never shells out to `go` at all.

Definition of done, actually run:

```
go build ./...   # clean
go vet ./...     # clean
go test -race ./...   # 30 tests, all packages, all pass
gofmt -l .       # prints nothing
```

## Develop

```sh
go test ./...              # full suite
go test -race ./...        # what CI runs
go run ./examples          # the base/head go.mod comparison at the top of this README
```

## License

MIT
