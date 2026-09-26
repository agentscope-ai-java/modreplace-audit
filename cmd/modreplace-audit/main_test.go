package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func mustRun(t *testing.T, args []string) (stdout, stderr string, code int) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code = run(args, &out, &errBuf)
	return out.String(), errBuf.String(), code
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// --- two-file mode, the no-git-required path ---

func TestTwoFileMode_ForkDetected(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.mod")
	head := filepath.Join(dir, "head.mod")
	writeFile(t, base, "module m\n\ngo 1.22\n\nrequire github.com/real/pkg v1.5.0\n")
	writeFile(t, head, "module m\n\ngo 1.22\n\nrequire github.com/real/pkg v1.5.0\n\nreplace github.com/real/pkg => github.com/attacker/pkg v1.5.0\n")

	stdout, stderr, code := mustRun(t, []string{base, head})
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stdout, "FORK") || !strings.Contains(stdout, "github.com/attacker/pkg") {
		t.Errorf("stdout missing fork signal:\n%s", stdout)
	}
}

// Two files not literally named go.mod — this is the content-detection
// requirement: filenames here are deliberately not "go.mod".
func TestTwoFileMode_FileNamesDoNotMatter(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "old-revision.txt")
	head := filepath.Join(dir, "new-revision.txt")
	writeFile(t, base, "module m\n\ngo 1.22\n")
	writeFile(t, head, "module m\n\ngo 1.22\n\nreplace github.com/real/pkg => ../local/pkg\n")

	stdout, stderr, code := mustRun(t, []string{base, head})
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stdout, "LOCAL-PATH") {
		t.Errorf("stdout missing local-path signal:\n%s", stdout)
	}
}

func TestTwoFileMode_RejectsNonGoMod(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.json")
	head := filepath.Join(dir, "head.json")
	writeFile(t, base, `{"name": "package-lock", "lockfileVersion": 3}`)
	writeFile(t, head, `{"name": "package-lock", "lockfileVersion": 3}`)

	_, stderr, code := mustRun(t, []string{base, head})
	if code != 2 {
		t.Fatalf("code = %d, want 2; stderr = %s", code, stderr)
	}
	if !strings.Contains(stderr, "does not look like a go.mod") {
		t.Errorf("stderr = %s", stderr)
	}
}

func TestTwoFileMode_BaseFlagRejected(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.mod")
	head := filepath.Join(dir, "head.mod")
	writeFile(t, base, "module m\n\ngo 1.22\n")
	writeFile(t, head, "module m\n\ngo 1.22\n")

	_, stderr, code := mustRun(t, []string{"--base", "HEAD", base, head})
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "--base is not used") {
		t.Errorf("stderr = %s", stderr)
	}
}

// --- --fail-on and exit codes ---

func TestFailOn_TriggersExitCode1(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.mod")
	head := filepath.Join(dir, "head.mod")
	writeFile(t, base, "module m\n\ngo 1.22\n")
	writeFile(t, head, "module m\n\ngo 1.22\n\nreplace github.com/real/pkg => ../local/pkg\n")

	_, _, code := mustRun(t, []string{"--fail-on", "local-path", base, head})
	if code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}

	_, _, code = mustRun(t, []string{"--fail-on", "downgrade", base, head})
	if code != 0 {
		t.Fatalf("code = %d, want 0 (local-path signal shouldn't match downgrade)", code)
	}
}

func TestFailOn_DefaultNeverFails(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.mod")
	head := filepath.Join(dir, "head.mod")
	writeFile(t, base, "module m\n\ngo 1.22\n")
	writeFile(t, head, "module m\n\ngo 1.22\n\nreplace github.com/real/pkg => github.com/attacker/pkg v1.0.0\n")

	_, _, code := mustRun(t, []string{base, head})
	if code != 0 {
		t.Fatalf("code = %d, want 0 (no --fail-on given)", code)
	}
}

// --- --json ---

func TestJSONOutput(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.mod")
	head := filepath.Join(dir, "head.mod")
	writeFile(t, base, "module m\n\ngo 1.22\n")
	writeFile(t, head, "module m\n\ngo 1.22\n\nreplace github.com/real/pkg => ../local/pkg\n")

	stdout, stderr, code := mustRun(t, []string{"--json", "--fail-on", "local-path", base, head})
	if code != 1 {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	var rep jsonReport
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout)
	}
	if !rep.Failed {
		t.Errorf("Failed = false, want true")
	}
	if len(rep.Signals) == 0 {
		t.Errorf("no signals in JSON output")
	}
	found := false
	for _, s := range rep.Signals {
		for _, k := range s.Kinds {
			if k == "local-path" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("expected a local-path kind in JSON signals: %+v", rep.Signals)
	}
}

// --- --help ---

func TestHelp(t *testing.T) {
	stdout, _, code := mustRun(t, []string{"--help"})
	if code != 0 {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(stdout, "Usage:") {
		t.Errorf("stdout missing usage: %s", stdout)
	}
}

// --- git ref mode, the primary documented usage ---

func TestGitRefMode(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	run("init", "-q", "-b", "main")
	writeFile(t, filepath.Join(dir, "go.mod"), "module m\n\ngo 1.22\n\nrequire github.com/real/pkg v1.5.0\n")
	run("add", "go.mod")
	run("commit", "-q", "-m", "base")

	writeFile(t, filepath.Join(dir, "go.mod"), "module m\n\ngo 1.22\n\nrequire github.com/real/pkg v1.5.0\n\nreplace github.com/real/pkg => github.com/attacker/pkg v1.5.0\n")

	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWD)

	stdout, stderr, code := mustRun(t, []string{"--base", "main"})
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stdout, "FORK") {
		t.Errorf("expected a fork signal against git base, got:\n%s", stdout)
	}
}

// --- --base pointing at a file that exists on disk, not a git ref ---

func TestBaseAsFilePath(t *testing.T) {
	dir := t.TempDir()
	baseFile := filepath.Join(dir, "saved-base.mod")
	writeFile(t, baseFile, "module m\n\ngo 1.22\n")
	writeFile(t, filepath.Join(dir, "go.mod"), "module m\n\ngo 1.22\n\nreplace github.com/real/pkg => ../local/pkg\n")

	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWD)

	stdout, stderr, code := mustRun(t, []string{"--base", baseFile})
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stdout, "LOCAL-PATH") {
		t.Errorf("stdout = %s", stdout)
	}
}

// --- GOFLAGS is read live from the environment ---

func TestGoFlagsSignalFromEnv(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.mod")
	head := filepath.Join(dir, "head.mod")
	writeFile(t, base, "module m\n\ngo 1.22\n")
	writeFile(t, head, "module m\n\ngo 1.22\n")

	t.Setenv("GOFLAGS", "-mod=mod")
	stdout, stderr, code := mustRun(t, []string{base, head})
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stdout, "GOFLAGS") {
		t.Errorf("expected a goflags signal, got:\n%s", stdout)
	}
}
