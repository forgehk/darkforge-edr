package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A rule that matches the test binary itself, so a live poll produces an alert.
const testPack = `
rules:
  - name: dfedr_self_test
    severity: low
    when:
      cmdline_contains: ["dfedr"]
    tags: ["self-test"]
`

func writePack(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNoArgsPrintsUsage(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), nil, &out, &errOut); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "Usage:") {
		t.Errorf("usage not printed, got %q", errOut.String())
	}
}

func TestUnknownCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"bogus"}, &out, &errOut); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), `unknown command "bogus"`) {
		t.Errorf("error not reported, got %q", errOut.String())
	}
}

func TestVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"version"}, &out, &errOut); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.HasPrefix(out.String(), "dfedr ") {
		t.Errorf("version not printed, got %q", out.String())
	}
}

func TestHelp(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"--help"}, &out, &errOut); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "Usage:") {
		t.Errorf("usage not printed, got %q", out.String())
	}
}

func TestRunMissingRulePack(t *testing.T) {
	var out, errOut bytes.Buffer
	args := []string{"run", "--rules", filepath.Join(t.TempDir(), "absent.yaml")}
	if code := run(context.Background(), args, &out, &errOut); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), "read rules") {
		t.Errorf("error not reported, got %q", errOut.String())
	}
}

func TestRunEmptyRulePack(t *testing.T) {
	var out, errOut bytes.Buffer
	args := []string{"run", "--rules", writePack(t, "rules: []\n")}
	if code := run(context.Background(), args, &out, &errOut); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), "no rules") {
		t.Errorf("error not reported, got %q", errOut.String())
	}
}

func TestRunRejectsNonPositiveInterval(t *testing.T) {
	var out, errOut bytes.Buffer
	args := []string{"run", "--rules", writePack(t, testPack), "--interval", "0"}
	if code := run(context.Background(), args, &out, &errOut); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "--interval must be positive") {
		t.Errorf("error not reported, got %q", errOut.String())
	}
}

// A cancelled context is a clean shutdown, not an error: Ctrl-C should exit 0.
func TestRunExitsCleanlyWhenContextIsCancelled(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "alerts.jsonl")
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	var out, errOut bytes.Buffer
	args := []string{
		"run",
		"--rules", writePack(t, testPack),
		"--out", outPath,
		"--interval", "20ms",
	}
	if code := run(ctx, args, &out, &errOut); code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "1 rules") {
		t.Errorf("startup banner missing, got %q", errOut.String())
	}
}

// The end-to-end path: poll, match a rule, append a JSON line to the alert log.
func TestRunWritesJSONLinesToTheAlertLog(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "alerts.jsonl")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	var out, errOut bytes.Buffer
	args := []string{
		"run",
		"--rules", writePack(t, testPack),
		"--out", outPath,
		"--interval", "20ms",
	}
	if code := run(ctx, args, &out, &errOut); code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, errOut.String())
	}

	body, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("alert log not written: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		t.Fatal("no alerts written; the self-test rule should match this process")
	}
	var alert struct {
		Timestamp string   `json:"ts"`
		Rule      string   `json:"rule"`
		Severity  string   `json:"severity"`
		PID       int      `json:"pid"`
		Tags      []string `json:"tags"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &alert); err != nil {
		t.Fatalf("alert line is not JSON: %v (%q)", err, lines[0])
	}
	if alert.Rule != "dfedr_self_test" {
		t.Errorf("rule = %q, want dfedr_self_test", alert.Rule)
	}
	if alert.Severity != "low" {
		t.Errorf("severity = %q, want low", alert.Severity)
	}
	if alert.PID == 0 || alert.Timestamp == "" {
		t.Errorf("alert missing pid/ts: %+v", alert)
	}
}
