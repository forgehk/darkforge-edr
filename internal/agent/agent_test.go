package agent

import (
	"errors"
	"testing"
	"time"

	"github.com/forgehk/darkforge-edr/internal/alerts"
	"github.com/forgehk/darkforge-edr/internal/proc"
	"github.com/forgehk/darkforge-edr/internal/rules"
)

type memSink struct{ got []alerts.Alert }

func (m *memSink) Emit(a alerts.Alert) error { m.got = append(m.got, a); return nil }
func (m *memSink) Close() error              { return nil }

const testRules = `
rules:
  - name: nc_listener
    severity: high
    when:
      name: ["nc"]
      cmdline_contains: ["-l"]
    tags: ["mitre:T1059"]
`

func newTestAgent(t *testing.T, tables ...[]proc.Process) (*Agent, *memSink) {
	t.Helper()
	pack, err := rules.LoadBytes([]byte(testRules))
	if err != nil {
		t.Fatal(err)
	}
	sink := &memSink{}
	a := New(pack, sink, 0)
	i := 0
	a.list = func() ([]proc.Process, error) {
		if i >= len(tables) {
			return tables[len(tables)-1], nil
		}
		t := tables[i]
		i++
		return t, nil
	}
	return a, sink
}

var (
	ncProc     = proc.Process{PID: 100, PPID: 1, Name: "nc", Cmdline: "nc -l 4444"}
	benignProc = proc.Process{PID: 101, PPID: 1, Name: "sleep", Cmdline: "sleep 10"}
)

func TestNewDefaultsInterval(t *testing.T) {
	a, _ := newTestAgent(t, nil)
	if a.Interval != time.Second {
		t.Fatalf("interval = %v, want 1s", a.Interval)
	}
}

func TestTickAlertsOnMatchOnly(t *testing.T) {
	a, sink := newTestAgent(t, []proc.Process{ncProc, benignProc})
	if err := a.tick(); err != nil {
		t.Fatal(err)
	}
	if len(sink.got) != 1 {
		t.Fatalf("got %d alerts, want 1", len(sink.got))
	}
	al := sink.got[0]
	if al.Rule != "nc_listener" || al.PID != 100 || al.Severity != "high" {
		t.Fatalf("unexpected alert: %+v", al)
	}
	if len(al.Tags) != 1 || al.Tags[0] != "mitre:T1059" {
		t.Fatalf("tags not carried over: %+v", al.Tags)
	}
}

func TestTickDoesNotRepeatAlerts(t *testing.T) {
	table := []proc.Process{ncProc}
	a, sink := newTestAgent(t, table, table, table)
	for i := 0; i < 3; i++ {
		if err := a.tick(); err != nil {
			t.Fatal(err)
		}
	}
	if len(sink.got) != 1 {
		t.Fatalf("got %d alerts across 3 ticks, want 1", len(sink.got))
	}
}

func TestTickReevaluatesReusedPID(t *testing.T) {
	// The process exits, then a new process takes the same PID.
	a, sink := newTestAgent(t,
		[]proc.Process{ncProc},
		[]proc.Process{},
		[]proc.Process{ncProc},
	)
	for i := 0; i < 3; i++ {
		if err := a.tick(); err != nil {
			t.Fatal(err)
		}
	}
	if len(sink.got) != 2 {
		t.Fatalf("got %d alerts, want 2 (PID reuse must be re-evaluated)", len(sink.got))
	}
	if len(a.seen) != 1 {
		t.Fatalf("seen has %d entries, want 1", len(a.seen))
	}
}

func TestTickReturnsListError(t *testing.T) {
	a, _ := newTestAgent(t, nil)
	want := errors.New("boom")
	a.list = func() ([]proc.Process, error) { return nil, want }
	if err := a.tick(); !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}

const parentRules = `
rules:
  - name: webserver_shell
    severity: high
    when:
      name: ["sh"]
      parent_name: ["nginx"]
`

func TestTickResolvesParentName(t *testing.T) {
	pack, err := rules.LoadBytes([]byte(parentRules))
	if err != nil {
		t.Fatal(err)
	}
	sink := &memSink{}
	a := New(pack, sink, 0)
	table := []proc.Process{
		{PID: 10, PPID: 1, Name: "nginx", Cmdline: "nginx: worker"},
		{PID: 11, PPID: 10, Name: "sh", Cmdline: "sh -c id"},    // child of nginx: alert
		{PID: 12, PPID: 1, Name: "sh", Cmdline: "sh"},           // parent init is not in the table
		{PID: 13, PPID: 999, Name: "sh", Cmdline: "sh -c true"}, // parent already exited
	}
	a.list = func() ([]proc.Process, error) { return table, nil }
	if err := a.tick(); err != nil {
		t.Fatal(err)
	}
	if len(sink.got) != 1 || sink.got[0].PID != 11 {
		t.Fatalf("expected one alert for PID 11, got %+v", sink.got)
	}
}
