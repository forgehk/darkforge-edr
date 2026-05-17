// Package agent ties the collector, rule engine, and sink together.
package agent

import (
	"context"
	"os"
	"time"

	"github.com/forgehk/darkforge-edr/internal/alerts"
	"github.com/forgehk/darkforge-edr/internal/proc"
	"github.com/forgehk/darkforge-edr/internal/rules"
)

// Agent is the core polling loop.
type Agent struct {
	Pack     *rules.Pack
	Sink     alerts.Sink
	Interval time.Duration
	Host     string

	seen map[int]struct{}
}

// New constructs an agent. Interval defaults to 1s if zero.
func New(pack *rules.Pack, sink alerts.Sink, interval time.Duration) *Agent {
	if interval == 0 {
		interval = time.Second
	}
	host, _ := os.Hostname()
	return &Agent{
		Pack:     pack,
		Sink:     sink,
		Interval: interval,
		Host:     host,
		seen:     map[int]struct{}{},
	}
}

// Run blocks until ctx is cancelled, polling processes and emitting alerts
// for any newly-seen process that matches a rule.
func (a *Agent) Run(ctx context.Context) error {
	ticker := time.NewTicker(a.Interval)
	defer ticker.Stop()
	if err := a.tick(); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := a.tick(); err != nil {
				return err
			}
		}
	}
}

func (a *Agent) tick() error {
	procs, err := proc.List()
	if err != nil {
		return err
	}
	currentPIDs := make(map[int]struct{}, len(procs))
	for _, p := range procs {
		currentPIDs[p.PID] = struct{}{}
		if _, alreadySeen := a.seen[p.PID]; alreadySeen {
			continue
		}
		a.seen[p.PID] = struct{}{}
		// Evaluate rules against the new process.
		hits := a.Pack.Match(rules.Process{
			PID: p.PID, PPID: p.PPID, Name: p.Name, Cmdline: p.Cmdline,
		})
		for _, hit := range hits {
			_ = a.Sink.Emit(alerts.Alert{
				Rule:     hit.Name,
				Severity: string(hit.Severity),
				PID:      p.PID, PPID: p.PPID,
				Name: p.Name, Cmdline: p.Cmdline,
				Host: a.Host,
				Tags: hit.Tags,
			})
		}
	}
	// Drop exited PIDs from the seen set so PID re-use later will re-evaluate.
	for pid := range a.seen {
		if _, alive := currentPIDs[pid]; !alive {
			delete(a.seen, pid)
		}
	}
	return nil
}
