// Command dfedr runs the darkforge-edr endpoint agent.
//
// It loads a YAML rule pack, polls the process table, and appends a JSON line
// to the alert log for every newly-seen process that matches a rule.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/forgehk/darkforge-edr/internal/agent"
	"github.com/forgehk/darkforge-edr/internal/alerts"
	"github.com/forgehk/darkforge-edr/internal/rules"
)

// version is the build version, overridable at link time:
//
//	go build -ldflags "-X main.version=v0.2.0" ./cmd/dfedr
var version = "dev"

const usage = `dfedr — darkforge-edr endpoint agent

Usage:
  dfedr run [flags]
  dfedr version

Flags for "run":
  --rules PATH       rule pack to load (default "rules.yaml")
  --out PATH         alert log to append to, "-" for stdout (default "alerts.jsonl")
  --interval DUR     process poll interval (default 1s)
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

// run is main's testable body: it returns the process exit code instead of
// calling os.Exit, and takes its context, arguments and streams as parameters.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}

	switch args[0] {
	case "run":
		return runAgent(ctx, args[1:], stderr)
	case "version":
		fmt.Fprintf(stdout, "dfedr %s\n", version)
		return 0
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "dfedr: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

func runAgent(ctx context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	rulesPath := fs.String("rules", "rules.yaml", "rule pack to load")
	outPath := fs.String("out", "alerts.jsonl", `alert log to append to, "-" for stdout`)
	interval := fs.Duration("interval", time.Second, "process poll interval")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *interval <= 0 {
		fmt.Fprintln(stderr, "dfedr: --interval must be positive")
		return 2
	}

	pack, err := rules.LoadFile(*rulesPath)
	if err != nil {
		fmt.Fprintf(stderr, "dfedr: %v\n", err)
		return 1
	}
	if len(pack.Rules) == 0 {
		fmt.Fprintf(stderr, "dfedr: rule pack %q has no rules\n", *rulesPath)
		return 1
	}

	sink, err := alerts.NewFileSink(*outPath)
	if err != nil {
		fmt.Fprintf(stderr, "dfedr: open alert log: %v\n", err)
		return 1
	}
	defer sink.Close()

	fmt.Fprintf(stderr, "dfedr %s: %d rules from %s, polling every %s, alerts → %s\n",
		version, len(pack.Rules), *rulesPath, *interval, *outPath)

	err = agent.New(pack, sink, *interval).Run(ctx)
	// A cancelled context is how a clean shutdown is signalled (Ctrl-C, SIGTERM).
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		fmt.Fprintf(stderr, "dfedr: %v\n", err)
		return 1
	}
	return 0
}
