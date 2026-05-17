// Package alerts is the alert sink — writes alerts to JSON lines on disk.
package alerts

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// Alert is one record emitted by the rule engine.
type Alert struct {
	Timestamp string   `json:"ts"`
	Rule      string   `json:"rule"`
	Severity  string   `json:"severity"`
	PID       int      `json:"pid"`
	PPID      int      `json:"ppid"`
	Name      string   `json:"name"`
	Cmdline   string   `json:"cmdline"`
	Host      string   `json:"host,omitempty"`
	Tags      []string `json:"tags,omitempty"`
}

// Sink writes alerts somewhere (file, network, stdout).
type Sink interface {
	io.Closer
	Emit(Alert) error
}

// NewFileSink returns a Sink that appends JSON lines to `path`.
// Pass "-" for stdout.
func NewFileSink(path string) (Sink, error) {
	if path == "-" {
		return &fileSink{w: nopCloser{os.Stdout}}, nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &fileSink{w: f}, nil
}

type fileSink struct {
	mu sync.Mutex
	w  io.WriteCloser
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

func (s *fileSink) Emit(a Alert) error {
	if a.Timestamp == "" {
		a.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(a); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.w.Write(buf.Bytes())
	return err
}

func (s *fileSink) Close() error {
	return s.w.Close()
}
