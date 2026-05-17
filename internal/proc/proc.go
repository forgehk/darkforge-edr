// Package proc enumerates running processes.
//
// Linux: reads /proc directly. macOS/Windows: stub for now, contribution welcome.
package proc

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Process describes a single running process.
type Process struct {
	PID     int
	PPID    int
	Name    string
	Cmdline string
}

// List returns a snapshot of currently running processes.
func List() ([]Process, error) {
	return listLinux()
}

func listLinux() ([]Process, error) {
	if _, err := os.Stat("/proc"); err != nil {
		return nil, errors.New("proc: /proc not available (non-Linux host)")
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	out := make([]Process, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // non-numeric, not a PID dir
		}
		p, err := readProcess(pid)
		if err != nil {
			continue // process exited between listing and reading; skip
		}
		out = append(out, p)
	}
	return out, nil
}

func readProcess(pid int) (Process, error) {
	root := filepath.Join("/proc", strconv.Itoa(pid))
	stat, err := os.ReadFile(filepath.Join(root, "stat"))
	if err != nil {
		return Process{}, err
	}
	name, ppid := parseStat(string(stat))
	cmdRaw, _ := os.ReadFile(filepath.Join(root, "cmdline"))
	// /proc/[pid]/cmdline uses NUL separators; replace with spaces.
	cmdline := strings.TrimSpace(strings.ReplaceAll(string(cmdRaw), "\x00", " "))
	if cmdline == "" {
		cmdline = name
	}
	return Process{PID: pid, PPID: ppid, Name: name, Cmdline: cmdline}, nil
}

// parseStat extracts the comm and ppid from /proc/[pid]/stat.
// Format: "PID (comm) state PPID ..." — comm can contain spaces and parens.
func parseStat(s string) (name string, ppid int) {
	open := strings.IndexByte(s, '(')
	close := strings.LastIndexByte(s, ')')
	if open < 0 || close < 0 || close < open {
		return "", 0
	}
	name = s[open+1 : close]
	rest := strings.TrimSpace(s[close+1:])
	fields := strings.Fields(rest)
	if len(fields) >= 2 {
		ppid, _ = strconv.Atoi(fields[1])
	}
	return name, ppid
}
