// Package rules implements the YAML rule format and matching engine.
package rules

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Severity is a coarse risk level: low / medium / high / critical.
type Severity string

const (
	Low      Severity = "low"
	Medium   Severity = "medium"
	High     Severity = "high"
	Critical Severity = "critical"
)

// Process is the minimal shape a rule cares about.
// Defined here too so the rules package doesn't import proc (decoupled).
type Process struct {
	PID     int
	PPID    int
	Name    string
	Cmdline string
}

// Rule is one detection rule.
type Rule struct {
	Name     string   `yaml:"name"`
	Severity Severity `yaml:"severity"`
	When     When     `yaml:"when"`
	Tags     []string `yaml:"tags"`

	// Compiled regex cache (populated by Compile).
	compiledRegex []*regexp.Regexp
}

// When is the match clause.
type When struct {
	Name            []string `yaml:"name"`
	CmdlineContains []string `yaml:"cmdline_contains"`
	CmdlineRegex    []string `yaml:"cmdline_regex"`
}

// Pack is the top-level rule pack document.
type Pack struct {
	Rules []Rule `yaml:"rules"`
}

// LoadFile reads a YAML rule pack from disk and compiles regexes.
func LoadFile(path string) (*Pack, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules %q: %w", path, err)
	}
	return LoadBytes(b)
}

// LoadBytes parses + compiles a rule pack from a YAML byte slice.
func LoadBytes(b []byte) (*Pack, error) {
	var pack Pack
	if err := yaml.Unmarshal(b, &pack); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	for i := range pack.Rules {
		r := &pack.Rules[i]
		if r.Severity == "" {
			r.Severity = Medium
		}
		for _, pat := range r.When.CmdlineRegex {
			re, err := regexp.Compile(pat)
			if err != nil {
				return nil, fmt.Errorf("rule %q: invalid regex %q: %w", r.Name, pat, err)
			}
			r.compiledRegex = append(r.compiledRegex, re)
		}
	}
	return &pack, nil
}

// Match returns all rules that match the given process.
func (p *Pack) Match(proc Process) []*Rule {
	var hits []*Rule
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.matches(proc) {
			hits = append(hits, r)
		}
	}
	return hits
}

func (r *Rule) matches(p Process) bool {
	// All non-empty clauses are ANDed.
	if len(r.When.Name) > 0 && !anyEqualFold(r.When.Name, p.Name) {
		return false
	}
	if len(r.When.CmdlineContains) > 0 && !anyContains(r.When.CmdlineContains, p.Cmdline) {
		return false
	}
	if len(r.compiledRegex) > 0 && !anyMatch(r.compiledRegex, p.Cmdline) {
		return false
	}
	// If a rule has *no* when clauses, treat as non-matching to avoid
	// accidental match-everything rules.
	if len(r.When.Name) == 0 && len(r.When.CmdlineContains) == 0 && len(r.compiledRegex) == 0 {
		return false
	}
	return true
}

func anyEqualFold(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}

func anyContains(needles []string, haystack string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}

func anyMatch(res []*regexp.Regexp, s string) bool {
	for _, r := range res {
		if r.MatchString(s) {
			return true
		}
	}
	return false
}
