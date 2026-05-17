package proc

import "testing"

func TestParseStatBasic(t *testing.T) {
	stat := "12031 (bash) S 1248 12031 12031 34816 12095 4194304 ..."
	name, ppid := parseStat(stat)
	if name != "bash" {
		t.Errorf("name = %q; want bash", name)
	}
	if ppid != 1248 {
		t.Errorf("ppid = %d; want 1248", ppid)
	}
}

func TestParseStatCommWithSpaces(t *testing.T) {
	// comm field can contain spaces.
	stat := "999 (chrome browser) S 200 999 ..."
	name, ppid := parseStat(stat)
	if name != "chrome browser" {
		t.Errorf("name = %q; want 'chrome browser'", name)
	}
	if ppid != 200 {
		t.Errorf("ppid = %d; want 200", ppid)
	}
}

func TestParseStatCommWithParens(t *testing.T) {
	// comm can also contain parentheses; we use LastIndexByte to find the close.
	stat := "42 (some (weird) name) S 1 ..."
	name, ppid := parseStat(stat)
	if name != "some (weird) name" {
		t.Errorf("name = %q; want 'some (weird) name'", name)
	}
	if ppid != 1 {
		t.Errorf("ppid = %d; want 1", ppid)
	}
}

func TestParseStatMalformed(t *testing.T) {
	name, ppid := parseStat("garbage")
	if name != "" || ppid != 0 {
		t.Errorf("malformed input should return zero values; got name=%q ppid=%d", name, ppid)
	}
}
