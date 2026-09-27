package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A record written by an older guard carries only ms/ts/tool/session. It has to
// read back as "not recorded" rather than as zero, or the table would report
// `paths 0` for every call made before the counts existed and send somebody
// hunting a bug that is not there.
func TestTraceSeparatesAnAbsentCountFromZero(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".eval-ring.jsonl"), []byte(
		`{"ms":41,"ts":1000,"tool":"view_file","session":"s"}`+"\n"+
			`{"ms":42,"ts":2000,"tool":"view_file","session":"s","client":"antigravity","perm":"READ","args":["AbsolutePath"],"paths":1,"cmds":0,"urls":0}`+"\n",
	), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := readTraceRing(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 records, got %d", len(got))
	}

	// Newest first.
	if got[0].TS != 2000 {
		t.Fatalf("records are not newest-first: %+v", got[0])
	}
	if got[0].Paths == nil || *got[0].Paths != 1 {
		t.Errorf("paths not read: %+v", got[0].Paths)
	}
	if got[0].Cmds == nil || *got[0].Cmds != 0 {
		t.Errorf("a recorded zero must survive as zero: %+v", got[0].Cmds)
	}
	if got[1].Paths != nil {
		t.Errorf("an old record must report paths as absent, got %v", *got[1].Paths)
	}
}

func TestTraceCountCellMakesZeroImpossibleToSkim(t *testing.T) {
	zero := 0
	three := 3

	if countCell(nil) != dim("-") {
		t.Errorf("absent should render as a dash, got %q", countCell(nil))
	}
	// Zero is the answer that explains a rule doing nothing.
	if !strings.Contains(countCell(&zero), "0") || countCell(&zero) == "0" {
		t.Errorf("zero should be highlighted, got %q", countCell(&zero))
	}
	if countCell(&three) != "3" {
		t.Errorf("a non-zero count renders plain, got %q", countCell(&three))
	}
}

func TestTraceSkipsUnparseableLinesRatherThanFailing(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".eval-ring.jsonl"), []byte(
		"not json\n"+`{"ms":1,"ts":5,"tool":"bash"}`+"\n\n",
	), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := readTraceRing(dir)
	if err != nil {
		t.Fatal(err)
	}
	// A truncated write from a killed process must not hide the records around it.
	if len(got) != 1 || got[0].Tool != "bash" {
		t.Fatalf("want the one good record, got %+v", got)
	}
}

func TestTraceReportsAMissingRingRatherThanAnEmptyTable(t *testing.T) {
	if _, err := readTraceRing(t.TempDir()); err == nil {
		t.Error("a directory with no ring must be an error, so the command can explain itself")
	}
}

// Records are matched on the cwd they CARRY, not on the ring they were filed
// in: the guard files under a hash of the directory its own process was spawned
// in, and Antigravity does not spawn its hooks in the workspace. Comparing the
// two the naive way found nothing for exactly the client this command exists
// for.
func TestTraceMatchesTheDirectoryTheCallWasMadeIn(t *testing.T) {
	for _, tc := range []struct {
		recorded, here string
		want           bool
	}{
		{"/home/u/proj", "/home/u/proj", true},
		{"/home/u/proj/", "/home/u/proj", true},
		{`C:\Users\u\proj`, "C:/Users/u/proj", true},
		{"/home/u/proj", "/home/u/other", false},
		{"/home/u/proj", "/home/u/proj/sub", false},
		// An older record carries no directory at all, and must not silently
		// match whatever directory the command happens to be run from.
		{"", "/home/u/proj", false},
		{"/", "/", true},
	} {
		if got := sameDir(tc.recorded, tc.here); got != tc.want {
			t.Errorf("sameDir(%q, %q) = %v, want %v", tc.recorded, tc.here, got, tc.want)
		}
	}
}
