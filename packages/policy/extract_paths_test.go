// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsContentSearchTool(t *testing.T) {
	yes := []string{"Grep", "grep", "ripgrep", "search_files", "mcp__fs__search"}
	for _, tool := range yes {
		if !IsContentSearchTool(tool) {
			t.Errorf("IsContentSearchTool(%q)=false, want true", tool)
		}
	}
	no := []string{"Bash", "Read", "Write", "WebSearch", "web_search"}
	for _, tool := range no {
		if IsContentSearchTool(tool) {
			t.Errorf("IsContentSearchTool(%q)=true, web search should not count as a content search tool", tool)
		}
	}
}

func TestExpandCommandGlobsResolvesMatchingFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.txt", "b.txt", "c.log"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := ExpandCommandGlobs(args("command", "rm *.txt"), dir)
	wantA := filepath.ToSlash(filepath.Join(dir, "a.txt"))
	wantB := filepath.ToSlash(filepath.Join(dir, "b.txt"))
	if !has(got, wantA) || !has(got, wantB) {
		t.Errorf("expected %q and %q in expanded globs, got %v", wantA, wantB, got)
	}
	wantC := filepath.ToSlash(filepath.Join(dir, "c.log"))
	if has(got, wantC) {
		t.Errorf("a non-matching extension was expanded: %v", got)
	}
}

func TestExpandCommandGlobsEscapesLiteralBrackets(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"file[1].txt", "file1.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := ExpandCommandGlobs(args("command", "rm file[1].txt"), dir)
	want := filepath.ToSlash(filepath.Join(dir, "file[1].txt"))
	if len(got) != 1 || got[0] != want {
		t.Errorf("expected only %q to be expanded, got %v", want, got)
	}
}

func TestExpandCommandGlobsIgnoresFlagsAndURLs(t *testing.T) {
	dir := t.TempDir()
	got := ExpandCommandGlobs(args("command", "curl https://evil.example/*.txt -rf"), dir)
	if len(got) != 0 {
		t.Errorf("a flag or URL token was treated as a glob: %v", got)
	}
}

func TestReadReferencedFilesReadsInterpreterTarget(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "deploy.sh")
	if err := os.WriteFile(script, []byte("echo hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, interpreter := range []string{
		"bash", "/bin/bash", "./bash", "../bin/bash",
		"node", "/usr/bin/node", "./node", "/usr/bin/python3 -u",
		"source", ".",
	} {
		t.Run(interpreter, func(t *testing.T) {
			got := ReadReferencedFiles(args("command", interpreter+" deploy.sh"), dir)
			if len(got) != 1 || got[0].Name != "deploy.sh" {
				t.Fatalf("expected deploy.sh to be read, got %+v", got)
			}
			if got[0].Content != "echo hello" {
				t.Errorf("unexpected content: %q", got[0].Content)
			}
		})
	}
}

func TestReadReferencedFilesSkipsFlagsAfterInterpreter(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "run.py")
	if err := os.WriteFile(script, []byte("print(1)"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := ReadReferencedFiles(args("command", "python3 -u run.py"), dir)
	if len(got) != 1 || got[0].Name != "run.py" {
		t.Fatalf("expected run.py to be found past the -u flag, got %+v", got)
	}
}

func TestReadReferencedFilesIgnoresMissingOrOversizedFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "oversized.sh"), make([]byte, 65537), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"does-not-exist.sh", "oversized.sh"} {
		t.Run(name, func(t *testing.T) {
			if got := ReadReferencedFiles(args("command", "/bin/bash "+name), dir); len(got) != 0 {
				t.Errorf("an unreadable referenced file was reported as read: %+v", got)
			}
		})
	}
}

func TestReadReferencedFilesArgumentsDoNotExhaustLimit(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.sh", "b.sh", "c.sh", "deploy.sh"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("echo hello"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, command := range []string{
		"echo /bin/bash a.sh ./node b.sh /usr/bin/python3 c.sh; /bin/bash deploy.sh",
		"echo bash a.sh node b.sh python3 c.sh && ./bash deploy.sh",
		"echo '; /bin/bash a.sh; ./node b.sh; python3 c.sh'; /bin/bash deploy.sh",
		"echo \"; /bin/bash a.sh; ./node b.sh; python3 c.sh\"; /bin/bash deploy.sh",
		"echo ignored # /bin/bash a.sh; ./node b.sh; python3 c.sh\n/bin/bash deploy.sh",
		"echo ignored > /bin/bash a.sh > ./node b.sh > /usr/bin/python3 c.sh; /bin/bash deploy.sh",
		"cat <<'EOF'\n/bin/bash a.sh; ./node b.sh; python3 c.sh\nEOF\n/bin/bash deploy.sh",
		"sudo -u /bin/bash a.sh; sudo -u ./node b.sh; sudo -u python3 c.sh; /bin/bash deploy.sh",
	} {
		t.Run(command, func(t *testing.T) {
			got := ReadReferencedFiles(args("command", command), dir)
			if len(got) != 1 || got[0].Name != "deploy.sh" {
				t.Fatalf("expected only the actual script to be read, got %+v", got)
			}
		})
	}
}

func TestReadReferencedFilesCommandPositions(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "deploy script.sh"), []byte("echo hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		`'/bin/bash' 'deploy script.sh'`,
		`"/bin/bash" "deploy script.sh"`,
		`/bin/ba\sh deploy\ script.sh`,
		`MODE=test /bin/bash 'deploy script.sh'`,
		`env -i MODE=test /bin/bash 'deploy script.sh'`,
		`sudo -u root /bin/bash 'deploy script.sh'`,
		`sudo --user=root /bin/bash 'deploy script.sh'`,
		`command -p /bin/bash 'deploy script.sh'`,
		`exec -a shell /bin/bash 'deploy script.sh'`,
		`nohup /bin/bash 'deploy script.sh'`,
		`true && /bin/bash 'deploy script.sh'`,
		`false || /bin/bash 'deploy script.sh'`,
		`echo hello | /bin/bash 'deploy script.sh'`,
		`(/bin/bash 'deploy script.sh')`,
		`if true; then /bin/bash 'deploy script.sh'; fi`,
		`>/dev/null /bin/bash 'deploy script.sh'`,
		`echo "$(/bin/bash 'deploy script.sh')"`,
		"true\n/bin/bash 'deploy script.sh'",
	} {
		t.Run(command, func(t *testing.T) {
			got := ReadReferencedFiles(args("command", command), dir)
			if len(got) != 1 || got[0].Name != "deploy script.sh" {
				t.Fatalf("expected the script at the command position to be read, got %+v", got)
			}
		})
	}
}

func TestReadReferencedFilesInvalidFilesDoNotExhaustLimit(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "oversized.sh"), make([]byte, 65537), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "limit.sh"), make([]byte, 65536), 0o644); err != nil {
		t.Fatal(err)
	}
	command := "/bin/bash missing.sh; /bin/bash oversized.sh; /bin/bash missing-too.sh; /bin/bash limit.sh"
	got := ReadReferencedFiles(args("command", command), dir)
	if len(got) != 1 || got[0].Name != "limit.sh" || len(got[0].Content) != 65536 {
		t.Fatalf("expected the size-limit script after invalid files to be read, got %d files", len(got))
	}
}

func TestExpandSearchRootsWalksDirectoryForContentSearchTools(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "needle.go"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	skipDir := filepath.Join(dir, "node_modules")
	if err := os.MkdirAll(skipDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skipDir, "ignored.js"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := ExpandSearchRoots("Grep", args("pattern", "x", "path", dir), "")
	wantPath := filepath.ToSlash(filepath.Join(dir, "needle.go"))
	if !has(got, wantPath) {
		t.Errorf("expected %q to be walked into, got %v", wantPath, got)
	}
	for _, p := range got {
		if filepath.Base(filepath.Dir(p)) == "node_modules" {
			t.Errorf("a skip-listed directory was walked into: %q", p)
		}
	}
}

func TestExpandSearchRootsIgnoredForNonSearchTools(t *testing.T) {
	dir := t.TempDir()
	if got := ExpandSearchRoots("Bash", args("path", dir), ""); len(got) != 0 {
		t.Errorf("a non-search tool had its paths walked: %v", got)
	}
}
