package sgshared

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Anything that depends on this module has to SHIP it.
//
// A local `replace` is invisible to `go build` on a developer's machine — the
// directory is simply there — and invisible to `go test`, and invisible to
// `go vet`. It becomes visible exactly once: inside a Docker build, where the
// context is whatever the Dockerfile copied, and `go mod download` fails with
//
//	reading /packages/sgshared/go.mod: no such file or directory
//
// That is not hypothetical. auth-go and manage-go gained a dependency on this
// module in da61f772 and their Dockerfiles were not updated, so the next deploy
// of each failed. Railway kept the previous image, so nothing went down, but the
// change did not land either and the only signal was a build log.
//
// Nothing else in this repo can catch it: Docker is not available in the
// environment the tests run in, so there is no build to run. This test reads the
// Dockerfile as text instead, which is enough — the failure is always a missing
// COPY, never a subtle one.

var replaceRe = regexp.MustCompile(`(?m)^\s*replace\s+(\S+)\s*=>\s*(\.\S*)`)

// copyPaths returns just the COPY instructions of a Dockerfile, joined.
//
// Searching the whole file was the first version and it did not work: this
// test's own negative control passed, because the COMMENT explaining why the
// COPY is needed contains the path the COPY would name. A test that a comment
// can satisfy is not a test. Only instructions count.
func copyPaths(dockerfile string) string {
	var out []string
	for _, line := range strings.Split(dockerfile, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(line), "COPY ") {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

// dockerfileFor maps a module directory to the Dockerfile that builds it.
// Modules with no Dockerfile are not deployed as their own image and are
// skipped rather than reported.
func dockerfileFor(repo, moduleDir string) string {
	name := "Dockerfile." + filepath.Base(moduleDir)
	p := filepath.Join(repo, name)
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}

func TestEveryDockerfileShipsTheModulesItReplaces(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}

	var modules []string
	for _, group := range []string{"apps", "packages"} {
		entries, err := os.ReadDir(filepath.Join(repo, group))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			dir := filepath.Join(repo, group, e.Name())
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				modules = append(modules, dir)
			}
		}
	}
	if len(modules) == 0 {
		t.Fatal("found no Go modules — this test is not looking where it thinks it is")
	}

	checked := 0
	for _, dir := range modules {
		gomod, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err != nil {
			continue
		}
		matches := replaceRe.FindAllStringSubmatch(string(gomod), -1)
		if len(matches) == 0 {
			continue
		}
		dockerfile := dockerfileFor(repo, dir)
		if dockerfile == "" {
			continue // not built as its own image
		}
		body, err := os.ReadFile(dockerfile)
		if err != nil {
			t.Errorf("%s: %v", dockerfile, err)
			continue
		}
		copies := copyPaths(string(body))

		for _, m := range matches {
			module, rel := m[1], m[2]
			// The replaced directory, repo-relative — which is the path a COPY
			// in a repo-root build context has to name.
			abs := filepath.Clean(filepath.Join(dir, rel))
			want, err := filepath.Rel(repo, abs)
			if err != nil {
				t.Errorf("%s: cannot make %s repo-relative: %v", dir, abs, err)
				continue
			}
			checked++
			if !strings.Contains(copies, want) {
				t.Errorf("%s replaces %s with %s, but %s never COPYs %s.\n"+
					"`go mod download` reads the replaced module's go.mod, so the build fails at that step.\n"+
					"Add, BEFORE the go.mod COPY:\n\n    COPY %s/ /%s/\n",
					filepath.Base(dir), module, rel, filepath.Base(dockerfile), want, want, want)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no replaced module was checked against a Dockerfile — the test passed without testing anything")
	}
	t.Logf("checked %d local replace(s) across %d module(s)", checked, len(modules))
}
