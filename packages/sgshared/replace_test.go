// SPDX-License-Identifier: Apache-2.0

package sgshared

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestEveryDockerfileShipsTheModulesItReplaces stood here, and it was a good test of a
// hazard this repository no longer has.
//
// A local `replace` is invisible to `go build`, `go test` and `go vet` on a developer's
// machine — the directory is simply there. It became visible exactly once, inside a
// Docker build, where the context is whatever the Dockerfile copied:
//
//	reading /packages/sgshared/go.mod: no such file or directory
//
// Which happened: two services gained a dependency on this module and their Dockerfiles
// were not updated, so the next deploy of each failed with nothing but a build log to
// say so. The test read every Dockerfile as text and required a COPY for each replaced
// module, because Docker is not available where these tests run.
//
// There are no Dockerfiles. Nothing here is deployed as an image — what ships is an npm
// package and a set of binaries — and the services those Dockerfiles built are gone.
//
// IT DID NOT GO QUIETLY, and that is worth recording. The test refused to pass
// vacuously:
//
//	no replaced module was checked against a Dockerfile — the test passed without
//	testing anything
//
// So when the last Dockerfile was deleted it failed rather than turning green, which is
// exactly what a self-checking test should do — and the failure sat hidden for a while
// behind Go's test cache, surfacing only when an unrelated change in another package
// invalidated it. A test whose subject can be deleted should say so the moment it is.
//
// What survives is the check below: this module's `replace` directives are still worth
// keeping honest, and a cross-module dependency is still something that can be added
// without noticing. It just cannot break a deploy any more.

var replaceRe = regexp.MustCompile(`(?m)^\s*replace\s+(\S+)\s*=>\s*(\.\S*)`)

// A REPLACED MODULE HAS TO EXIST, at the path that names it.
//
// The old test's failure mode was a module missing from an image. The one that remains
// is a module missing from the REPO: a `replace ../sgpolicy` pointing at a directory
// that has been moved or deleted breaks every build of every module that declares it,
// and the error names the go.mod rather than the thing that moved.
//
// Every go.mod in the repository is read, not just this module's, because the direction
// of the dependency is not what matters — a dangling replace is the same failure
// whichever module holds it.
func TestEveryReplacedModuleIsActuallyThere(t *testing.T) {
	root := repoRoot(t)

	var mods []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", ".git", "dist", "platforms":
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == "go.mod" {
			mods = append(mods, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) == 0 {
		t.Fatal("no go.mod found anywhere — this test cannot mean anything without one")
	}

	checked := 0
	for _, mod := range mods {
		b, err := os.ReadFile(mod)
		if err != nil {
			t.Fatalf("%s: %v", mod, err)
		}
		dir := filepath.Dir(mod)
		for _, m := range replaceRe.FindAllStringSubmatch(string(b), -1) {
			module, target := m[1], m[2]
			checked++
			// Relative to the go.mod that declares it, which is how the go tool
			// resolves it.
			resolved := filepath.Join(dir, target)
			info, err := os.Stat(filepath.Join(resolved, "go.mod"))
			if err != nil {
				rel, _ := filepath.Rel(root, mod)
				t.Errorf("%s replaces %s with %s, and there is no go.mod there: %v",
					rel, module, target, err)
				continue
			}
			if info.IsDir() {
				t.Errorf("%s: %s/go.mod is a directory", mod, resolved)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no replace directive was checked — the test passed without testing anything")
	}
	t.Logf("%d replace directive(s) across %d go.mod file(s)", checked, len(mods))
}

// repoRoot walks up from this package to the directory holding .git, so the test does
// not depend on where `go test` was invoked from.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skip("not inside a git checkout, so the repository layout cannot be read")
	return ""
}

// copyPaths was the old test's reader: it kept only the COPY instructions of a
// Dockerfile, because searching the whole file let a COMMENT explaining why a COPY was
// needed satisfy the check — the comment contained the path. A test a comment can
// satisfy is not a test, and that lesson is the reason this note is here rather than
// just the deletion.
var _ = strings.TrimSpace
