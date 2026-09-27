package main

// The failure that looks like nothing, guarded here the way it is guarded on
// the dashboard.
//
// go.mod reaches the packages beside it through relative replaces and the image
// has to carry each of those directories. When it does not, the build fails,
// Railway keeps serving the LAST image that built, and the only symptom is that
// whatever was just shipped is not there. The health check is green throughout.

import (
	"os"
	"strings"
	"testing"
)

func TestEveryModuleTheBuildNeedsIsInTheImage(t *testing.T) {
	// Above the build context, so it is absent when this runs inside the image
	// - which is the one place the check cannot help and also the one place the
	// failure has already happened.
	docker, err := os.ReadFile("../../Dockerfile.system")
	if err != nil {
		t.Skip("not run from a checkout")
	}
	mod, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}

	for _, line := range strings.Split(string(mod), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "replace ") {
			continue
		}
		_, target, ok := strings.Cut(line, "=> ")
		if !ok {
			continue
		}
		dir := strings.TrimPrefix(strings.TrimSpace(target), "../../")
		if !strings.HasPrefix(dir, "packages/") {
			continue
		}
		if !strings.Contains(string(docker), "COPY "+dir+"/") {
			t.Fatalf("go.mod replaces %s and the image never copies it: the build will fail "+
				"and the last image that worked will keep being served.\n"+
				"Add to Dockerfile.system:  COPY %s/ /%s/", dir, dir, dir)
		}
	}
}
