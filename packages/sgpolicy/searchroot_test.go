package sgpolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A grep-style tool names a search ROOT and a query, never the files whose
// contents come back. Measured on Antigravity: `view_file` on a denied path was
// refused and `grep_search` rooted at the workspace returned the same file's
// contents one refusal later.
func TestSearchRootStandsInForTheFilesItWouldReturn(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "data", "orders.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := ExpandSearchRoots("grep_search", map[string]interface{}{
		"SearchPath": root, "Query": "orders", "IsRegex": false,
	}, root)

	found := false
	for _, p := range got {
		if strings.HasSuffix(p, "/data/orders.json") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the file the search would return is not among the paths: %v", got)
	}
}

func TestSearchExpansionOnlyAppliesToSearchTools(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "a.txt"), []byte("x"), 0o644)

	if got := ExpandSearchRoots("view_file", map[string]interface{}{"file_path": root}, root); len(got) != 0 {
		t.Errorf("a read tool must not be walked: %v", got)
	}
	// websearch reaches the network, not the disk.
	if got := ExpandSearchRoots("websearch", map[string]interface{}{"query": root}, root); len(got) != 0 {
		t.Errorf("websearch must not be walked: %v", got)
	}
	if !IsContentSearchTool("grep_search") || !IsContentSearchTool("Grep") {
		t.Error("grep tools must be recognised")
	}
	if IsContentSearchTool("web_search") {
		t.Error("web_search must not be")
	}
}

// Every bound fails OPEN: this layer is hardening on top of the literal match,
// never the thing standing between a call and a decision.
func TestSearchExpansionIsBoundedAndNeverErrors(t *testing.T) {
	root := t.TempDir()
	deep := root
	for i := 0; i < 20; i++ {
		deep = filepath.Join(deep, "d")
	}
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(deep, "buried.txt"), []byte("x"), 0o644)
	_ = os.MkdirAll(filepath.Join(root, "node_modules", "pkg"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "node_modules", "pkg", "index.js"), []byte("x"), 0o644)

	got := ExpandSearchRoots("grep_search", map[string]interface{}{"SearchPath": root}, root)
	for _, p := range got {
		if strings.Contains(p, "node_modules") {
			t.Errorf("node_modules was walked: %s", p)
		}
		if strings.Count(p, "/d/") > searchWalkMaxDepth {
			t.Errorf("walked past the depth bound: %s", p)
		}
	}
	// A path that does not exist is simply not expanded, not an error.
	if got := ExpandSearchRoots("grep_search", map[string]interface{}{"SearchPath": "/no/such/dir"}, root); len(got) != 0 {
		t.Errorf("a missing root must expand to nothing: %v", got)
	}
}
