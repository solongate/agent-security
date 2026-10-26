// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package install

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSourceRecordPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	want := filepath.Join(home, ".solongate", sourceRecordName)
	if got := SourceRecordPath(); got != want {
		t.Errorf("SourceRecordPath() = %q, want %q", got, want)
	}
}

func makeCheckout(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "scripts", "shell"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scripts", "shell", "install.sh"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestIsCheckout(t *testing.T) {
	dir := t.TempDir()
	if isCheckout(dir) {
		t.Error("isCheckout() = true for an empty directory")
	}

	if err := os.MkdirAll(filepath.Join(dir, "scripts", "shell"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scripts", "shell", "install.sh"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if isCheckout(dir) {
		t.Error("isCheckout() = true with only install.sh and no .git")
	}

	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !isCheckout(dir) {
		t.Error("isCheckout() = false with both install.sh and .git present")
	}
}

func TestCheckoutRootFindsAncestorCheckout(t *testing.T) {
	root := t.TempDir()
	makeCheckout(t, root)
	hooksDir := filepath.Join(root, "packages", "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hooksDir, opencodePluginName), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOLONGATE_HOOKS_DIR", hooksDir)

	gotRoot, ok := CheckoutRoot()
	if !ok {
		t.Fatal("CheckoutRoot() = false, want true")
	}
	wantAbs, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	if gotRoot != wantAbs {
		t.Errorf("CheckoutRoot() = %q, want %q", gotRoot, wantAbs)
	}
}

func TestCheckoutRootNotFoundWithoutAHookSource(t *testing.T) {
	t.Setenv("SOLONGATE_HOOKS_DIR", "")
	isolated := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(isolated); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })

	if _, ok := CheckoutRoot(); ok {
		t.Error("CheckoutRoot() = true, want false with no hook source reachable")
	}
}

func TestCheckoutRootGivesUpAfterSixLevels(t *testing.T) {
	base := t.TempDir()
	makeCheckout(t, base)

	nested := filepath.Join(base, "a", "b", "c", "d", "e", "f", "g")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, opencodePluginName), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOLONGATE_HOOKS_DIR", nested)

	if _, ok := CheckoutRoot(); ok {
		t.Error("CheckoutRoot() = true, want false: the checkout markers are 7 levels up, past the search limit")
	}
}

func TestInstalledFrom(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if _, ok := InstalledFrom(); ok {
		t.Error("InstalledFrom() = true, want false with no record file")
	}

	record := filepath.Join(home, ".solongate", sourceRecordName)
	if err := os.MkdirAll(filepath.Dir(record), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(record, []byte("  \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := InstalledFrom(); ok {
		t.Error("InstalledFrom() = true, want false with a blank record")
	}

	notCheckout := t.TempDir()
	if err := os.WriteFile(record, []byte(notCheckout+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := InstalledFrom(); ok {
		t.Error("InstalledFrom() = true, want false when the recorded path is not a checkout")
	}

	checkout := t.TempDir()
	makeCheckout(t, checkout)
	if err := os.WriteFile(record, []byte(checkout+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, ok := InstalledFrom()
	if !ok || got != checkout {
		t.Errorf("InstalledFrom() = (%q, %v), want (%q, true)", got, ok, checkout)
	}
}

func TestRecordInstallSourceWritesWhenCheckoutFound(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	root := t.TempDir()
	makeCheckout(t, root)
	hooksDir := filepath.Join(root, "packages", "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hooksDir, opencodePluginName), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOLONGATE_HOOKS_DIR", hooksDir)

	if err := os.MkdirAll(filepath.Join(home, ".solongate"), 0o755); err != nil {
		t.Fatal(err)
	}
	RecordInstallSource()

	got, ok := InstalledFrom()
	if !ok {
		t.Fatal("InstalledFrom() = false after RecordInstallSource()")
	}
	wantAbs, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	if got != wantAbs {
		t.Errorf("InstalledFrom() = %q, want %q", got, wantAbs)
	}
}

func TestRecordInstallSourceNoopWithoutACheckout(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SOLONGATE_HOOKS_DIR", "")

	isolated := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(isolated); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })

	if err := os.MkdirAll(filepath.Join(home, ".solongate"), 0o755); err != nil {
		t.Fatal(err)
	}
	RecordInstallSource()

	if Exists(SourceRecordPath()) {
		t.Error("RecordInstallSource() wrote a record file with no checkout found")
	}
}