// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// THE PROFILE IS A STRING, AND A STRING CAN BE READ ANYWHERE.
//
// Everything in this file generates SBPL for macOS Seatbelt, and none of it is
// behind a build tag, on purpose. Applying a profile needs macOS. Deciding what
// goes in one does not: it is path arithmetic and text.
//
// That split is not tidiness, it is the only way this code is ever checked.
// Behind //go:build darwin it compiles on one developer's machine and on no CI
// runner this project has, so a rule that denies the wrong path, or a quoting
// bug that ends the profile early and silently allows everything after it, is
// found by a macOS user at runtime or not at all. Untagged, the generator is
// built and its output asserted on every push from every platform, and the
// darwin file keeps only what genuinely needs the kernel: Launch, Preview and
// Describe.
// seatbeltProfile writes the SBPL. It returns the profile and the paths that
// made it in, which is not always every path asked for: one that does not
// exist cannot be canonicalised and is reported rather than silently dropped.
func seatbeltProfile(deny []string) (string, []string) {
	var b strings.Builder
	b.WriteString("(version 1)\n(allow default)\n")

	var got []string
	ancestors := map[string]bool{}

	for _, d := range deny {
		abs, err := filepath.Abs(d)
		if err != nil {
			continue
		}
		abs = filepath.Clean(abs)
		forms := map[string]bool{abs: true}
		// The canonical form as well as the literal one. Seatbelt matches what
		// the kernel resolves, so a symlink to the file is a way past a rule
		// written against the name the user typed.
		if real, err := filepath.EvalSymlinks(abs); err == nil {
			forms[real] = true
		}
		for f := range forms {
			b.WriteString("(deny file-read* (literal " + sbplString(f) + "))\n")
			b.WriteString("(deny file-write* (literal " + sbplString(f) + "))\n")
			b.WriteString("(deny file-read* (subpath " + sbplString(f) + "))\n")
			b.WriteString("(deny file-write* (subpath " + sbplString(f) + "))\n")
			for dir := filepath.Dir(f); dir != "/" && dir != "."; dir = filepath.Dir(dir) {
				ancestors[dir] = true
			}
		}
		got = append(got, abs)
	}

	// Resolving any path stats every directory above it, so the ancestors of a
	// denied path keep their metadata readable. Without this, denying
	// ~/game/game.c makes ~/game/readme.md unreachable as well, and the symptom
	// is an agent that cannot see files nobody protected.
	//
	// file-write-unlink on each ancestor is a second rule for the same file,
	// not a new protection. `rm` unlinks by the absolute path, which the
	// literal/subpath denies above already catch. `cd`-then-delete and
	// `find -delete` do not: both resolve the directory once and then remove
	// the entry through that open directory, so the path Seatbelt is asked to
	// check is the DIRECTORY's, not the file's, and nothing above denies that.
	// Denying file-write-unlink on the exact ancestor path closes it without
	// touching file-write-create, so a sibling can still be written through
	// the same directory - only removing something through it is refused.
	for dir := range ancestors {
		b.WriteString("(allow file-read-metadata (literal " + sbplString(dir) + "))\n")
		b.WriteString("(deny file-write-unlink (literal " + sbplString(dir) + "))\n")
	}
	return b.String(), got
}

// sbplString quotes a path for SBPL, which is a Scheme dialect.
func sbplString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// seatbeltWorkspaceProfile is the allowlist, and on this platform it is the
// honest shape: Seatbelt has a real default-deny and a real deny rule, so
// "nothing except these" is one line rather than Landlock's enumeration.
//
// `(deny default)` first, then grants. Order does not decide it, in SBPL the
// LAST matching rule wins, which is why every grant comes after the deny and
// why nothing is granted twice with different rights.
//
// process-exec is granted on the read set rather than globally: the agent has
// to run its own interpreter and the tools in /usr/bin, and it must not be able
// to execute something it just wrote outside the workspace. Inside the
// workspace it can, because a project that cannot run its own build scripts is
// not a workspace.
func seatbeltWorkspaceProfile(p Plan) (string, error) {
	ws := filepath.Clean(p.Workspace)
	if !filepath.IsAbs(ws) {
		return "", errors.New("workspace must be an absolute path, got " + p.Workspace)
	}
	if ws == "/" {
		return "", errors.New(`refusing to use "/" as a workspace: that confines nothing`)
	}
	if home, err := os.UserHomeDir(); err == nil && filepath.Clean(home) == ws {
		return "", errors.New("refusing to use the home directory as a workspace: " +
			"it contains ~/.ssh and every other project, which is what this mode exists to keep out")
	}

	var b strings.Builder
	b.WriteString("(version 1)\n(deny default)\n")

	// Without these the process cannot start, and the failure reads as the
	// sandbox being broken rather than as a missing grant: no sysctl means no
	// page size, no mach lookup means no dyld.
	b.WriteString("(allow process-fork)\n")
	b.WriteString("(allow sysctl-read)\n")
	b.WriteString("(allow mach-lookup)\n")
	b.WriteString("(allow signal (target self))\n")
	b.WriteString("(allow file-read-metadata)\n")

	// The workspace, and the canonical form of it as well: Seatbelt matches
	// what the kernel resolves, and on macOS /Users is commonly reached through
	// a symlink, so a rule written against the typed path alone can be walked
	// around.
	for _, f := range canonicalForms(ws) {
		b.WriteString("(allow file* (subpath " + sbplString(f) + "))\n")
		b.WriteString("(allow process-exec (subpath " + sbplString(f) + "))\n")
	}
	for _, d := range append(p.RuntimeWrite, DefaultRuntimeDevices()...) {
		if d == "" {
			continue
		}
		for _, f := range canonicalForms(filepath.Clean(d)) {
			b.WriteString("(allow file* (subpath " + sbplString(f) + "))\n")
		}
	}
	for _, d := range p.RuntimeRead {
		if d == "" {
			continue
		}
		for _, f := range canonicalForms(filepath.Clean(d)) {
			b.WriteString("(allow file-read* (subpath " + sbplString(f) + "))\n")
			b.WriteString("(allow process-exec (subpath " + sbplString(f) + "))\n")
		}
	}
	return b.String(), nil
}

// canonicalForms is the literal path and its realpath, deduplicated. Both are
// needed for the same reason the deny list needs both.
func canonicalForms(abs string) []string {
	out := []string{abs}
	if real, err := filepath.EvalSymlinks(abs); err == nil && real != abs {
		out = append(out, real)
	}
	return out
}