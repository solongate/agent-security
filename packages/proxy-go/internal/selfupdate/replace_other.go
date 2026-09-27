//go:build !windows

package selfupdate

// On POSIX a running executable can be unlinked and replaced while it runs: the
// kernel keeps the old inode alive for the running image and the new file simply
// takes the name. npm's install needs no help here, so staging would only add a
// way to fail.
func stageRunningExecutable() (restore func()) { return func() {} }

// SweepStagedReplacements exists so the caller does not have to know which
// platform it is on. Nothing is ever staged here, so there is nothing to sweep.
func SweepStagedReplacements() {}
