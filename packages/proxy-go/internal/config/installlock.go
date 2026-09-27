package config

// The installer has to lift these locks around its own writes: a (re)install
// rewrites the very files self-protection pins read-only, and writing to a
// pinned file fails with EPERM — which is how a reinstall could report success
// while the old hook stayed on disk.
//
// The mechanism lives here, beside WriteProtectedFile, so there is exactly one
// answer to "how is a file pinned on this OS". WHICH files are protected is the
// installer's list (internal/install), because the installer is what puts them
// there.
func LockFile(file string) { lockFile(file) }

func UnlockFile(file string) { unlockFile(file) }
