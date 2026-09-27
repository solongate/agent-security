package auditscan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// The extra log directories a user has added live in ~/.solongate-audit, NOT in
// ~/.solongate. That is not tidy, but the npm tool writes there today and both
// implementations are installable at once: moving the file would make the two
// disagree about which directories are being scanned, and the disagreement
// would look like "the audit stopped seeing my logs".

func configDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.Getenv("HOME")
	}
	return filepath.Join(home, ".solongate-audit")
}

func configFile() string { return filepath.Join(configDir(), "config.json") }

type Config struct {
	CustomDirs []string `json:"customDirs"`
}

// LoadConfig never fails. A config file that will not parse means "no custom
// directories", the same answer as no file at all: the default locations are
// always scanned, so a corrupt file degrades the scan rather than stopping it.
func LoadConfig() Config {
	b, err := os.ReadFile(configFile())
	if err != nil {
		return Config{CustomDirs: []string{}}
	}
	var c Config
	if json.Unmarshal(b, &c) != nil {
		return Config{CustomDirs: []string{}}
	}
	if c.CustomDirs == nil {
		c.CustomDirs = []string{}
	}
	return c
}

func saveConfig(c Config) error {
	if err := os.MkdirAll(configDir(), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configFile(), b, 0o644)
}

func absPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	return abs
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// AddDir records a directory to scan alongside the built-in locations.
//
// A directory that does not exist yet is still added, deliberately: people add
// the path before the tool that writes there has run once, and refusing would
// send them back to do it again later.
func AddDir(dir string) {
	abs := absPath(dir)
	cfg := LoadConfig()
	for _, d := range cfg.CustomDirs {
		if d == abs {
			fmt.Printf("  Already added: %s\n", abs)
			return
		}
	}
	if !exists(abs) {
		fmt.Printf("  Warning: directory does not exist: %s\n", abs)
		fmt.Print("  Adding anyway — it may appear later.\n\n")
	}
	cfg.CustomDirs = append(cfg.CustomDirs, abs)
	if err := saveConfig(cfg); err != nil {
		fmt.Printf("  Could not save the config: %v\n", err)
		return
	}
	fmt.Printf("  Added: %s\n", abs)
	fmt.Printf("  Total custom dirs: %d\n\n", len(cfg.CustomDirs))
}

// RemoveDir drops a directory. An exact path wins; failing that a substring
// match is accepted, so a long path can be removed by the part of it the user
// remembers.
func RemoveDir(dir string) {
	abs := absPath(dir)
	cfg := LoadConfig()
	idx := -1
	for i, d := range cfg.CustomDirs {
		if d == abs {
			idx = i
			break
		}
	}
	if idx == -1 {
		for i, d := range cfg.CustomDirs {
			if strings.Contains(d, dir) {
				match := d
				cfg.CustomDirs = append(cfg.CustomDirs[:i], cfg.CustomDirs[i+1:]...)
				if err := saveConfig(cfg); err != nil {
					fmt.Printf("  Could not save the config: %v\n", err)
					return
				}
				fmt.Printf("  Removed: %s\n", match)
				fmt.Printf("  Remaining: %d\n\n", len(cfg.CustomDirs))
				return
			}
		}
		fmt.Printf("  Not found: %s\n", abs)
		fmt.Print("  Use --list-dirs to see saved directories.\n\n")
		return
	}
	cfg.CustomDirs = append(cfg.CustomDirs[:idx], cfg.CustomDirs[idx+1:]...)
	if err := saveConfig(cfg); err != nil {
		fmt.Printf("  Could not save the config: %v\n", err)
		return
	}
	fmt.Printf("  Removed: %s\n", abs)
	fmt.Printf("  Remaining: %d\n\n", len(cfg.CustomDirs))
}

// defaultLocation is one built-in transcript directory, in the display order
// the tool has always listed them in.
type defaultLocation struct {
	Name string
	Path string
}

func defaultLocations(home string) []defaultLocation {
	return []defaultLocation{
		{"Claude Code", filepath.Join(home, ".claude", "projects")},
		{"Codex", filepath.Join(home, ".codex", "sessions")},
		{"Antigravity", filepath.Join(home, ".gemini", "antigravity", "brain")},
		{"OpenClaw", filepath.Join(home, ".openclaw", "agents", "main", "sessions")},
	}
}

func homeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.Getenv("HOME")
	}
	return home
}

func ListDirs() {
	cfg := LoadConfig()
	home := homeDir()

	fmt.Print("\n  Default log directories:\n")
	fmt.Printf("    Claude Code  → %s\n", filepath.Join(home, ".claude", "projects"))
	fmt.Printf("    Codex        → %s\n", filepath.Join(home, ".codex", "sessions"))
	fmt.Printf("    Antigravity  → %s\n", filepath.Join(home, ".gemini", "antigravity", "brain"))
	fmt.Printf("    OpenClaw     → %s\n", filepath.Join(home, ".openclaw", "agents", "main", "sessions"))

	if len(cfg.CustomDirs) == 0 {
		fmt.Print("\n  Custom directories: (none)\n")
	} else {
		fmt.Printf("\n  Custom directories (%d):\n", len(cfg.CustomDirs))
		for _, d := range cfg.CustomDirs {
			if exists(d) {
				fmt.Printf("    + %s\n", d)
			} else {
				fmt.Printf("    - %s (not found)\n", d)
			}
		}
	}

	fmt.Printf("\n  Config: %s\n\n", configFile())
}

// SearchLogs looks for transcript directories, including under other user
// accounts on the machine. It only reports; nothing is added without the user
// running --add-dir, because the paths it turns up may belong to someone else.
func SearchLogs() {
	home := homeDir()
	var found []string

	fmt.Print("\n  Searching for AI tool logs...\n\n")

	for _, d := range defaultLocations(home) {
		if exists(d.Path) {
			fmt.Printf("  Found %s: %s\n", d.Name, d.Path)
			found = append(found, d.Path)
		}
	}

	if runtime.GOOS == "windows" {
		usersDir := filepath.Dir(home)
		entries, err := os.ReadDir(usersDir)
		if err == nil {
			for _, e := range entries {
				userHome := filepath.Join(usersDir, e.Name())
				if userHome == home {
					continue
				}
				info, err := os.Stat(userHome)
				if err != nil || !info.IsDir() {
					continue
				}
				for _, d := range defaultLocations(userHome) {
					if exists(d.Path) {
						fmt.Printf("  Found %s (%s): %s\n", d.Name, e.Name(), d.Path)
						found = append(found, d.Path)
					}
				}
			}
		}
	} else {
		for _, baseDir := range []string{"/home", "/Users"} {
			if !exists(baseDir) {
				continue
			}
			entries, err := os.ReadDir(baseDir)
			if err != nil {
				continue
			}
			for _, e := range entries {
				userHome := filepath.Join(baseDir, e.Name())
				if userHome == home {
					continue
				}
				for _, d := range defaultLocations(userHome) {
					if exists(d.Path) {
						fmt.Printf("  Found %s (%s): %s\n", d.Name, e.Name(), d.Path)
						found = append(found, d.Path)
					}
				}
			}
		}
	}

	if len(found) == 0 {
		fmt.Print("  No AI tool logs found.\n\n")
		return
	}
	fmt.Printf("\n  Found %d log location(s).\n", len(found))
	fmt.Print("  Default locations are scanned automatically.\n")
	fmt.Print("  To add a non-default location: npx solongate-audit --add-dir <path>\n\n")
}
