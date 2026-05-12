// Package config — coverage_test.go
//
// Per post-v2.1.0 anti-rot item 1 (Auditable Codebase Bundle).
//
// Catches "lying env vars" — CERTCTL_* env vars read by config.go that
// have no consumer in the rest of the codebase. Companion to the
// scripts/ci-guards/complete-path-config-coverage.sh shell guard: the
// shell guard catches non-Go consumers too (Helm, .env templates,
// docs); this Go test runs under `go test -short` and gives developers
// the same signal in the same loop they're already in.
//
// Allowlist is the same YAML file used by the shell guard. Keep them in
// sync — a row added here should be added there, and vice versa.

package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// envVarRe matches getEnv* call sites that take a CERTCTL_-prefixed
// string literal as their first argument. Mirrors the regex in
// scripts/ci-guards/complete-path-config-coverage.sh.
var envVarRe = regexp.MustCompile(`getEnv(?:Bool|Int|Int64|Duration|Float|StringSlice)?\(\s*"(CERTCTL_[A-Z0-9_]+)"`)

// allowlistEntry is the shape of a row in
// scripts/ci-guards/complete-path-config-coverage-exceptions.yaml.
type allowlistEntry struct {
	Name          string
	Justification string
	Expires       time.Time
}

func TestCompletePathConfigCoverage(t *testing.T) {
	// Find repo root by walking up from this file's dir until we hit
	// go.mod.
	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatalf("find repo root: %v", err)
	}

	// 1. Extract env-var read sites from internal/config/config.go.
	configBytes, err := os.ReadFile(filepath.Join(repoRoot, "internal", "config", "config.go"))
	if err != nil {
		t.Fatalf("read config.go: %v", err)
	}
	envVars := map[string]struct{}{}
	for _, m := range envVarRe.FindAllStringSubmatch(string(configBytes), -1) {
		envVars[m[1]] = struct{}{}
	}
	if len(envVars) == 0 {
		t.Fatal("regex matched zero env vars — likely a regex/format change, fix the test")
	}

	// 2. Walk the rest of the repo looking for consumers.
	searchDirs := []string{
		"cmd", "internal", "deploy", "migrations", "scripts", "docs",
		"api", "web",
	}
	searchFiles := []string{"Makefile", "README.md", "CHANGELOG.md"}

	consumed := map[string]bool{}
	for ev := range envVars {
		consumed[ev] = false
	}

	walk := func(path string) error {
		return filepath.Walk(path, func(p string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return nil // best-effort
			}
			if info.IsDir() {
				name := info.Name()
				if name == "node_modules" || name == "dist" || name == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			// Skip internal/config (where the vars are DEFINED) and this
			// test file itself.
			rel, _ := filepath.Rel(repoRoot, p)
			if strings.HasPrefix(rel, filepath.Join("internal", "config")) {
				return nil
			}
			// Only text-ish files.
			ok := false
			for _, ext := range []string{".go", ".sh", ".yml", ".yaml", ".sql", ".md", ".tmpl", ".tpl", ".env", ".json", ".toml", ".ts", ".tsx"} {
				if strings.HasSuffix(p, ext) {
					ok = true
					break
				}
			}
			if !ok && info.Name() != "Makefile" && info.Name() != "Dockerfile" {
				return nil
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			body := string(data)
			for ev := range envVars {
				if consumed[ev] {
					continue
				}
				if strings.Contains(body, ev) {
					consumed[ev] = true
				}
			}
			return nil
		})
	}

	for _, d := range searchDirs {
		if err := walk(filepath.Join(repoRoot, d)); err != nil {
			t.Fatalf("walk %s: %v", d, err)
		}
	}
	for _, f := range searchFiles {
		p := filepath.Join(repoRoot, f)
		if _, err := os.Stat(p); err == nil {
			data, _ := os.ReadFile(p)
			body := string(data)
			for ev := range envVars {
				if consumed[ev] {
					continue
				}
				if strings.Contains(body, ev) {
					consumed[ev] = true
				}
			}
		}
	}

	// 3. Load the allowlist + filter orphans through it.
	allowlist, err := loadAllowlist(filepath.Join(repoRoot, "scripts", "ci-guards", "complete-path-config-coverage-exceptions.yaml"))
	if err != nil {
		t.Fatalf("load allowlist: %v", err)
	}
	today := time.Now().UTC().Truncate(24 * time.Hour)

	var orphans []string
	for ev, ok := range consumed {
		if ok {
			continue
		}
		entry, allowlisted := allowlist[ev]
		if !allowlisted {
			orphans = append(orphans, ev+" (no consumer found)")
			continue
		}
		if entry.Expires.Before(today) {
			orphans = append(orphans, ev+" (allowlist entry expired "+entry.Expires.Format("2006-01-02")+")")
			continue
		}
		if entry.Justification == "" {
			orphans = append(orphans, ev+" (allowlist entry has no justification)")
			continue
		}
	}

	if len(orphans) > 0 {
		t.Errorf("complete-path config-coverage: %d orphan env var(s) — defined in config.go, no consumer outside internal/config/:", len(orphans))
		for _, o := range orphans {
			t.Errorf("  - %s", o)
		}
		t.Errorf("Fix: wire the env var to a real consumer, remove it from config.go, or allowlist it with a justification + expiration in scripts/ci-guards/complete-path-config-coverage-exceptions.yaml")
	}
}

func findRepoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	cur := wd
	for {
		if _, err := os.Stat(filepath.Join(cur, "go.mod")); err == nil {
			return cur, nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", os.ErrNotExist
		}
		cur = parent
	}
}

// loadAllowlist parses the tiny YAML shape used by the exceptions file.
// Same shape parsed by complete-path-config-coverage.sh — keep them in
// sync. Returns name → entry.
func loadAllowlist(path string) (map[string]allowlistEntry, error) {
	out := map[string]allowlistEntry{}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, err
	}
	var cur *allowlistEntry
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "- name:") {
			name := strings.TrimSpace(strings.TrimPrefix(trimmed, "- name:"))
			name = strings.Trim(name, `"' `)
			cur = &allowlistEntry{Name: name}
			out[name] = *cur
			continue
		}
		if cur == nil || !strings.HasPrefix(line, "  ") {
			continue
		}
		kv := strings.SplitN(trimmed, ":", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.TrimSpace(kv[0])
		v := strings.Trim(strings.TrimSpace(kv[1]), `"' `)
		switch k {
		case "justification":
			cur.Justification = v
		case "expires":
			if t, err := time.Parse("2006-01-02", v); err == nil {
				cur.Expires = t
			}
		}
		out[cur.Name] = *cur
	}
	return out, nil
}
