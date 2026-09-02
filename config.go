package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config is written once on first run and read on every start.
//
// It lives in the per-user config directory (%APPDATA% on Windows,
// ~/Library/Application Support on macOS) rather than beside the binary, so the
// agent works from a read-only install location and each user of a shared
// machine gets their own token.
type Config struct {
	// Token is required on every privileged call. See security.go for why the
	// origin allowlist is the real gate and this is defence in depth.
	Token string `json:"token"`

	// MachineID identifies this install to Sally so a user who works at two
	// counters gets the right saved printer at each. It is a random value, not
	// a hardware identifier — Sally has no business fingerprinting the device.
	MachineID string `json:"machineId"`

	// AllowedOrigins is the list of web origins permitted to talk to the agent.
	// Editable so a self-hosted deployment can add its own domain; anything not
	// listed is refused outright.
	AllowedOrigins []string `json:"allowedOrigins"`

	// HelperPath optionally points at the PDF print helper on Windows, where
	// there is no built-in way to print a PDF to a named printer. Empty means
	// "look in the usual places" — see printers_windows.go.
	HelperPath string `json:"helperPath,omitempty"`
}

// defaultAllowedOrigins is intentionally short. Adding an origin here grants it
// the ability to enumerate the user's printers and spool jobs to them.
func defaultAllowedOrigins() []string {
	return []string{
		"https://sallyerp.in",
		"https://www.sallyerp.in",
		// Local development of the Sally web app.
		"http://localhost:3000",
		"http://127.0.0.1:3000",
	}
}

func configDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locating the user config directory: %w", err)
	}
	return filepath.Join(base, "SallyPrintAgent"), nil
}

// loadOrCreateConfig reads the config, creating it with a fresh token on first
// run. A config that exists but is unreadable is a hard error rather than a
// silent regeneration: rotating the token behind the user's back would break
// their paired browsers with no explanation.
func loadOrCreateConfig() (*Config, string, error) {
	dir, err := configDir()
	if err != nil {
		return nil, "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, "", fmt.Errorf("creating %s: %w", dir, err)
	}
	path := filepath.Join(dir, "config.json")

	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		var cfg Config
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, "", fmt.Errorf("reading %s: %w", path, err)
		}
		// Tolerate a config written by an older version that lacked a field.
		if cfg.Token == "" {
			if cfg.Token, err = randomHex(32); err != nil {
				return nil, "", err
			}
		}
		if cfg.MachineID == "" {
			if cfg.MachineID, err = randomHex(16); err != nil {
				return nil, "", err
			}
		}
		if len(cfg.AllowedOrigins) == 0 {
			cfg.AllowedOrigins = defaultAllowedOrigins()
		}
		if err := writeConfig(path, &cfg); err != nil {
			return nil, "", err
		}
		return &cfg, path, nil

	case os.IsNotExist(err):
		token, err := randomHex(32)
		if err != nil {
			return nil, "", err
		}
		machineID, err := randomHex(16)
		if err != nil {
			return nil, "", err
		}
		cfg := &Config{
			Token:          token,
			MachineID:      machineID,
			AllowedOrigins: defaultAllowedOrigins(),
		}
		if err := writeConfig(path, cfg); err != nil {
			return nil, "", err
		}
		return cfg, path, nil

	default:
		return nil, "", fmt.Errorf("reading %s: %w", path, err)
	}
}

// writeConfig saves the config 0600 — it holds the token.
func writeConfig(path string, cfg *Config) error {
	body, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(body, '\n'), 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating random bytes: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
