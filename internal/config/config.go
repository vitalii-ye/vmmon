// Package config loads config.yaml, secrets.env and environment overrides.
//
// Precedence, lowest to highest: defaults, config file, secrets file,
// environment. A missing config file is not an error: every field has a
// default, so `vmmon scan` works before `vmmon setup` has run.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Default locations.
const (
	DefaultPath     = "/etc/vmmon/config.yaml"
	DefaultStateDir = "/var/lib/vmmon"
)

// Policy presets.
const (
	PresetQuiet      = "quiet"
	PresetCritical   = "critical"
	PresetEverything = "everything"
)

// Config is the whole of vmmon's configuration.
type Config struct {
	// Hostname overrides os.Hostname in messages.
	Hostname string `yaml:"hostname,omitempty"`
	// StateDir holds db/ and state.bolt.
	StateDir string   `yaml:"state_dir"`
	DB       DB       `yaml:"db"`
	Policy   Policy   `yaml:"policy"`
	Telegram Telegram `yaml:"telegram"`

	// Path is the file this config was loaded from, or would be written to.
	Path string `yaml:"-"`
}

// DB configures vulnerability data sources and sync cadence.
type DB struct {
	SyncInterval        time.Duration `yaml:"sync_interval"`
	FullRefreshInterval time.Duration `yaml:"full_refresh_interval"`
	EnrichInterval      time.Duration `yaml:"enrich_interval"`
	StaleAfter          time.Duration `yaml:"stale_after"`
	// FullSyncThreshold is how many changed records an incremental sync may
	// fetch one by one before it falls back to a full download.
	FullSyncThreshold int    `yaml:"full_sync_threshold"`
	OSVBaseURL        string `yaml:"osv_base_url"`
	KEVURL            string `yaml:"kev_url"`
	EPSSURL           string `yaml:"epss_url"`
	// UbuntuPro includes Ubuntu :Pro: ecosystems in matching.
	UbuntuPro bool `yaml:"ubuntu_pro"`
}

// Policy selects which findings alert immediately.
type Policy struct {
	Preset string `yaml:"preset"`
	// MinCVSS and MinEPSS are the quiet preset's thresholds for findings with
	// a fix available.
	MinCVSS float64 `yaml:"min_cvss"`
	MinEPSS float64 `yaml:"min_epss"`
	// DigestTime is the local time of the digest, as HH:MM.
	DigestTime string `yaml:"digest_time"`
	Ignore     Ignore `yaml:"ignore,omitempty"`
}

// Ignore suppresses findings entirely; it handles OSV data bugs.
type Ignore struct {
	CVEs     []string `yaml:"cves,omitempty"`
	Packages []string `yaml:"packages,omitempty"`
}

// Telegram configures the Telegram channel.
type Telegram struct {
	ChatID     string `yaml:"chat_id,omitempty"`
	APIBaseURL string `yaml:"api_base_url,omitempty"`
	// Token comes only from secrets.env or the environment, is never written
	// to config.yaml and must never be logged. Use Redacted to display it.
	Token string `yaml:"-"`
}

// Configured reports whether the channel has what it needs to send.
func (t Telegram) Configured() bool { return t.Token != "" && t.ChatID != "" }

// Redacted returns a form of the token that is safe to display.
func (t Telegram) Redacted() string {
	if t.Token == "" {
		return "(not set)"
	}
	return "(set)"
}

// Default returns the built-in configuration.
func Default() *Config {
	return &Config{
		StateDir: DefaultStateDir,
		Path:     DefaultPath,
		DB: DB{
			SyncInterval:        6 * time.Hour,
			FullRefreshInterval: 7 * 24 * time.Hour,
			EnrichInterval:      24 * time.Hour,
			StaleAfter:          48 * time.Hour,
			FullSyncThreshold:   5000,
			OSVBaseURL:          "https://storage.googleapis.com/osv-vulnerabilities",
			KEVURL:              "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
			EPSSURL:             "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
		},
		Policy: Policy{
			Preset:     PresetQuiet,
			MinCVSS:    7,
			MinEPSS:    0.1,
			DigestTime: "09:00",
		},
		Telegram: Telegram{APIBaseURL: "https://api.telegram.org"},
	}
}

// Load reads configuration. An empty path means $VMMON_CONFIG, then DefaultPath.
func Load(path string) (*Config, error) {
	if path == "" {
		path = os.Getenv("VMMON_CONFIG")
	}
	if path == "" {
		path = DefaultPath
	}
	c := Default()
	c.Path = path

	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		dec := yaml.NewDecoder(strings.NewReader(string(data)))
		dec.KnownFields(true)
		if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, fs.ErrPermission):
		// Fall through to defaults and the environment.
	default:
		return nil, fmt.Errorf("read config: %w", err)
	}

	secrets := filepath.Join(filepath.Dir(path), "secrets.env")
	env, err := readEnvFile(secrets)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", secrets, err)
	}
	lookup := func(k string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return env[k]
	}
	if err := c.applyEnv(lookup); err != nil {
		return nil, err
	}
	return c, c.Validate()
}

func (c *Config) applyEnv(get func(string) string) error {
	setStr := func(dst *string, key string) {
		if v := get(key); v != "" {
			*dst = v
		}
	}
	setStr(&c.Hostname, "VMMON_HOSTNAME")
	setStr(&c.StateDir, "VMMON_STATE_DIR")
	setStr(&c.Policy.Preset, "VMMON_POLICY")
	setStr(&c.Telegram.Token, "VMMON_TELEGRAM_TOKEN")
	setStr(&c.Telegram.ChatID, "VMMON_TELEGRAM_CHAT_ID")
	setStr(&c.Telegram.APIBaseURL, "VMMON_TELEGRAM_API_BASE_URL")
	setStr(&c.DB.OSVBaseURL, "VMMON_OSV_BASE_URL")
	setStr(&c.DB.KEVURL, "VMMON_KEV_URL")
	setStr(&c.DB.EPSSURL, "VMMON_EPSS_URL")
	if v := get("VMMON_SYNC_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("VMMON_SYNC_INTERVAL: %w", err)
		}
		c.DB.SyncInterval = d
	}
	if v := get("VMMON_UBUNTU_PRO"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("VMMON_UBUNTU_PRO: %w", err)
		}
		c.DB.UbuntuPro = b
	}
	return nil
}

// Validate checks values that would otherwise fail much later in the daemon.
func (c *Config) Validate() error {
	switch c.Policy.Preset {
	case PresetQuiet, PresetCritical, PresetEverything:
	default:
		return fmt.Errorf("policy.preset: unknown preset %q (want quiet, critical or everything)", c.Policy.Preset)
	}
	if _, err := time.Parse("15:04", c.Policy.DigestTime); err != nil {
		return fmt.Errorf("policy.digest_time: want HH:MM, got %q", c.Policy.DigestTime)
	}
	if c.DB.SyncInterval <= 0 || c.DB.FullRefreshInterval <= 0 || c.DB.EnrichInterval <= 0 || c.DB.StaleAfter <= 0 {
		return errors.New("db: intervals must be positive")
	}
	return nil
}

// DBDir is where vulnerability data lives.
func (c *Config) DBDir() string { return filepath.Join(c.StateDir, "db") }

// StatePath is the bbolt file holding reported findings.
func (c *Config) StatePath() string { return filepath.Join(c.StateDir, "state.bolt") }

// SecretsPath is the env file holding the token.
func (c *Config) SecretsPath() string { return filepath.Join(filepath.Dir(c.Path), "secrets.env") }

// Marshal renders the config as YAML. Secrets are never included.
func (c *Config) Marshal() ([]byte, error) { return yaml.Marshal(c) }

// readEnvFile parses KEY=VALUE lines. A missing or unreadable file gives an
// empty map: under systemd the daemon gets these through EnvironmentFile and
// cannot read the file itself.
func readEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return out, sc.Err()
}
