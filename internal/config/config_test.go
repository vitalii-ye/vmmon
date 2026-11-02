package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadMissingFileGivesDefaults(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Policy.Preset != PresetQuiet || c.DB.SyncInterval != 6*time.Hour {
		t.Fatalf("unexpected defaults: %+v", c)
	}
}

func TestPrecedence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	write(t, path, "policy:\n  preset: critical\ntelegram:\n  chat_id: \"1\"\ndb:\n  sync_interval: 2h\n")
	write(t, filepath.Join(dir, "secrets.env"), "# comment\nVMMON_TELEGRAM_TOKEN=\"from-file\"\n")

	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Policy.Preset != PresetCritical || c.DB.SyncInterval != 2*time.Hour {
		t.Fatalf("file values not applied: %+v", c)
	}
	if c.Telegram.Token != "from-file" || !c.Telegram.Configured() {
		t.Fatalf("secret not applied")
	}

	t.Setenv("VMMON_TELEGRAM_TOKEN", "")
	if c, err = Load(path); err != nil || c.Telegram.Token != "from-file" {
		t.Fatalf("empty env var should not hide the secrets file: %v", err)
	}

	t.Setenv("VMMON_TELEGRAM_TOKEN", "from-env")
	t.Setenv("VMMON_POLICY", "everything")
	c, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Telegram.Token != "from-env" || c.Policy.Preset != PresetEverything {
		t.Fatalf("env should win: preset=%s", c.Policy.Preset)
	}
}

func TestValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	for name, body := range map[string]string{
		"preset":  "policy:\n  preset: loud\n",
		"digest":  "policy:\n  digest_time: nine\n",
		"unknown": "polisy: {}\n",
	} {
		write(t, path, body)
		if _, err := Load(path); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestMarshalNeverIncludesToken(t *testing.T) {
	c := Default()
	c.Telegram.Token = "123:SECRET"
	b, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "SECRET") {
		t.Fatal("token leaked into YAML")
	}
	if strings.Contains(c.Telegram.Redacted(), "SECRET") {
		t.Fatal("token leaked into Redacted")
	}
}
