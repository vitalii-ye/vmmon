package setup

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/vitalii-ye/vmmon/internal/fsutil"
)

const tokenEnvKey = "VMMON_TELEGRAM_TOKEN" //nolint:gosec // an environment variable name, not a credential

// writeFiles saves the three values setup owns and reports whether anything on
// disk changed. The directory is created 0755 so the unprivileged daemon can
// read config.yaml.
func writeFiles(configPath, token, chatID, preset string, warn io.Writer) (bool, error) {
	dir := filepath.Dir(configPath)
	if err := ensureDir(dir, warn); err != nil {
		return false, err
	}
	secretsChanged, err := writeSecrets(filepath.Join(dir, "secrets.env"), token)
	if err != nil {
		return false, err
	}
	configChanged, err := writeConfig(configPath, chatID, preset)
	if err != nil {
		return false, err
	}
	return secretsChanged || configChanged, nil
}

func ensureDir(dir string, warn io.Writer) error {
	info, err := os.Stat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		return os.Chmod(dir, 0o755) // Regardless of the umask.
	}
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o005 != 0o005 {
		_, _ = fmt.Fprintf(warn, "Warning: %s has mode %04o, so the service may not be able to read the config.\n", dir, info.Mode().Perm())
	}
	return nil
}

// writeConfig edits the YAML tree rather than re-marshalling a Config, so that
// other values and comments survive, defaults stay unpinned and environment
// overrides are not baked into the file.
func writeConfig(path, chatID, preset string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return false, fmt.Errorf("parse %s: %w", path, err)
	}
	if doc.Kind == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode}}}
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return false, fmt.Errorf("parse %s: top level is not a mapping", path)
	}
	edited := setString(root, chatID, "telegram", "chat_id")
	edited = setString(root, preset, "policy", "preset") || edited
	if edited {
		var buf bytes.Buffer
		enc := yaml.NewEncoder(&buf)
		enc.SetIndent(2)
		if err := enc.Encode(&doc); err != nil {
			return false, err
		}
		if err := enc.Close(); err != nil {
			return false, err
		}
		data = buf.Bytes()
	}
	return writeIfChanged(path, data, 0o644)
}

// setString sets the scalar at section.key, creating what is missing, and
// reports whether it changed anything.
func setString(root *yaml.Node, value, section, key string) bool {
	sec := mapValue(root, section)
	if sec == nil || sec.Kind != yaml.MappingNode {
		if sec == nil {
			sec = &yaml.Node{Kind: yaml.MappingNode}
			root.Content = append(root.Content, scalar(section, ""), sec)
		} else {
			*sec = yaml.Node{Kind: yaml.MappingNode} // e.g. a bare "telegram:".
		}
	}
	node := mapValue(sec, key)
	if node == nil {
		sec.Content = append(sec.Content, scalar(key, ""), scalar(value, "!!str"))
		return true
	}
	if node.Kind == yaml.ScalarNode && node.Value == value {
		return false
	}
	*node = *scalar(value, "!!str")
	return true
}

func mapValue(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func scalar(value, tag string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Value: value, Tag: tag}
}

// writeSecrets sets the token line and keeps every other line. fsutil creates
// the temp file 0600 and renames it into place, so the secret is never readable
// more widely than that, even briefly.
func writeSecrets(path, token string) (bool, error) {
	line, err := envLine(token)
	if err != nil {
		return false, err
	}
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	var out []string
	replaced := false
	for _, l := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		trimmed := strings.TrimSpace(l)
		if k, _, ok := strings.Cut(trimmed, "="); ok && !strings.HasPrefix(trimmed, "#") && strings.TrimSpace(k) == tokenEnvKey {
			if !replaced {
				out = append(out, line)
				replaced = true
			}
			continue
		}
		if l != "" || len(data) > 0 {
			out = append(out, l)
		}
	}
	if !replaced {
		out = append(out, line)
	}
	return writeIfChanged(path, []byte(strings.Join(out, "\n")+"\n"), 0o600)
}

var safeEnvValue = regexp.MustCompile(`^[A-Za-z0-9_:.,@%+=/-]+$`)

// tokenSyntaxError is a token that cannot be stored; it never quotes the token.
type tokenSyntaxError struct{ reason string }

func (e *tokenSyntaxError) Error() string { return "the token " + e.reason }

// envLine formats the token so config's readEnvFile and systemd's
// EnvironmentFile read the same value. Telegram's own tokens are written bare.
// Anything else is single-quoted, which both take literally, including
// backslashes, "$" and "#". What single quotes cannot carry is refused: a
// quote, which readEnvFile may also trim, and control characters, which include
// the newline. systemd also refuses invalid UTF-8.
func envLine(token string) (string, error) {
	if safeEnvValue.MatchString(token) {
		return tokenEnvKey + "=" + token, nil
	}
	if !utf8.ValidString(token) {
		return "", &tokenSyntaxError{"is not valid UTF-8"}
	}
	for _, r := range token {
		switch {
		case r == '\'' || r == '"':
			return "", &tokenSyntaxError{"contains a quote"}
		case r < 0x20 || r == 0x7f:
			return "", &tokenSyntaxError{"contains a control character"}
		}
	}
	return tokenEnvKey + "='" + token + "'", nil
}

// writeIfChanged leaves a file alone if it already has this content and mode.
func writeIfChanged(path string, data []byte, perm os.FileMode) (bool, error) {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		info, err := os.Stat(path)
		if err != nil {
			return false, err
		}
		if info.Mode().Perm() == perm {
			return false, nil
		}
	}
	if err := fsutil.WriteFileAtomic(path, data, perm); err != nil {
		return false, fmt.Errorf("write %s: %w", path, err)
	}
	return true, nil
}
