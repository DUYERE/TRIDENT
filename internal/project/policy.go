package project

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"unicode/utf8"
)

// 01: Bounds are a fixed security policy, not caller-controlled hints.
const PolicyVersion = "trident-local-source-v1"
const SnapshotToolVersion = "0.2.0-p0.2+r1-snapshot"
const ManifestFileName = ".trident-manifest.json"

var (
	ErrUnsafePath          = errors.New("unsafe project path or file")
	ErrIntegrity           = errors.New("snapshot integrity check failed")
	ErrLimit               = errors.New("project security budget exceeded")
	ErrUnsupportedPlatform = errors.New("unsupported secure filesystem configuration")
	ErrDestinationExists   = errors.New("snapshot destination already exists")
	ErrSourceChanged       = errors.New("source changed during import")
)

type Limits struct {
	MaxFiles         int   `json:"max_files"`
	MaxEntries       int   `json:"max_entries"`
	MaxFileBytes     int64 `json:"max_file_bytes"`
	MaxTotalBytes    int64 `json:"max_total_bytes"`
	MaxDepth         int   `json:"max_depth"`
	MaxExcluded      int   `json:"max_excluded"`
	MaxManifestBytes int64 `json:"max_manifest_bytes"`
	MaxPathBytes     int   `json:"max_path_bytes"`
}

func DefaultLimits() Limits {
	return Limits{MaxFiles: 10000, MaxEntries: 20000, MaxFileBytes: 16 << 20,
		MaxTotalBytes: 128 << 20, MaxDepth: 32, MaxExcluded: 1000,
		MaxManifestBytes: 8 << 20, MaxPathBytes: 1024}
}

// 02: One portable spelling prevents ADS, DOS devices, dot aliases and path escapes.
func validateRelative(p string) error {
	limits := DefaultLimits()
	if p == "" || !utf8.ValidString(p) || len(p) > limits.MaxPathBytes || strings.ContainsAny(p, "\\:\x00") || strings.HasPrefix(p, "/") {
		return fmt.Errorf("%w: invalid relative path", ErrUnsafePath)
	}
	parts := strings.Split(p, "/")
	if len(parts) > limits.MaxDepth {
		return fmt.Errorf("%w: path depth", ErrLimit)
	}
	for _, part := range parts {
		if err := validateComponent(part); err != nil {
			return err
		}
	}
	return nil
}

func validateComponent(s string) error {
	if s == "" || s == "." || s == ".." || len(s) > 255 || !utf8.ValidString(s) || strings.TrimRight(s, " .") != s {
		return fmt.Errorf("%w: invalid path component", ErrUnsafePath)
	}
	for _, r := range s {
		if r < 32 || r == 127 || strings.ContainsRune("\\/:*?\"<>|", r) {
			return fmt.Errorf("%w: invalid path character", ErrUnsafePath)
		}
	}
	base := strings.ToUpper(strings.SplitN(s, ".", 2)[0])
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return fmt.Errorf("%w: reserved device name", ErrUnsafePath)
	}
	deviceRunes := []rune(base)
	if len(deviceRunes) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && strings.ContainsRune("123456789¹²³", deviceRunes[3]) {
		return fmt.Errorf("%w: reserved device name", ErrUnsafePath)
	}
	return nil
}

func exclusionReason(p string, directory bool) string {
	name := strings.ToLower(path.Base(p))
	if directory {
		switch name {
		case ".git", ".hg", ".svn", ".ssh", ".aws", ".azure", ".gnupg", ".kube", ".terraform", "secrets", "credentials":
			return "sensitive_metadata"
		case "node_modules", "vendor", ".venv", "venv", "__pycache__", "target", "dist", "build", ".idea", ".vscode", ".gradle", ".next", "coverage":
			return "generated_or_dependency_directory"
		}
		return ""
	}
	if name == ".env" || strings.HasPrefix(name, ".env.") || strings.HasPrefix(name, "id_rsa") || strings.HasPrefix(name, "id_ed25519") || name == ".netrc" || name == ".npmrc" || name == ".pypirc" || name == "credentials" || name == "credentials.json" || name == "secrets.json" || name == "secrets.yaml" || name == "secrets.yml" || name == "service-account.json" || name == "application_default_credentials.json" {
		return "sensitive_file"
	}
	switch strings.ToLower(path.Ext(name)) {
	case ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".kdbx", ".secret", ".sqlite", ".sqlite3", ".db", ".sql", ".dump":
		return "sensitive_file"
	case ".exe", ".dll", ".so", ".dylib", ".jar", ".war", ".class", ".pyc", ".zip", ".gz", ".tar", ".7z", ".png", ".jpg", ".jpeg", ".gif", ".pdf":
		return "binary_or_archive"
	}
	return ""
}
