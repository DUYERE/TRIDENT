package webui

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
)

const (
	// TokenIdentityMax bounds token file id/role fields.
	TokenIdentityMax = 64
	// SingleTokenID is the fixed audit identity of the legacy single-token mode.
	SingleTokenID = "local"
	// SingleTokenRole is the fixed role of the legacy single-token mode.
	SingleTokenRole = "reviewer"
)

// TokenEntry is the identity resolved from a presented token.
type TokenEntry struct {
	ID   string
	Role string
	hash string
}

type tokenFileUser struct {
	ID        string `json:"id"`
	Role      string `json:"role"`
	TokenHash string `json:"token_hash"`
}

// tokenRegistry maps presented tokens to identities. File-backed registries
// re-read the token file when its modification time or size changes, so
// rotation and revocation apply on the next request without a restart.
type tokenRegistry struct {
	mu      sync.Mutex
	source  string // token file path; empty for the single-token registry
	modTime int64  // unix nanoseconds of the loaded file state
	size    int64
	entries map[string]TokenEntry // keyed by lowercase hex SHA-256 of the token
	ids     []string              // sorted user ids for display
	warnTo  io.Writer
	warnSig string
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// newSingleTokenRegistry serves the legacy --token mode with a fixed local
// identity. It never reloads.
func newSingleTokenRegistry(token string) *tokenRegistry {
	entry := TokenEntry{ID: SingleTokenID, Role: SingleTokenRole, hash: hashToken(token)}
	return &tokenRegistry{
		entries: map[string]TokenEntry{entry.hash: entry},
		ids:     []string{SingleTokenID},
	}
}

// newFileTokenRegistry loads a multi-user token file; an unusable file fails
// startup instead of degrading authentication.
func newFileTokenRegistry(path string, warnTo io.Writer) (*tokenRegistry, error) {
	entries, ids, err := loadTokenFile(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("token file is not readable: %w", err)
	}
	return &tokenRegistry{
		source:  path,
		modTime: info.ModTime().UnixNano(),
		size:    info.Size(),
		entries: entries,
		ids:     ids,
		warnTo:  warnTo,
	}, nil
}

func loadTokenFile(path string) (map[string]TokenEntry, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("token file is not readable: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	users := []tokenFileUser{}
	if err := decoder.Decode(&users); err != nil {
		return nil, nil, fmt.Errorf("token file must be a JSON array of {id, role, token_hash}: %v", err)
	}
	if decoder.More() {
		return nil, nil, fmt.Errorf("token file must be a single JSON array")
	}
	if len(users) == 0 {
		return nil, nil, fmt.Errorf("token file must contain at least one user")
	}
	entries := make(map[string]TokenEntry, len(users))
	ids := make([]string, 0, len(users))
	seenIDs := map[string]bool{}
	seenHashes := map[string]string{}
	for _, user := range users {
		id, err := validateIdentityField(user.ID, "id")
		if err != nil {
			return nil, nil, err
		}
		role, err := validateIdentityField(user.Role, "role")
		if err != nil {
			return nil, nil, err
		}
		hash := strings.ToLower(strings.TrimSpace(user.TokenHash))
		if len(hash) != sha256.Size*2 || !isHex(hash) {
			return nil, nil, fmt.Errorf("token file user %q: token_hash must be a 64-character hex SHA-256", id)
		}
		if seenIDs[id] {
			return nil, nil, fmt.Errorf("token file contains duplicate id %q", id)
		}
		if owner, dup := seenHashes[hash]; dup {
			return nil, nil, fmt.Errorf("token file maps the same token_hash to %q and %q", owner, id)
		}
		entries[hash] = TokenEntry{ID: id, Role: role, hash: hash}
		seenIDs[id] = true
		seenHashes[hash] = id
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return entries, ids, nil
}

func validateIdentityField(value, field string) (string, error) {
	if len(value) == 0 || len(value) > TokenIdentityMax {
		return "", fmt.Errorf("token file %s must contain 1 to %d characters", field, TokenIdentityMax)
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		default:
			return "", fmt.Errorf("token file %s must only contain A-Za-z0-9._-: %q", field, value)
		}
	}
	return value, nil
}

func isHex(value string) bool {
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

// lookup resolves a presented token to its identity. File-backed registries
// check for a changed file signature on every lookup; a failed reload keeps
// the last known-good registry and warns once per error signature.
func (reg *tokenRegistry) lookup(token string) (TokenEntry, bool) {
	if reg == nil || token == "" {
		return TokenEntry{}, false
	}
	if reg.source != "" {
		reg.maybeReload()
	}
	digest := hashToken(token)
	reg.mu.Lock()
	defer reg.mu.Unlock()
	entry, ok := reg.entries[digest]
	if !ok {
		return TokenEntry{}, false
	}
	if subtle.ConstantTimeCompare([]byte(digest), []byte(entry.hash)) != 1 {
		return TokenEntry{}, false
	}
	return entry, true
}

func (reg *tokenRegistry) maybeReload() {
	info, err := os.Stat(reg.source)
	if err != nil {
		reg.warnReload(fmt.Sprintf("stat: %v", err))
		return
	}
	modTime := info.ModTime().UnixNano()
	size := info.Size()
	reg.mu.Lock()
	unchanged := modTime == reg.modTime && size == reg.size
	reg.mu.Unlock()
	if unchanged {
		return
	}
	entries, ids, err := loadTokenFile(reg.source)
	if err != nil {
		// A structurally broken or unreadable file must not lock reviewers
		// out mid-rotation; keep serving the last known-good registry.
		reg.warnReload(err.Error())
		return
	}
	reg.mu.Lock()
	reg.entries = entries
	reg.ids = ids
	reg.modTime = modTime
	reg.size = size
	reg.mu.Unlock()
}

func (reg *tokenRegistry) warnReload(message string) {
	if reg.warnTo == nil {
		return
	}
	reg.mu.Lock()
	defer reg.mu.Unlock()
	if message == reg.warnSig {
		return
	}
	reg.warnSig = message
	fmt.Fprintf(reg.warnTo, "TRIDENT web: token file reload failed, keeping last known-good registry: %s\n", message)
}

// TokenIDs returns the sorted user ids currently loaded.
func (reg *tokenRegistry) TokenIDs() []string {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	return append([]string{}, reg.ids...)
}
