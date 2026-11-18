// Package entry is the pilot capability-provider layer for entry evidence.
// Existing analyzers remain responsible for their own bounded scans; this
// package only normalizes their evidence into the shared model. Future
// capabilities (authz, SCA, reachability) can follow the same Provider
// interface without changing the surfaces.
package entry

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"trident/internal/audit"
	"trident/internal/authz"
	"trident/internal/codescan"
	"trident/internal/entrypoint"
	"trident/internal/evidence"
	"trident/internal/project"
)

const Capability = "entry"

// Input is the already-computed input for a capability build. Providers never
// start a new expensive analysis here; missing optional inputs become explicit
// limitations, not empty zeroes.
type Input struct {
	Snapshot           *project.Snapshot
	JavaAudit          *audit.Report
	Authz              *authz.Report
	CodeAudit          *codescan.Report
	ApplicationEntries *entrypoint.Report
}

// Contribution is one provider's normalized output.
type Contribution struct {
	Entries     []evidence.Entry
	Coverage    []evidence.LanguageCoverage
	Partial     bool
	Limitations []string
}

// Provider is the capability-provider contract for the entry pilot.
type Provider interface {
	Name() string
	Collect(Input) (Contribution, error)
}

// Registry composes providers into one deterministic evidence report.
type Registry struct {
	providers []Provider
}

// NewRegistry returns the built-in entry providers. It does not execute any
// analyzer by itself.
func NewRegistry() *Registry {
	return &Registry{providers: []Provider{
		JavaAuditProvider{},
		CodeRouteProvider{},
		ApplicationEntryProvider{},
	}}
}

// Register adds a provider; duplicate names are rejected.
func (r *Registry) Register(provider Provider) error {
	if provider == nil {
		return fmt.Errorf("entry: nil provider")
	}
	for _, existing := range r.providers {
		if existing.Name() == provider.Name() {
			return fmt.Errorf("entry: duplicate provider %q", provider.Name())
		}
	}
	r.providers = append(r.providers, provider)
	return nil
}

// Build merges all provider contributions. It sorts entries deterministically
// and suppresses duplicate route evidence when a richer provider already
// carries the same file/line/path/method tuple.
func (r *Registry) Build(ctx context.Context, input Input) (evidence.Report, error) {
	if r == nil {
		return evidence.Report{}, fmt.Errorf("entry: nil registry")
	}
	if err := contextError(ctx); err != nil {
		return evidence.Report{}, err
	}
	report := evidence.Report{
		SchemaVersion: evidence.SchemaVersion,
		Capability:    Capability,
		Providers:     []string{},
		Entries:       []evidence.Entry{},
		Coverage:      []evidence.LanguageCoverage{},
		Limitations:   []string{"entry_normalized_from_providers", "entry_evidence_not_deployed_route"},
	}
	seen := map[string]evidence.Entry{}
	duplicateSuppressed := false
	limited := map[string]struct{}{}
	for _, provider := range r.providers {
		contribution, err := provider.Collect(input)
		if err != nil {
			return evidence.Report{}, fmt.Errorf("entry provider %s: %w", provider.Name(), err)
		}
		report.Providers = append(report.Providers, provider.Name())
		report.Partial = report.Partial || contribution.Partial
		for _, limitation := range contribution.Limitations {
			if limitation == "" {
				continue
			}
			if _, ok := limited[limitation]; ok {
				continue
			}
			limited[limitation] = struct{}{}
			report.Limitations = append(report.Limitations, limitation)
		}
		for _, item := range contribution.Entries {
			key := duplicateKey(item)
			if previous, ok := seen[key]; ok {
				if entryPriority(item) > entryPriority(previous) {
					seen[key] = item
				}
				duplicateSuppressed = true
				continue
			}
			seen[key] = item
		}
		report.Coverage = append(report.Coverage, contribution.Coverage...)
	}
	if duplicateSuppressed {
		report.Limitations = append(report.Limitations, "entry_duplicate_suppressed")
	}
	for _, item := range seen {
		report.Entries = append(report.Entries, item)
	}
	sort.Slice(report.Entries, func(i, j int) bool {
		return entrySortKey(report.Entries[i]) < entrySortKey(report.Entries[j])
	})
	sort.Slice(report.Coverage, func(i, j int) bool {
		if report.Coverage[i].Source != report.Coverage[j].Source {
			return report.Coverage[i].Source < report.Coverage[j].Source
		}
		return report.Coverage[i].Language < report.Coverage[j].Language
	})
	return report, nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func duplicateKey(item evidence.Entry) string {
	return strings.Join([]string{
		item.Language,
		item.File,
		fmt.Sprintf("%d", item.StartLine),
		item.Path,
		strings.Join(item.HTTPMethods, ","),
	}, "\x1f")
}

func entryPriority(item evidence.Entry) int {
	switch item.Kind {
	case evidence.KindAnnotationRoute:
		return 3
	case evidence.KindRouteDeclaration:
		return 2
	case evidence.KindApplicationEntry:
		return 1
	case evidence.KindRequestScript:
		return 1
	default:
		return 0
	}
}

func entrySortKey(item evidence.Entry) string {
	return strings.Join([]string{
		item.Language,
		item.Kind,
		item.File,
		fmt.Sprintf("%08d", item.StartLine),
		item.Path,
		item.Symbol,
		item.ID,
	}, "\x1f")
}

func stableID(source, file string, line int, path, symbol string) string {
	parts := []string{
		strings.TrimSpace(source),
		strings.TrimSpace(file),
		fmt.Sprintf("%d", line),
		strings.TrimSpace(path),
		strings.TrimSpace(symbol),
	}
	return strings.Join(parts, ":")
}
