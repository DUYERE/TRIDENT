package sca

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// advisoryCatalog is the fixed-intelligence fixture format. It is deliberately
// exact-version only: ranges, aliases and repository resolution stay outside
// this slice and must not be inferred from missing cases.
type advisoryCatalog struct {
	SchemaVersion   string   `json:"schema_version"`
	FixtureID       string   `json:"fixture_id"`
	Kind            string   `json:"kind"`
	AdvisoryID      string   `json:"advisory_id"`
	Aliases         []string `json:"aliases"`
	AliasesComplete bool     `json:"aliases_complete"`
	PublishedDate   string   `json:"published_date"`
	RetrievedDate   string   `json:"retrieved_date"`
	Ecosystem       string   `json:"ecosystem"`
	Package         struct {
		GroupID    string `json:"group_id"`
		ArtifactID string `json:"artifact_id"`
	} `json:"package"`
	Sources []struct {
		ID                  string `json:"id"`
		URL                 string `json:"url"`
		Publisher           string `json:"publisher"`
		RetrievalStatus     string `json:"retrieval_status"`
		RetrievalMethod     string `json:"retrieval_method"`
		RetrievedBodySHA256 string `json:"retrieved_body_sha256"`
		RawBodyIncluded     bool   `json:"raw_body_included"`
		SummaryKind         string `json:"summary_kind"`
		Summary             string `json:"summary"`
	} `json:"sources"`
	MatchingScope struct {
		SourceID                         string `json:"source_id"`
		Policy                           string `json:"policy"`
		FixedDefaultConfigurationRelease string `json:"fixed_default_configuration_release"`
	} `json:"matching_scope"`
	VersionCases []struct {
		Version           string `json:"version"`
		VersionMatched    bool   `json:"version_matched"`
		SupplyChainStatus string `json:"supply_chain_status"`
		FindingStatus     string `json:"finding_status"`
		AssessmentScope   string `json:"assessment_scope"`
		RuntimeStatus     string `json:"runtime_status"`
	} `json:"version_cases"`
	ExploitabilityPrerequisites []string `json:"exploitability_prerequisites"`
	ForbiddenInferences         []string `json:"forbidden_inferences"`
	Coverage                    struct {
		Advisories                       []string `json:"advisories"`
		AllCVEsChecked                   bool     `json:"all_cves_checked"`
		ArtifactHashesAvailable          bool     `json:"artifact_hashes_available"`
		EffectiveDependencyTreeAvailable bool     `json:"effective_dependency_tree_available"`
		RuntimeExploitTestAvailable      bool     `json:"runtime_exploit_test_available"`
	} `json:"coverage"`
}

func loadAdvisories(advisoryPath string) ([]*advisoryCatalog, error) {
	if advisoryPath == "" {
		return nil, nil
	}
	data, err := readAdvisoryFile(advisoryPath)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var catalog advisoryCatalog
	if err = decoder.Decode(&catalog); err != nil {
		return nil, fmt.Errorf("%w: invalid JSON", ErrAdvisory)
	}
	if err = decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing JSON", ErrAdvisory)
	}
	if err = validateAdvisory(&catalog); err != nil {
		return nil, err
	}
	return []*advisoryCatalog{&catalog}, nil
}

// readAdvisoryFile accepts an explicit caller-selected regular file only. The
// catalog is trusted configuration, but size/symlink bounds still fail closed.
func readAdvisoryFile(advisoryPath string) ([]byte, error) {
	if strings.ContainsRune(advisoryPath, 0) {
		return nil, fmt.Errorf("%w: invalid advisory path", ErrAdvisory)
	}
	info, err := os.Lstat(advisoryPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > MaxAdvisoryBytes {
		return nil, fmt.Errorf("%w: advisory file must be a bounded regular file", ErrAdvisory)
	}
	file, err := os.Open(advisoryPath)
	if err != nil {
		return nil, fmt.Errorf("%w: advisory file unreadable", ErrAdvisory)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxAdvisoryBytes+1))
	if err != nil || len(data) == 0 || len(data) > MaxAdvisoryBytes {
		return nil, fmt.Errorf("%w: advisory file size", ErrAdvisory)
	}
	return data, nil
}

func validateAdvisory(catalog *advisoryCatalog) error {
	if catalog.AdvisoryID == "" || len(catalog.AdvisoryID) > 128 || catalog.Ecosystem != "Maven" {
		return fmt.Errorf("%w: advisory identity or ecosystem", ErrAdvisory)
	}
	if catalog.Package.GroupID == "" || catalog.Package.ArtifactID == "" {
		return fmt.Errorf("%w: advisory package coordinates", ErrAdvisory)
	}
	if len(catalog.VersionCases) == 0 || len(catalog.VersionCases) > MaxAdvisoryVersionCases {
		return fmt.Errorf("%w: advisory version cases", ErrAdvisory)
	}
	sources := make(map[string]bool, len(catalog.Sources))
	for _, source := range catalog.Sources {
		if source.ID == "" || sources[source.ID] {
			return fmt.Errorf("%w: advisory source identity", ErrAdvisory)
		}
		sources[source.ID] = true
		if source.RetrievedBodySHA256 != "" && !validSHA256(source.RetrievedBodySHA256) {
			return fmt.Errorf("%w: advisory source digest", ErrAdvisory)
		}
	}
	if catalog.MatchingScope.SourceID != "" && !sources[catalog.MatchingScope.SourceID] {
		return fmt.Errorf("%w: advisory matching source", ErrAdvisory)
	}
	seen := make(map[string]bool, len(catalog.VersionCases))
	for _, versionCase := range catalog.VersionCases {
		if versionCase.Version == "" || len(versionCase.Version) > 128 || seen[versionCase.Version] {
			return fmt.Errorf("%w: advisory version case", ErrAdvisory)
		}
		seen[versionCase.Version] = true
		switch {
		case versionCase.VersionMatched && versionCase.SupplyChainStatus != "version_matched":
			return fmt.Errorf("%w: matched case status", ErrAdvisory)
		case !versionCase.VersionMatched && versionCase.SupplyChainStatus != "not_affected":
			return fmt.Errorf("%w: unmatched case status", ErrAdvisory)
		}
	}
	return nil
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func advisoryInfo(advisories []*advisoryCatalog) []AdvisoryInfo {
	info := make([]AdvisoryInfo, 0, len(advisories))
	for _, advisory := range advisories {
		info = append(info, AdvisoryInfo{
			AdvisoryID:                       advisory.AdvisoryID,
			Package:                          advisory.Package.GroupID + ":" + advisory.Package.ArtifactID,
			SourceID:                         advisory.MatchingScope.SourceID,
			Policy:                           advisory.MatchingScope.Policy,
			RetrievedDate:                    advisory.RetrievedDate,
			VersionCaseCount:                 len(advisory.VersionCases),
			AllCVEsChecked:                   advisory.Coverage.AllCVEsChecked,
			ArtifactHashesAvailable:          advisory.Coverage.ArtifactHashesAvailable,
			EffectiveDependencyTreeAvailable: advisory.Coverage.EffectiveDependencyTreeAvailable,
			RuntimeExploitTestAvailable:      advisory.Coverage.RuntimeExploitTestAvailable,
		})
	}
	sort.Slice(info, func(i, j int) bool { return info[i].AdvisoryID < info[j].AdvisoryID })
	return info
}

func matchAdvisories(dependencies []Dependency, advisories []*advisoryCatalog) []AdvisoryMatch {
	matches := []AdvisoryMatch{}
	seen := make(map[string]bool)
	for _, advisory := range advisories {
		caseByVersion := make(map[string]int, len(advisory.VersionCases))
		for index, versionCase := range advisory.VersionCases {
			caseByVersion[versionCase.Version] = index
		}
		for _, dependency := range dependencies {
			if dependency.GroupID != advisory.Package.GroupID || dependency.ArtifactID != advisory.Package.ArtifactID {
				continue
			}
			key := advisory.AdvisoryID + "\x00" + dependency.Module + "\x00" + dependency.GroupID + ":" + dependency.ArtifactID + "\x00" + dependency.Version + "\x00" + dependency.DeclarationPOM
			if seen[key] {
				continue
			}
			seen[key] = true
			match := AdvisoryMatch{
				AdvisoryID:        advisory.AdvisoryID,
				Module:            dependency.Module,
				Dependency:        dependency.GroupID + ":" + dependency.ArtifactID,
				DeclaredVersion:   dependency.Version,
				RuntimeStatus:     "not_run",
				InputReachability: "unknown",
				FindingStatus:     "unknown",
			}
			if dependency.VersionStatus != "resolved" {
				match.VersionStatus = "unknown"
				match.SupplyChainStatus = "unknown"
				match.Reason = "unresolved_version"
				matches = append(matches, match)
				continue
			}
			index, ok := caseByVersion[dependency.Version]
			if !ok {
				match.VersionStatus = "unknown"
				match.SupplyChainStatus = "unknown"
				match.Reason = "no_exact_version_case"
				matches = append(matches, match)
				continue
			}
			versionCase := advisory.VersionCases[index]
			match.AssessmentScope = versionCase.AssessmentScope
			if versionCase.VersionMatched {
				match.VersionStatus = "version_matched"
				match.SupplyChainStatus = "version_matched"
				match.FindingStatus = "candidate"
			} else {
				match.VersionStatus = "not_affected"
				match.SupplyChainStatus = "not_affected"
				match.FindingStatus = "none"
				if match.AssessmentScope == "" {
					match.AssessmentScope = "version criterion only"
				}
			}
			matches = append(matches, match)
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		a, b := matches[i], matches[j]
		if a.AdvisoryID != b.AdvisoryID {
			return a.AdvisoryID < b.AdvisoryID
		}
		if a.Module != b.Module {
			return a.Module < b.Module
		}
		if a.Dependency != b.Dependency {
			return a.Dependency < b.Dependency
		}
		return a.DeclaredVersion < b.DeclaredVersion
	})
	return matches
}
