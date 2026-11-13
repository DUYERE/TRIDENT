package sca

import (
	"fmt"
	"path/filepath"
	"sort"
)

const (
	MaxTreeNodes = 5000
	MaxTreeDepth = 32
)

// TreeReport is a bounded module/declaration graph. External dependencies are
// leaves: their own transitive declarations are not present in the snapshot.
type TreeReport struct {
	SchemaVersion int          `json:"schema_version"`
	ToolVersion   string       `json:"tool_version"`
	SnapshotHash  string       `json:"snapshot_hash"`
	AnalysisKind  string       `json:"analysis_kind"`
	Partial       bool         `json:"partial"`
	Roots         []TreeNode   `json:"roots"`
	Coverage      TreeCoverage `json:"coverage"`
	Limitations   []string     `json:"limitations"`
	RuntimeStatus string       `json:"runtime_status"`
}

type TreeCoverage struct {
	Modules        int    `json:"modules"`
	Nodes          int    `json:"nodes"`
	ExternalLeaves int    `json:"external_leaves"`
	Cycles         int    `json:"cycles"`
	Truncated      bool   `json:"truncated"`
	TransitiveTree string `json:"transitive_tree"`
	ArtifactHashes string `json:"artifact_hashes"`
	RuntimeStatus  string `json:"runtime_status"`
}

type TreeNode struct {
	Name         string     `json:"name"`
	GroupID      string     `json:"group_id,omitempty"`
	ArtifactID   string     `json:"artifact_id,omitempty"`
	Version      string     `json:"version,omitempty"`
	POM          string     `json:"pom,omitempty"`
	Scope        string     `json:"scope,omitempty"`
	External     bool       `json:"external"`
	Cycle        bool       `json:"cycle,omitempty"`
	VersionState string     `json:"version_state,omitempty"`
	Children     []TreeNode `json:"children,omitempty"`
}

type treeBuilder struct {
	report   Report
	byPOM    map[string]Module
	byDir    map[string]Module
	byGAV    map[string]Module
	byName   map[string]Module
	children map[string][]Module
	coverage TreeCoverage
	nodes    int
	partial  bool
}

// Tree builds a deterministic module graph from the declaration report. It is
// not Maven's effective dependency tree and does not resolve external
// transitive dependencies.
func Tree(report Report) TreeReport {
	builder := &treeBuilder{
		report:   report,
		byPOM:    map[string]Module{},
		byDir:    map[string]Module{},
		byGAV:    map[string]Module{},
		byName:   map[string]Module{},
		children: map[string][]Module{},
	}
	for _, module := range report.Modules {
		builder.byPOM[module.POM] = module
		builder.byDir[module.Directory] = module
		builder.byName[module.ArtifactID] = module
		builder.byName[filepath.Base(module.Directory)] = module
		if module.GroupID != "" && module.ArtifactID != "" {
			builder.byGAV[module.GroupID+":"+module.ArtifactID] = module
		}
	}
	for _, module := range report.Modules {
		for _, directory := range module.ModuleDirs {
			if child, ok := builder.byDir[directory]; ok {
				builder.children[module.POM] = append(builder.children[module.POM], child)
			}
		}
		for _, dependencyName := range module.ProjectDeps {
			if child, ok := builder.byName[dependencyName]; ok && child.POM != module.POM {
				builder.children[module.POM] = append(builder.children[module.POM], child)
			}
		}
		for _, dependency := range report.Dependencies {
			if dependency.Module != module.Directory {
				continue
			}
			if child, ok := builder.byGAV[dependency.GroupID+":"+dependency.ArtifactID]; ok && child.POM != module.POM {
				builder.children[module.POM] = append(builder.children[module.POM], child)
			}
		}
	}
	for pom := range builder.children {
		sort.Slice(builder.children[pom], func(i, j int) bool {
			return builder.children[pom][i].POM < builder.children[pom][j].POM
		})
	}
	var roots []Module
	if len(report.Project.RootPOMs) > 0 {
		for _, pom := range report.Project.RootPOMs {
			if module, ok := builder.byPOM[pom]; ok {
				roots = append(roots, module)
			}
		}
	} else {
		for _, module := range report.Modules {
			if module.Parent == "" {
				roots = append(roots, module)
			}
		}
	}
	if len(roots) == 0 {
		for _, module := range report.Modules {
			roots = append(roots, module)
			break
		}
	}
	tree := TreeReport{
		SchemaVersion: SchemaVersion,
		ToolVersion:   ToolVersion,
		SnapshotHash:  report.SnapshotHash,
		AnalysisKind:  "module_declaration_tree",
		Partial:       report.Partial || report.Project.GradleFileCount > 0,
		Roots:         []TreeNode{},
		Coverage: TreeCoverage{
			Modules:        report.Project.ModuleCount,
			TransitiveTree: "module_edges_only",
			ArtifactHashes: "not_available",
			RuntimeStatus:  "not_run",
		},
		Limitations: []string{
			"module_tree_not_effective_dependency_tree: module directory edges and same-snapshot GAV matches only",
			"external_transitive_dependencies_unavailable: external components are leaves",
			"gradle_tree_partial: Gradle files are modules with direct declarations; settings evaluation and project dependencies are not modeled",
			"runtime_status_not_run: a declaration graph does not prove classpath presence, reachability or exploitability",
		},
		RuntimeStatus: "not_run",
	}
	for _, root := range roots {
		node := builder.node(root, nil, 0)
		tree.Roots = append(tree.Roots, node)
	}
	tree.Coverage.Nodes = builder.nodes
	tree.Coverage.ExternalLeaves = builder.coverage.ExternalLeaves
	tree.Coverage.Cycles = builder.coverage.Cycles
	tree.Coverage.Truncated = builder.coverage.Truncated
	tree.Partial = tree.Partial || builder.partial
	sort.Strings(tree.Limitations)
	return tree
}

func (b *treeBuilder) node(module Module, stack map[string]bool, depth int) TreeNode {
	b.nodes++
	node := TreeNode{
		Name: module.Name(), GroupID: module.GroupID, ArtifactID: module.ArtifactID,
		Version: module.Version, POM: module.POM, External: false, Children: []TreeNode{},
	}
	if node.Name == "" {
		node.Name = module.ArtifactID
	}
	if depth >= MaxTreeDepth || b.nodes >= MaxTreeNodes {
		b.coverage.Truncated = true
		b.partial = true
		node.VersionState = "depth_or_node_limit"
		return node
	}
	if stack == nil {
		stack = map[string]bool{}
	}
	if stack[module.POM] {
		node.Cycle = true
		b.coverage.Cycles++
		return node
	}
	next := make(map[string]bool, len(stack)+1)
	for key, value := range stack {
		next[key] = value
	}
	next[module.POM] = true
	seen := map[string]bool{}
	for _, child := range b.children[module.POM] {
		if seen[child.POM] {
			continue
		}
		seen[child.POM] = true
		node.Children = append(node.Children, b.node(child, next, depth+1))
	}
	for _, dependency := range b.report.Dependencies {
		if dependency.Module != module.Directory {
			continue
		}
		key := dependency.GroupID + ":" + dependency.ArtifactID
		if child, ok := b.byGAV[key]; ok && child.POM == module.POM {
			continue
		}
		if _, ok := b.byGAV[key]; ok {
			continue
		}
		leafKey := "external:" + key + ":" + dependency.Version
		if seen[leafKey] {
			continue
		}
		seen[leafKey] = true
		b.nodes++
		leaf := TreeNode{
			Name: key, GroupID: dependency.GroupID, ArtifactID: dependency.ArtifactID,
			Version: dependency.Version, Scope: dependency.Scope, External: true,
			VersionState: dependency.VersionStatus,
		}
		if dependency.VersionReason != "" {
			leaf.VersionState = dependency.VersionReason
		}
		if leaf.VersionState == "" {
			leaf.VersionState = "unknown"
		}
		b.coverage.ExternalLeaves++
		node.Children = append(node.Children, leaf)
	}
	sort.Slice(node.Children, func(i, j int) bool {
		if node.Children[i].External != node.Children[j].External {
			return !node.Children[i].External
		}
		if node.Children[i].Name != node.Children[j].Name {
			return node.Children[i].Name < node.Children[j].Name
		}
		if node.Children[i].Version != node.Children[j].Version {
			return node.Children[i].Version < node.Children[j].Version
		}
		return node.Children[i].POM < node.Children[j].POM
	})
	return node
}

func (m Module) Name() string {
	if m.ArtifactID != "" {
		return m.ArtifactID
	}
	if m.POM != "" {
		return m.POM
	}
	return fmt.Sprintf("module-%s", m.Directory)
}
