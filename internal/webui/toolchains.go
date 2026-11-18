package webui

import (
	"net/http"

	"trident/internal/r3"
)

type toolchainsResponse struct {
	SchemaVersion int                  `json:"schema_version"`
	Product       string               `json:"product"`
	Scope         string               `json:"scope"`
	Toolchains    []r3.ToolchainStatus `json:"toolchains"`
	Limitations   []string             `json:"limitations"`
}

func (c *Console) handleToolchains(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, toolchainsResponse{
		SchemaVersion: SchemaVersion,
		Product:       Product,
		Scope:         "host_toolchain",
		Toolchains:    r3.ProbeToolchains(),
		Limitations: []string{
			"php_lint_syntax_only: php -l checks syntax, not PHP 8 runtime behavior, exploitability or whether the vulnerability is fixed",
			"host_toolchain_only: language validation profiles run on the console host PATH; container sandbox is not wired for them",
			"probe_is_path_lookup_only: availability is a PATH lookup, not proof that the test runner or project dependencies are installed",
		},
	})
}
