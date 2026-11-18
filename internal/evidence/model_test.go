package evidence

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestReportJSONRoundTrip(t *testing.T) {
	report := Report{
		SchemaVersion: SchemaVersion,
		Capability:    "entry",
		Providers:     []string{"java_audit", "codescan", "application_entry"},
		Entries: []Entry{{
			ID:          "java:src/App.java:12:/users",
			Language:    "java",
			Framework:   "Spring MVC",
			Kind:        KindAnnotationRoute,
			Source:      "java_audit",
			HTTPMethods: []string{"GET"},
			Path:        "/users",
			PathStatus:  "resolved",
			Symbol:      "Demo#users",
			File:        "src/App.java",
			SHA256:      "abc",
			StartLine:   1,
			MethodLine:  12,
			Parameters:  []Parameter{{Name: "name", BindingName: "name", Bindings: []string{"RequestParam"}}},
			Authz:       &Authz{Decision: "protected", RuntimeStatus: "not_run"},
			Reason:      "annotation",
		}, {
			ID:         "application_entry:public/index.php:23:",
			Language:   "php",
			Framework:  "ThinkPHP",
			Kind:       KindApplicationEntry,
			Source:     "application_entry",
			File:       "public/index.php",
			StartLine:  23,
			PathStatus: "not_applicable",
			Confidence: "filename_heuristic",
		}},
		Coverage: []LanguageCoverage{{
			Source: "java_audit", Capability: "entry", Language: "java",
			FilesScanned: 8, FilesRejected: 1, Entries: 1, Status: "partial",
		}},
		Partial:     true,
		Limitations: []string{"entry_candidate_not_deployed_route"},
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(report, decoded) {
		t.Fatalf("round trip mismatch\nwant: %+v\ngot:  %+v", report, decoded)
	}
}
