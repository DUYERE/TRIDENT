package r3

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trident/internal/findings"
	"trident/internal/model"
)

type fakeCompletion struct {
	content string
	err     error
	request model.Request
}

func (f *fakeCompletion) Complete(_ context.Context, request model.Request) (model.Response, error) {
	f.request = request
	if f.err != nil {
		return model.Response{}, f.err
	}
	return model.Response{Stop: model.StopComplete, Message: model.Message{Role: "assistant", Content: f.content}}, nil
}

func proposalContent(t *testing.T, patch, rationale string) string {
	t.Helper()
	raw, err := json.Marshal(proposalEnvelope{Patch: patch, Rationale: rationale})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestProposeValidatesGeneratedPatch(t *testing.T) {
	snapshot, imported, source := testSnapshot(t, map[string]string{
		"src/main/java/demo/A.java": originalJava,
	})
	client := &fakeCompletion{content: proposalContent(t, safePatch, "replace the constant")}
	proposal, err := Propose(context.Background(), snapshot, client, ProposeOptions{
		Paths: []string{"src/main/java/demo/A.java"}, Goal: "change 1 to 2", Model: "fake", MaxOutputTokens: 256,
	})
	if err != nil {
		t.Fatal(err)
	}
	if proposal.Patch != safePatch || proposal.Rationale == "" || proposal.PatchSHA256 == "" || len(proposal.Files) != 1 {
		t.Fatalf("proposal: %+v", proposal)
	}
	if len(client.request.Messages) != 2 || client.request.Messages[0].Role != "system" {
		t.Fatalf("request: %+v", client.request)
	}
	if !snapshotIntact(context.Background(), imported.Path, imported.Hash) {
		t.Fatal("snapshot changed")
	}
	original, err := readFile(source, "src/main/java/demo/A.java")
	if err != nil || original != originalJava {
		t.Fatalf("source changed: %q (%v)", original, err)
	}
}

func TestProposeRejectsInvalidOrNonApplyingOutput(t *testing.T) {
	snapshot, _, _ := testSnapshot(t, map[string]string{
		"src/main/java/demo/A.java": originalJava,
		"src/main/java/demo/B.java": "package demo;\npublic class B { int y = 1; }",
	})
	for name, content := range map[string]string{
		"not-json":    "here is a patch",
		"empty-patch": proposalContent(t, "", "nothing"),
		"mismatch": proposalContent(t, `--- a/src/main/java/demo/A.java
+++ b/src/main/java/demo/A.java
@@ -1,2 +1,2 @@
 package demo;
-public class A { int x = 9; }
+public class A { int x = 2; }
`, "wrong context"),
		"creation": proposalContent(t, `--- /dev/null
+++ b/src/main/java/demo/New.java
@@ -0,0 +1,1 @@
+x
`, "new file"),
		"outside-context": proposalContent(t, `--- a/src/main/java/demo/B.java
+++ b/src/main/java/demo/B.java
@@ -1,2 +1,2 @@
 package demo;
-public class B { int y = 1; }
+public class B { int y = 2; }
`, "patch an unseen file"),
	} {
		t.Run(name, func(t *testing.T) {
			client := &fakeCompletion{content: content}
			_, err := Propose(context.Background(), snapshot, client, ProposeOptions{
				Paths: []string{"src/main/java/demo/A.java"}, Goal: "patch", Model: "fake", MaxOutputTokens: 256,
			})
			if !errors.Is(err, ErrProposal) {
				t.Fatalf("error = %v; want ErrProposal", err)
			}
		})
	}
}

func TestProposeUsesFindingEvidence(t *testing.T) {
	snapshot, _, _ := testSnapshot(t, map[string]string{
		"src/main/java/demo/App.java": `package demo;
import org.springframework.web.bind.annotation.*;
import java.sql.*;
@RestController
public class App {
    private Connection connection;
    @GetMapping("/unsafe")
    public void unsafe(@RequestParam("q") String q) throws Exception {
        Statement statement = connection.createStatement();
        statement.executeQuery("SELECT * FROM t WHERE a='" + q + "'");
    }
}
`,
	})
	report, err := findings.Analyze(context.Background(), snapshot, findings.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) == 0 {
		t.Fatal("fixture finding missing")
	}
	id := report.Findings[0].ID
	client := &fakeCompletion{content: proposalContent(t, `--- a/src/main/java/demo/App.java
+++ b/src/main/java/demo/App.java
@@ -10,1 +10,1 @@
-        statement.executeQuery("SELECT * FROM t WHERE a='" + q + "'");
+        statement.executeQuery("SELECT * FROM t WHERE a='" + q + "' /* reviewed */");
`, "document the risky sink")}
	proposal, err := Propose(context.Background(), snapshot, client, ProposeOptions{
		FindingID: id, Goal: "review the SQL sink", Model: "fake", MaxOutputTokens: 512,
	})
	if err != nil {
		t.Fatal(err)
	}
	if proposal.FindingID != id || proposal.Patch == "" {
		t.Fatalf("finding proposal: %+v", proposal)
	}
	prompt := client.request.Messages[1].Content
	if !strings.Contains(prompt, "executeQuery") || !strings.Contains(prompt, id) {
		t.Fatalf("prompt missing finding context: %s", prompt)
	}
}

func readFile(root, relative string) (string, error) {
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
	return string(data), err
}
