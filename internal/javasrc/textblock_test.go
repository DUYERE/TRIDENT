package javasrc

import "testing"

func TestStripLeavesFilesWithoutBlocksUnchanged(t *testing.T) {
	source := []byte("package demo;\nclass A { String q = \"select 1\"; }\n")
	out, blocks, ok := Strip(source)
	if !ok || blocks != 0 {
		t.Fatalf("no-block source misreported: blocks=%d ok=%v", blocks, ok)
	}
	if string(out) != string(source) {
		t.Fatalf("byte-identical source changed:\n%s", out)
	}
}

func TestStripReplacesBlocksAndKeepsLineCount(t *testing.T) {
	source := []byte("package demo;\nclass A {\n    String q = \"\"\"\n        SELECT *\n        FROM t\n        \"\"\";\n}\n")
	out, blocks, ok := Strip(source)
	if !ok || blocks != 1 {
		t.Fatalf("block not stripped: blocks=%d ok=%v", blocks, ok)
	}
	if containsTripleQuote(out) {
		t.Fatalf("block delimiter survived: %q", out)
	}
	if countNewlines(out) != countNewlines(source) {
		t.Fatalf("line numbers would shift: in=%d out=%d\n%s", countNewlines(source), countNewlines(out), out)
	}
}

func TestStripRejectsUnterminatedBlock(t *testing.T) {
	if _, _, ok := Strip([]byte("class A { String q = \"\"\"\nabc\n")); ok {
		t.Fatal("unterminated block must be rejected")
	}
}

func TestStripHandlesSeveralBlocks(t *testing.T) {
	source := []byte("class A { String a = \"\"\"\nx\n\"\"\"; String b = \"\"\"\ny\n\"\"\"; }\n")
	_, blocks, ok := Strip(source)
	if !ok || blocks != 2 {
		t.Fatalf("expected two blocks, got %d (ok=%v)", blocks, ok)
	}
}

func containsTripleQuote(data []byte) bool {
	for i := 0; i+2 < len(data); i++ {
		if data[i] == '"' && data[i+1] == '"' && data[i+2] == '"' {
			return true
		}
	}
	return false
}

func countNewlines(data []byte) int {
	count := 0
	for _, b := range data {
		if b == '\n' {
			count++
		}
	}
	return count
}
